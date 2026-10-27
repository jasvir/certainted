// Package store persists collector events, independent probes, and derived
// watchlist findings. Application traffic is never passed to this package.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
	_ "modernc.org/sqlite"
)

const maxEvidenceBytes = 2 << 20

type Store struct{ db *sql.DB }

type FindingFilter struct {
	WatchID       int64
	DestinationID int64
	From          *time.Time
	To            *time.Time
	Evidence      string
	Limit         int
}

type Stats struct {
	DestinationEvents         int64      `json:"destination_events"`
	UniqueDestinations        int64      `json:"unique_destinations"`
	ProbedDestinations        int64      `json:"probed_destinations"`
	Probes                    int64      `json:"probes"`
	Last24hProbes             int64      `json:"last_24h_probes"`
	SuccessfulProbes          int64      `json:"successful_probes"`
	FailedProbes              int64      `json:"failed_probes"`
	ObservedCACertificates    int64      `json:"observed_ca_certificates"`
	WatchlistMatches          int64      `json:"watchlist_matches"`
	AffectedDestinations      int64      `json:"affected_destinations"`
	RevocationFindings        int64      `json:"revocation_findings"`
	RevokedDestinations       int64      `json:"revoked_destinations"`
	VerifiedDirectRevocations int64      `json:"verified_direct_revocations"`
	LatestProbe               *time.Time `json:"latest_probe,omitempty"`
}

type WatchLabel struct {
	WatchID  int64  `json:"watch_id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
}

type CARecord struct {
	Certificate           model.Certificate `json:"certificate"`
	FirstSeen             time.Time         `json:"first_seen"`
	LastSeen              time.Time         `json:"last_seen"`
	PresentedObservations int64             `json:"presented_observations"`
	CandidateObservations int64             `json:"candidate_observations"`
	DestinationCount      int64             `json:"destination_count"`
	WatchMatches          []WatchLabel      `json:"watch_matches"`
}

// Alert groups recurring findings while retaining every underlying finding.
type Alert struct {
	WatchID       int64 `json:"watch_id"`
	DestinationID int64 `json:"destination_id"`
	// DestinationKey encodes the exact destination fields used to group alerts.
	// Unlike DestinationID, it remains stable across repeated collector events.
	DestinationKey   string    `json:"destination_key"`
	Evidence         string    `json:"evidence"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ObservationCount int64     `json:"observation_count"`
	LatestProbeID    int64     `json:"latest_probe_id"`
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("database path is required")
	}
	if path != ":memory:" {
		if strings.HasPrefix(path, "file:") {
			return nil, errors.New("SQLite URI paths are not supported")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("database path must not be a symbolic link")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}
		if err = os.Chmod(path, 0600); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection keeps PRAGMA settings consistent, including for :memory:.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err = db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite setup: %w", err)
		}
	}
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite schema: %w", err)
	}
	s := &Store{db: db}
	if err = s.initSharing(); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite sharing schema: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS destination_events (
 id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, collector TEXT NOT NULL,
 vantage TEXT NOT NULL, hostname TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL,
 workload TEXT NOT NULL, attribution_reliable INTEGER NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_destination_identity ON destination_events(hostname,ip,port,vantage);
CREATE INDEX IF NOT EXISTS idx_destination_time ON destination_events(observed_at);
CREATE TABLE IF NOT EXISTS probe_observations (
 id INTEGER PRIMARY KEY, destination_id INTEGER NOT NULL REFERENCES destination_events(id) ON DELETE CASCADE,
 observed_at TEXT NOT NULL, vantage TEXT NOT NULL, hostname TEXT NOT NULL,
 target_ip TEXT NOT NULL, port INTEGER NOT NULL, sni TEXT NOT NULL,
 failure TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probe_dest_time ON probe_observations(destination_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_probe_time ON probe_observations(observed_at);
CREATE TABLE IF NOT EXISTS probe_certificates (
 id INTEGER PRIMARY KEY, probe_id INTEGER NOT NULL REFERENCES probe_observations(id) ON DELETE CASCADE,
 destination_id INTEGER NOT NULL REFERENCES destination_events(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('presented','candidate')),
 path_index INTEGER NOT NULL, position INTEGER NOT NULL,
 fingerprint TEXT NOT NULL, spki_fingerprint TEXT NOT NULL,
 subject TEXT NOT NULL, issuer TEXT NOT NULL, is_ca INTEGER NOT NULL,
 observed_at TEXT NOT NULL, certificate_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cert_fingerprint ON probe_certificates(fingerprint,kind);
CREATE INDEX IF NOT EXISTS idx_cert_spki ON probe_certificates(spki_fingerprint,kind);
CREATE INDEX IF NOT EXISTS idx_cert_probe ON probe_certificates(probe_id);
CREATE TABLE IF NOT EXISTS watches (
 id INTEGER PRIMARY KEY, match_type TEXT NOT NULL, value TEXT NOT NULL,
 name TEXT NOT NULL, status TEXT NOT NULL, evidence_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watch_match ON watches(match_type,value);
-- This ledger has no foreign key to watches: deletion of a built-in rule is an
-- operator choice and must not cause that rule to return on the next startup.
CREATE TABLE IF NOT EXISTS builtin_watch_keys (
 bundle_id TEXT NOT NULL, match_type TEXT NOT NULL, value TEXT NOT NULL,
 applied_at TEXT NOT NULL,
 PRIMARY KEY(bundle_id,match_type,value)
);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY, watch_id INTEGER NOT NULL REFERENCES watches(id) ON DELETE CASCADE,
 probe_id INTEGER NOT NULL REFERENCES probe_observations(id) ON DELETE CASCADE,
 destination_id INTEGER NOT NULL REFERENCES destination_events(id) ON DELETE CASCADE,
 evidence TEXT NOT NULL CHECK(evidence IN ('direct','candidate','name_only')),
 certificate_fingerprint TEXT NOT NULL, observed_at TEXT NOT NULL,
 UNIQUE(watch_id,probe_id)
);
CREATE INDEX IF NOT EXISTS idx_finding_watch_time ON findings(watch_id,observed_at);
CREATE INDEX IF NOT EXISTS idx_finding_dest ON findings(destination_id);
CREATE TABLE IF NOT EXISTS crl_imports (
 id INTEGER PRIMARY KEY,
 fingerprint TEXT NOT NULL UNIQUE,
 issuer_fingerprint TEXT NOT NULL,
 issuer_spki_fingerprint TEXT NOT NULL,
 issuer_name_hash TEXT NOT NULL,
 issuer TEXT NOT NULL,
 authority_key_id TEXT NOT NULL,
 issuer_subject_key_id TEXT NOT NULL,
 this_update TEXT NOT NULL,
 next_update TEXT NOT NULL,
 number TEXT NOT NULL,
 source TEXT NOT NULL,
 imported_at TEXT NOT NULL,
 entry_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_crl_issuer_name ON crl_imports(issuer_name_hash);
CREATE TABLE IF NOT EXISTS crl_entries (
 crl_id INTEGER NOT NULL REFERENCES crl_imports(id) ON DELETE CASCADE,
 serial TEXT NOT NULL,
 revoked_at TEXT NOT NULL,
 reason_code INTEGER NOT NULL,
 reason TEXT NOT NULL,
 PRIMARY KEY(crl_id,serial)
);
CREATE INDEX IF NOT EXISTS idx_crl_entries_serial ON crl_entries(serial);
CREATE TABLE IF NOT EXISTS revocation_findings (
 id INTEGER PRIMARY KEY,
 crl_id INTEGER NOT NULL REFERENCES crl_imports(id) ON DELETE CASCADE,
 probe_id INTEGER NOT NULL REFERENCES probe_observations(id) ON DELETE CASCADE,
 destination_id INTEGER NOT NULL REFERENCES destination_events(id) ON DELETE CASCADE,
 evidence TEXT NOT NULL CHECK(evidence IN ('direct','candidate')),
	issuer_match TEXT NOT NULL CHECK(issuer_match IN ('verified_path','key_identifier_candidate')),
 certificate_fingerprint TEXT NOT NULL,
 certificate_serial TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 UNIQUE(crl_id,probe_id,certificate_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_revocation_findings_time ON revocation_findings(observed_at);
CREATE INDEX IF NOT EXISTS idx_revocation_findings_dest ON revocation_findings(destination_id);
`

func encoded(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if len(b) > maxEvidenceBytes {
		return "", fmt.Errorf("evidence exceeds %d bytes", maxEvidenceBytes)
	}
	return string(b), nil
}

// Fixed precision makes SQLite text ordering match chronological ordering.
func timestamp(t time.Time) string          { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }
func parseTime(v string) (time.Time, error) { return time.Parse(time.RFC3339Nano, v) }

func (s *Store) AddDestination(d model.DestinationEvent) (int64, error) {
	if d.ID != 0 {
		return 0, errors.New("new destination must not specify an id")
	}
	if d.Port < 1 || d.Port > 65535 {
		return 0, errors.New("destination port is invalid")
	}
	if d.Hostname == "" && d.IP == "" {
		return 0, errors.New("destination hostname or IP is required")
	}
	if len(d.Hostname) > 253 || len(d.IP) > 128 || len(d.Collector) > 256 || len(d.Vantage) > 256 || len(d.Workload) > 512 {
		return 0, errors.New("destination field is too long")
	}
	if d.Time.IsZero() {
		d.Time = time.Now().UTC()
	}
	if !d.AttributionReliable {
		d.Workload = ""
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`INSERT INTO destination_events(observed_at,collector,vantage,hostname,ip,port,workload,attribution_reliable,evidence_json)
	 VALUES(?,?,?,?,?,?,?,?,?)`, timestamp(d.Time), d.Collector, d.Vantage, d.Hostname, d.IP, d.Port, d.Workload, d.AttributionReliable, "")
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	d.ID = id
	j, err := encoded(d)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec("UPDATE destination_events SET evidence_json=? WHERE id=?", j, id); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func (s *Store) AddProbe(p model.ProbeObservation) (int64, error) {
	if p.ID != 0 {
		return 0, errors.New("new probe must not specify an id")
	}
	if p.DestinationID < 1 {
		return 0, errors.New("probe destination is required")
	}
	if p.Port < 1 || p.Port > 65535 {
		return 0, errors.New("probe port is invalid")
	}
	if len(p.Presented) > 32 || len(p.CandidatePaths) > 16 {
		return 0, errors.New("too many certificates or candidate paths")
	}
	for _, path := range p.CandidatePaths {
		if len(path.Certificates) > 32 {
			return 0, errors.New("candidate path exceeds certificate limit")
		}
	}
	if p.Time.IsZero() {
		p.Time = time.Now().UTC()
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r, err := tx.Exec(`INSERT INTO probe_observations(destination_id,observed_at,vantage,hostname,target_ip,port,sni,failure,evidence_json)
	 VALUES(?,?,?,?,?,?,?,?,?)`, p.DestinationID, timestamp(p.Time), p.Vantage, p.Hostname, p.TargetIP, p.Port, p.SNI, p.Failure, "")
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	p.ID = id
	j, err := encoded(p)
	if err != nil {
		return 0, err
	}
	if _, err = tx.Exec("UPDATE probe_observations SET evidence_json=? WHERE id=?", j, id); err != nil {
		return 0, err
	}
	for pos, cert := range p.Presented {
		if err = insertCert(tx, p, cert, "presented", -1, pos); err != nil {
			return 0, err
		}
	}
	for pathIdx, path := range p.CandidatePaths {
		for pos, cert := range path.Certificates {
			if err = insertCert(tx, p, cert, "candidate", pathIdx, pos); err != nil {
				return 0, err
			}
		}
	}
	watches, err := listWatchesTx(tx)
	if err != nil {
		return 0, err
	}
	for _, watch := range watches {
		if f, ok := match(watch, p); ok {
			if err = insertFinding(context.Background(), tx, f); err != nil {
				return 0, err
			}
		}
	}
	if err = evaluateRevocationsForProbeTx(tx, p); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

func insertCert(tx *sql.Tx, p model.ProbeObservation, c model.Certificate, kind string, path, pos int) error {
	j, err := encoded(c)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO probe_certificates(probe_id,destination_id,kind,path_index,position,fingerprint,spki_fingerprint,subject,issuer,is_ca,observed_at,certificate_json)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, p.ID, p.DestinationID, kind, path, pos, normalizeFingerprint(c.Fingerprint), normalizeFingerprint(c.SPKIFingerprint), c.Subject, c.Issuer, c.IsCA, timestamp(p.Time), j)
	return err
}

func (s *Store) AddWatch(w model.WatchEntry) (int64, error) {
	var err error
	w, err = normalizeWatch(w)
	if err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := saveWatchTx(context.Background(), tx, &w); err != nil {
		return 0, err
	}
	return w.ID, tx.Commit()
}

func normalizeWatch(w model.WatchEntry) (model.WatchEntry, error) {
	w.MatchType = strings.ToLower(strings.TrimSpace(w.MatchType))
	w.Value = strings.TrimSpace(w.Value)
	w.Status = strings.ToLower(strings.TrimSpace(w.Status))
	w.Severity = strings.ToLower(strings.TrimSpace(w.Severity))
	w.Source = strings.TrimSpace(w.Source)
	if w.MatchType != "cert_sha256" && w.MatchType != "spki_sha256" && w.MatchType != "name" {
		return w, errors.New("unsupported watch match type")
	}
	if w.Value == "" {
		return w, errors.New("watch value is required")
	}
	if w.MatchType != "name" {
		w.Value = normalizeFingerprint(w.Value)
		if len(w.Value) != 64 || strings.Trim(w.Value, "0123456789abcdef") != "" {
			return w, errors.New("watch fingerprint must be SHA-256 hex")
		}
	}
	if len(w.Value) > 512 || len(w.Name) > 256 || len(w.Group) > 256 || len(w.Reason) > 2048 || len(w.Source) > 1024 {
		return w, errors.New("watch field is too long")
	}
	if w.Status == "" {
		w.Status = "monitored"
	}
	if w.Severity == "" {
		w.Severity = "info"
	}
	switch w.Status {
	case "monitored", "under investigation", "distrusted", "compromised":
	default:
		return w, errors.New("unsupported watch status")
	}
	switch w.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return w, errors.New("unsupported watch severity")
	}
	if w.Source == "" {
		w.Source = "manual"
	}
	if w.EffectiveFrom != nil && w.EffectiveFrom.IsZero() {
		return w, errors.New("watch effective_from must be a valid time")
	}
	if w.EffectiveTo != nil && w.EffectiveTo.IsZero() {
		return w, errors.New("watch effective_to must be a valid time")
	}
	if w.EffectiveFrom != nil && w.EffectiveTo != nil && !w.EffectiveFrom.Before(*w.EffectiveTo) {
		return w, errors.New("watch effective_from must precede effective_to")
	}
	return w, nil
}

func saveWatchTx(ctx context.Context, tx *sql.Tx, w *model.WatchEntry) error {
	if w.ID == 0 {
		r, err := tx.ExecContext(ctx, `INSERT INTO watches(match_type,value,name,status,evidence_json) VALUES(?,?,?,?,?)`, w.MatchType, w.Value, w.Name, w.Status, "")
		if err != nil {
			return err
		}
		w.ID, err = r.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		r, err := tx.ExecContext(ctx, `UPDATE watches SET match_type=?,value=?,name=?,status=? WHERE id=?`, w.MatchType, w.Value, w.Name, w.Status, w.ID)
		if err != nil {
			return err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return sql.ErrNoRows
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM findings WHERE watch_id=?`, w.ID); err != nil {
			return err
		}
	}
	j, err := encoded(w)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE watches SET evidence_json=? WHERE id=?`, j, w.ID); err != nil {
		return err
	}
	var afterID int64
	for {
		rows, err := tx.QueryContext(ctx, `SELECT id,evidence_json FROM probe_observations WHERE id>? ORDER BY id LIMIT 256`, afterID)
		if err != nil {
			return err
		}
		var probes []model.ProbeObservation
		for rows.Next() {
			var raw string
			var rowID int64
			if err = rows.Scan(&rowID, &raw); err != nil {
				break
			}
			var p model.ProbeObservation
			if err = json.Unmarshal([]byte(raw), &p); err != nil {
				break
			}
			afterID = rowID
			probes = append(probes, p)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		for _, p := range probes {
			if f, ok := match(*w, p); ok {
				if err = insertFinding(ctx, tx, f); err != nil {
					return err
				}
			}
		}
		if len(probes) < 256 {
			break
		}
	}
	return nil
}

func (s *Store) DeleteWatch(id int64) error {
	r, err := s.db.Exec(`DELETE FROM watches WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteDestination removes a collected event and all probe and finding
// evidence derived from that event. Other events for the same endpoint remain.
func (s *Store) DeleteDestination(id int64) error {
	r, err := s.db.Exec(`DELETE FROM destination_events WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func normalizeFingerprint(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), ":", ""), " ", ""))
}

func match(w model.WatchEntry, p model.ProbeObservation) (model.Finding, bool) {
	f := model.Finding{WatchID: w.ID, ProbeID: p.ID, DestinationID: p.DestinationID, Time: p.Time}
	// The watch interval is [effective_from, effective_to). A missing bound is
	// open ended. This applies equally to live probes and historical reevaluation.
	if w.EffectiveFrom != nil && p.Time.Before(*w.EffectiveFrom) {
		return f, false
	}
	if w.EffectiveTo != nil && !p.Time.Before(*w.EffectiveTo) {
		return f, false
	}
	findExact := func(certs []model.Certificate) (string, bool) {
		for _, c := range certs {
			switch w.MatchType {
			case "cert_sha256":
				if normalizeFingerprint(c.Fingerprint) == w.Value {
					return c.Fingerprint, true
				}
			case "spki_sha256":
				if normalizeFingerprint(c.SPKIFingerprint) == w.Value {
					return c.Fingerprint, true
				}
			}
		}
		return "", false
	}
	if w.MatchType != "name" {
		if fp, ok := findExact(p.Presented); ok {
			f.Evidence, f.CertificateFingerprint = "direct", fp
			return f, true
		}
		for _, path := range p.CandidatePaths {
			if fp, ok := findExact(path.Certificates); ok {
				f.Evidence, f.CertificateFingerprint = "candidate", fp
				return f, true
			}
		}
		return f, false
	}
	needle := strings.ToLower(w.Value)
	nameMatch := func(certs []model.Certificate) (string, bool) {
		for _, c := range certs {
			if strings.Contains(strings.ToLower(c.Subject), needle) {
				return c.Fingerprint, true
			}
			if strings.Contains(strings.ToLower(c.Issuer), needle) {
				return "", true
			}
		}
		return "", false
	}
	if fp, ok := nameMatch(p.Presented); ok {
		f.Evidence, f.CertificateFingerprint = "name_only", fp
		return f, true
	}
	for _, path := range p.CandidatePaths {
		if fp, ok := nameMatch(path.Certificates); ok {
			f.Evidence, f.CertificateFingerprint = "name_only", fp
			return f, true
		}
	}
	return f, false
}

func insertFinding(ctx context.Context, tx *sql.Tx, f model.Finding) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO findings(watch_id,probe_id,destination_id,evidence,certificate_fingerprint,observed_at) VALUES(?,?,?,?,?,?)`,
		f.WatchID, f.ProbeID, f.DestinationID, f.Evidence, f.CertificateFingerprint, timestamp(f.Time))
	return err
}

func listWatchesTx(tx *sql.Tx) ([]model.WatchEntry, error) {
	rows, err := tx.Query(`SELECT evidence_json FROM watches ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.WatchEntry
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var w model.WatchEntry
		if err = json.Unmarshal([]byte(raw), &w); err != nil {
			return nil, err
		}
		result = append(result, w)
	}
	return result, rows.Err()
}

func (s *Store) ListWatches() ([]model.WatchEntry, error) {
	rows, err := s.db.Query(`SELECT evidence_json FROM watches ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.WatchEntry
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var w model.WatchEntry
		if err = json.Unmarshal([]byte(raw), &w); err != nil {
			return nil, err
		}
		result = append(result, w)
	}
	return result, rows.Err()
}

func validLimit(n int) int {
	if n <= 0 || n > 100000 {
		return 100000
	}
	return n
}

func (s *Store) ListDestinations(limit int) ([]model.DestinationEvent, error) {
	return s.ListDestinationsBefore(0, limit)
}

// ListDestinationsBefore returns destination events newest first. Pass the
// smallest ID from the previous page as beforeID; zero starts at the newest
// event. Keyset pagination avoids skipping older events as new ones arrive.
func (s *Store) ListDestinationsBefore(beforeID int64, limit int) ([]model.DestinationEvent, error) {
	if beforeID < 0 {
		return nil, errors.New("beforeID must not be negative")
	}
	var rows *sql.Rows
	var err error
	if beforeID == 0 {
		rows, err = s.db.Query(`SELECT evidence_json FROM destination_events ORDER BY id DESC LIMIT ?`, validLimit(limit))
	} else {
		rows, err = s.db.Query(`SELECT evidence_json FROM destination_events WHERE id<? ORDER BY id DESC LIMIT ?`, beforeID, validLimit(limit))
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.DestinationEvent
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var d model.DestinationEvent
		if err = json.Unmarshal([]byte(raw), &d); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

func (s *Store) GetDestination(id int64) (model.DestinationEvent, error) {
	var d model.DestinationEvent
	var raw string
	err := s.db.QueryRow(`SELECT evidence_json FROM destination_events WHERE id=?`, id).Scan(&raw)
	if err != nil {
		return d, err
	}
	err = json.Unmarshal([]byte(raw), &d)
	return d, err
}

func (s *Store) ListProbes(limit int) ([]model.ProbeObservation, error) {
	return s.probes(`SELECT evidence_json FROM probe_observations ORDER BY id DESC LIMIT ?`, validLimit(limit))
}

// ErrExportTooLarge means a probe export exceeds its configured JSON byte
// budget. The caller can request fewer recent records rather than allocating
// an unbounded response in memory.
var ErrExportTooLarge = errors.New("probe export exceeds byte budget")

// ListProbesBounded reads the newest probes while enforcing a byte budget
// before decoding and retaining each row. The query and size check occur in
// one pass, so concurrent probe writes cannot invalidate a preflight count.
func (s *Store) ListProbesBounded(limit int, byteBudget int64) ([]model.ProbeObservation, error) {
	if byteBudget < 1 {
		return nil, errors.New("probe export byte budget must be positive")
	}
	rows, err := s.db.Query(`SELECT evidence_json FROM probe_observations ORDER BY id DESC LIMIT ?`, validLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.ProbeObservation
	var used int64
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		used += int64(len(raw))
		if used > byteBudget {
			return nil, ErrExportTooLarge
		}
		var p model.ProbeObservation
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *Store) ProbesForDestination(destinationID int64, limit int) ([]model.ProbeObservation, error) {
	return s.probes(`SELECT evidence_json FROM probe_observations WHERE destination_id=? ORDER BY id DESC LIMIT ?`, destinationID, validLimit(limit))
}

func (s *Store) probes(query string, args ...any) ([]model.ProbeObservation, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.ProbeObservation
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p model.ProbeObservation
		if err = json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *Store) GetProbe(id int64) (model.ProbeObservation, error) {
	var p model.ProbeObservation
	var raw string
	err := s.db.QueryRow(`SELECT evidence_json FROM probe_observations WHERE id=?`, id).Scan(&raw)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}

func filterClause(f FindingFilter) (string, []any) {
	where := " WHERE 1=1"
	var args []any
	if f.WatchID > 0 {
		where += " AND f.watch_id=?"
		args = append(args, f.WatchID)
	}
	if f.DestinationID > 0 {
		where += " AND f.destination_id=?"
		args = append(args, f.DestinationID)
	}
	if f.From != nil {
		where += " AND f.observed_at>=?"
		args = append(args, timestamp(*f.From))
	}
	if f.To != nil {
		where += " AND f.observed_at<?"
		args = append(args, timestamp(*f.To))
	}
	if f.Evidence == "direct" || f.Evidence == "candidate" || f.Evidence == "name_only" {
		where += " AND f.evidence=?"
		args = append(args, f.Evidence)
	}
	return where, args
}

func (s *Store) ListFindings(f FindingFilter) ([]model.Finding, error) {
	where, args := filterClause(f)
	args = append(args, validLimit(f.Limit))
	rows, err := s.db.Query(`SELECT f.id,f.watch_id,f.probe_id,f.destination_id,f.evidence,f.certificate_fingerprint,f.observed_at FROM findings f`+where+` ORDER BY f.observed_at DESC,f.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Finding
	for rows.Next() {
		var f model.Finding
		var rawTime string
		if err = rows.Scan(&f.ID, &f.WatchID, &f.ProbeID, &f.DestinationID, &f.Evidence, &f.CertificateFingerprint, &rawTime); err != nil {
			return nil, err
		}
		if f.Time, err = parseTime(rawTime); err != nil {
			return nil, err
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func (s *Store) ListAlerts(f FindingFilter) ([]Alert, error) {
	where, args := filterClause(f)
	var subWhere string
	var subArgs []any
	if f.DestinationID > 0 {
		subWhere += ` AND f2.destination_id=?`
		subArgs = append(subArgs, f.DestinationID)
	}
	if f.From != nil {
		subWhere += ` AND f2.observed_at>=?`
		subArgs = append(subArgs, timestamp(*f.From))
	}
	if f.To != nil {
		subWhere += ` AND f2.observed_at<?`
		subArgs = append(subArgs, timestamp(*f.To))
	}
	args = append(subArgs, args...)
	args = append(args, validLimit(f.Limit))
	rows, err := s.db.Query(`SELECT f.watch_id,MAX(f.destination_id),f.evidence,MIN(f.observed_at),MAX(f.observed_at),COUNT(*),
	 (SELECT f2.probe_id FROM findings f2 JOIN destination_events d2 ON d2.id=f2.destination_id
	  WHERE f2.watch_id=f.watch_id AND f2.evidence=f.evidence AND lower(d2.hostname)=lower(d.hostname)
	   AND d2.ip=d.ip AND d2.port=d.port AND d2.vantage=d.vantage`+subWhere+`
	  ORDER BY f2.observed_at DESC,f2.id DESC LIMIT 1),
	 lower(d.hostname),d.ip,d.port,d.vantage
	 FROM findings f JOIN destination_events d ON d.id=f.destination_id`+where+`
	 GROUP BY f.watch_id,lower(d.hostname),d.ip,d.port,d.vantage,f.evidence ORDER BY MAX(f.observed_at) DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Alert
	for rows.Next() {
		var a Alert
		var first, last string
		var hostname, ip, vantage string
		var port int
		if err = rows.Scan(&a.WatchID, &a.DestinationID, &a.Evidence, &first, &last, &a.ObservationCount, &a.LatestProbeID, &hostname, &ip, &port, &vantage); err != nil {
			return nil, err
		}
		// JSON array encoding preserves field boundaries even when names contain
		// separators. The hostname comes from SQLite lower(), matching GROUP BY.
		key, err := json.Marshal([4]any{hostname, ip, port, vantage})
		if err != nil {
			return nil, err
		}
		a.DestinationKey = string(key)
		if a.FirstSeen, err = parseTime(first); err != nil {
			return nil, err
		}
		if a.LastSeen, err = parseTime(last); err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

func (s *Store) Stats() (Stats, error) {
	var st Stats
	queries := []struct {
		q    string
		dest *int64
	}{
		{`SELECT COUNT(*) FROM destination_events`, &st.DestinationEvents},
		{`SELECT COUNT(*) FROM (SELECT 1 FROM destination_events GROUP BY lower(hostname),ip,port,vantage)`, &st.UniqueDestinations},
		{`SELECT COUNT(*) FROM (SELECT 1 FROM destination_events d JOIN probe_observations p ON p.destination_id=d.id GROUP BY lower(d.hostname),d.ip,d.port,d.vantage)`, &st.ProbedDestinations},
		{`SELECT COUNT(*) FROM probe_observations`, &st.Probes},
		{`SELECT COUNT(*) FROM probe_observations WHERE failure=''`, &st.SuccessfulProbes},
		{`SELECT COUNT(*) FROM probe_observations WHERE failure<>''`, &st.FailedProbes},
		{`SELECT COUNT(DISTINCT fingerprint) FROM probe_certificates WHERE kind='presented' AND is_ca=1 AND fingerprint<>''`, &st.ObservedCACertificates},
		{`SELECT COUNT(*) FROM findings`, &st.WatchlistMatches},
		{`SELECT COUNT(*) FROM (SELECT 1 FROM findings f JOIN destination_events d ON d.id=f.destination_id GROUP BY lower(d.hostname),d.ip,d.port,d.vantage)`, &st.AffectedDestinations},
		{`SELECT COUNT(*) FROM revocation_findings`, &st.RevocationFindings},
		{`SELECT COUNT(*) FROM (SELECT 1 FROM revocation_findings f JOIN destination_events d ON d.id=f.destination_id GROUP BY lower(d.hostname),d.ip,d.port,d.vantage)`, &st.RevokedDestinations},
		{`SELECT COUNT(*) FROM (SELECT 1 FROM revocation_findings WHERE evidence='direct' AND issuer_match='verified_path' GROUP BY probe_id,certificate_fingerprint)`, &st.VerifiedDirectRevocations},
	}
	for _, item := range queries {
		if err := s.db.QueryRow(item.q).Scan(item.dest); err != nil {
			return st, err
		}
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM probe_observations WHERE observed_at>=?`, timestamp(time.Now().Add(-24*time.Hour))).Scan(&st.Last24hProbes); err != nil {
		return st, err
	}
	var last sql.NullString
	if err := s.db.QueryRow(`SELECT MAX(observed_at) FROM probe_observations`).Scan(&last); err != nil {
		return st, err
	}
	if last.Valid {
		t, err := parseTime(last.String)
		if err != nil {
			return st, err
		}
		st.LatestProbe = &t
	}
	return st, nil
}

func (s *Store) CAInventory() ([]CARecord, error) {
	rows, err := s.db.Query(`SELECT DISTINCT c.probe_id,c.kind,c.fingerprint,c.observed_at,c.certificate_json,
	 lower(d.hostname),d.ip,d.port,d.vantage
	 FROM probe_certificates c JOIN destination_events d ON d.id=c.destination_id
	 WHERE c.is_ca=1 AND c.fingerprint<>'' ORDER BY c.observed_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type destinationIdentity struct {
		hostname, ip, vantage string
		port                  int
	}
	type caObservation struct {
		time time.Time
		kind string
	}
	type record struct {
		CARecord
		destinations map[destinationIdentity]struct{}
		observations []caObservation
	}
	byFP := map[string]*record{}
	for rows.Next() {
		var probeID int64
		var identity destinationIdentity
		var kind, fp, rawTime, rawCert string
		if err = rows.Scan(&probeID, &kind, &fp, &rawTime, &rawCert, &identity.hostname, &identity.ip, &identity.port, &identity.vantage); err != nil {
			return nil, err
		}
		t, e := parseTime(rawTime)
		if e != nil {
			return nil, e
		}
		r := byFP[fp]
		if r == nil {
			r = &record{destinations: map[destinationIdentity]struct{}{}}
			if e = json.Unmarshal([]byte(rawCert), &r.Certificate); e != nil {
				return nil, e
			}
			r.FirstSeen, r.LastSeen = t, t
			byFP[fp] = r
		}
		if t.Before(r.FirstSeen) {
			r.FirstSeen = t
		}
		if t.After(r.LastSeen) {
			r.LastSeen = t
		}
		if kind == "presented" {
			r.PresentedObservations++
		} else {
			r.CandidateObservations++
		}
		r.observations = append(r.observations, caObservation{t, kind})
		r.destinations[identity] = struct{}{}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	watches, err := s.ListWatches()
	if err != nil {
		return nil, err
	}
	result := make([]CARecord, 0, len(byFP))
	for _, r := range byFP {
		r.DestinationCount = int64(len(r.destinations))
		for _, w := range watches {
			var evidence string
			for _, observed := range r.observations {
				p := model.ProbeObservation{Time: observed.time}
				if observed.kind == "presented" {
					p.Presented = []model.Certificate{r.Certificate}
				} else {
					p.CandidatePaths = []model.CandidatePath{{Certificates: []model.Certificate{r.Certificate}}}
				}
				if f, ok := match(w, p); ok {
					if evidence == "" || f.Evidence == "direct" {
						evidence = f.Evidence
					}
					if evidence == "direct" {
						break
					}
				}
			}
			if evidence != "" {
				r.WatchMatches = append(r.WatchMatches, WatchLabel{w.ID, w.Name, w.Status, evidence})
			}
		}
		result = append(result, r.CARecord)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result, nil
}

// DeleteBefore removes observation history before cutoff. Cascades remove
// associated certificate rows and findings; configured watches are retained.
func (s *Store) DeleteBefore(cutoff time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM probe_observations WHERE observed_at<?`, timestamp(cutoff)); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM destination_events WHERE observed_at<? AND id NOT IN (SELECT destination_id FROM probe_observations)`, timestamp(cutoff)); err != nil {
		return err
	}
	return tx.Commit()
}
