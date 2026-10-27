package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/revocation"
)

// CRLRecord describes a locally imported, cryptographically verified CRL.
// Source is the caller-supplied provenance, not an automatic network lookup.
type CRLRecord struct {
	ID                    int64     `json:"id"`
	Fingerprint           string    `json:"fingerprint_sha256"`
	IssuerFingerprint     string    `json:"issuer_fingerprint_sha256"`
	IssuerSPKIFingerprint string    `json:"issuer_spki_sha256"`
	IssuerNameHash        string    `json:"issuer_name_sha256"`
	Issuer                string    `json:"issuer"`
	AuthorityKeyID        string    `json:"authority_key_identifier,omitempty"`
	IssuerSubjectKeyID    string    `json:"issuer_subject_key_identifier,omitempty"`
	ThisUpdate            time.Time `json:"this_update"`
	NextUpdate            time.Time `json:"next_update"`
	Number                string    `json:"number,omitempty"`
	Source                string    `json:"source"`
	ImportedAt            time.Time `json:"imported_at"`
	EntryCount            int       `json:"entry_count"`
}

// RevocationFinding is evidence from an independent probe. It says that a
// certificate observed in that probe was listed in a verified CRL; it makes
// no claim about an application's own TLS session or trust decision.
type RevocationFinding struct {
	ID                     int64     `json:"id"`
	CRLID                  int64     `json:"crl_id"`
	ProbeID                int64     `json:"probe_id"`
	DestinationID          int64     `json:"destination_id"`
	DestinationKey         string    `json:"destination_key"`
	Evidence               string    `json:"evidence"`     // direct or candidate
	IssuerMatch            string    `json:"issuer_match"` // verified_path or key_identifier_candidate
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	CertificateSerial      string    `json:"certificate_serial"`
	Time                   time.Time `json:"time"`
	RevokedAt              time.Time `json:"revoked_at"`
	ReasonCode             int       `json:"reason_code"`
	Reason                 string    `json:"reason,omitempty"`
	CRLFingerprint         string    `json:"crl_fingerprint_sha256"`
	Issuer                 string    `json:"issuer"`
	Source                 string    `json:"source"`
	CRLThisUpdate          time.Time `json:"crl_this_update"`
	CRLNextUpdate          time.Time `json:"crl_next_update"`
	// ThisUpdate later than the probe means the CRL's update time follows the
	// observation. It does not establish when the CRL was published.
	CRLThisUpdateAfterProbe bool `json:"crl_this_update_after_probe"`
	// A CRL past nextUpdate is historical evidence, not fresh status.
	CRLStaleAtProbe bool `json:"crl_stale_at_probe"`
}

type RevocationFindingFilter struct {
	CRLID         int64
	DestinationID int64
	From          *time.Time
	To            *time.Time
	Evidence      string
	Limit         int
}

// ImportCRL atomically stores a verified, full-scope CRL and reevaluates all
// retained probe history. Reimporting identical DER is idempotent. The
// revocation package validates signature, issuer, scope, and freshness before
// giving a List its unexported verification marker.
func (s *Store) ImportCRL(list *revocation.List, source string) (int64, error) {
	if list == nil || !list.Verified() {
		return 0, errors.New("CRL must be parsed and verified before import")
	}
	if len(source) > 1024 {
		return 0, errors.New("CRL source is too long")
	}
	if source == "" {
		source = "local import"
	}
	if list.Fingerprint == "" || list.IssuerNameHash == "" || !list.NextUpdate.After(list.ThisUpdate) {
		return 0, errors.New("verified CRL is missing required identity or time fields")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var existingID int64
	err = tx.QueryRow(`SELECT id FROM crl_imports WHERE fingerprint=?`, normalizeFingerprint(list.Fingerprint)).Scan(&existingID)
	if err == nil {
		return existingID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	r, err := tx.Exec(`INSERT INTO crl_imports(fingerprint,issuer_fingerprint,issuer_spki_fingerprint,issuer_name_hash,issuer,authority_key_id,issuer_subject_key_id,this_update,next_update,number,source,imported_at,entry_count)
	 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, normalizeFingerprint(list.Fingerprint), normalizeFingerprint(list.IssuerFingerprint), normalizeFingerprint(list.IssuerSPKIFingerprint), normalizeFingerprint(list.IssuerNameHash), list.Issuer,
		normalizeFingerprint(list.AuthorityKeyID), normalizeFingerprint(list.IssuerSubjectKeyID), timestamp(list.ThisUpdate), timestamp(list.NextUpdate), list.Number, source, timestamp(time.Now()), len(list.Entries))
	if err != nil {
		return 0, err
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	entries := make(map[string]revocation.Entry, len(list.Entries))
	entryStmt, err := tx.Prepare(`INSERT INTO crl_entries(crl_id,serial,revoked_at,reason_code,reason) VALUES(?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	for _, entry := range list.Entries {
		serial, ok := canonicalSerial(entry.Serial)
		if !ok || entry.RevokedAt.IsZero() {
			entryStmt.Close()
			return 0, errors.New("verified CRL contains an invalid entry")
		}
		if _, duplicate := entries[serial]; duplicate {
			entryStmt.Close()
			return 0, fmt.Errorf("verified CRL repeats serial %s", serial)
		}
		entry.Serial = serial
		entries[serial] = entry
		if _, err = entryStmt.Exec(id, serial, timestamp(entry.RevokedAt), entry.ReasonCode, entry.Reason); err != nil {
			entryStmt.Close()
			return 0, err
		}
	}
	if err = entryStmt.Close(); err != nil {
		return 0, err
	}
	meta := crlMatchMeta{ID: id, IssuerNameHash: normalizeFingerprint(list.IssuerNameHash), IssuerSPKIFingerprint: normalizeFingerprint(list.IssuerSPKIFingerprint), AuthorityKeyID: normalizeFingerprint(list.AuthorityKeyID), IssuerSubjectKeyID: normalizeFingerprint(list.IssuerSubjectKeyID), NextUpdate: list.NextUpdate}
	var afterID int64
	for {
		rows, queryErr := tx.Query(`SELECT id,evidence_json FROM probe_observations WHERE id>? ORDER BY id LIMIT 256`, afterID)
		if queryErr != nil {
			return 0, queryErr
		}
		var probes []model.ProbeObservation
		for rows.Next() {
			var raw string
			var rowID int64
			if err = rows.Scan(&rowID, &raw); err != nil {
				break
			}
			var p model.ProbeObservation
			if err = decodeProbe(raw, &p); err != nil {
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
			return 0, err
		}
		for _, p := range probes {
			if err = evaluateCRLAgainstProbeTx(tx, meta, entries, p); err != nil {
				return 0, err
			}
		}
		if len(probes) < 256 {
			break
		}
	}
	return id, tx.Commit()
}

// decodeProbe is kept here to leave the older store schema and evidence JSON
// compatible with databases created before CRL support.
func decodeProbe(raw string, p *model.ProbeObservation) error {
	return json.Unmarshal([]byte(raw), p)
}

type crlMatchMeta struct {
	ID                    int64
	IssuerNameHash        string
	IssuerSPKIFingerprint string
	AuthorityKeyID        string
	IssuerSubjectKeyID    string
	NextUpdate            time.Time
}

type revocationCandidate struct {
	Cert     model.Certificate
	Evidence string
}

func uniqueProbeCertificates(p model.ProbeObservation) []revocationCandidate {
	seen := map[string]bool{}
	result := make([]revocationCandidate, 0, len(p.Presented))
	for _, cert := range p.Presented {
		fp := normalizeFingerprint(cert.Fingerprint)
		if fp != "" && !seen[fp] {
			seen[fp] = true
			result = append(result, revocationCandidate{cert, "direct"})
		}
	}
	for _, path := range p.CandidatePaths {
		if path.Validation != "verified" {
			continue
		}
		for _, cert := range path.Certificates {
			fp := normalizeFingerprint(cert.Fingerprint)
			if fp != "" && !seen[fp] {
				seen[fp] = true
				result = append(result, revocationCandidate{cert, "candidate"})
			}
		}
	}
	return result
}

func canonicalSerial(s string) (string, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if strings.HasPrefix(s, "0x") {
		s = s[2:]
	}
	if s == "" || strings.Trim(s, "0123456789abcdef") != "" {
		return "", false
	}
	n := new(big.Int)
	if _, ok := n.SetString(s, 16); !ok || n.Sign() <= 0 {
		return "", false
	}
	return n.Text(16), true
}

// issuerPathMatch returns whether a verified candidate path identifies the
// same issuer key as the CRL signer. The second return says whether any such
// path relationship was available. If none was available, AKI/SKI provides
// the fallback; subject display names alone are never sufficient.
func issuerPathMatch(p model.ProbeObservation, cert model.Certificate, issuerSPKI string) (bool, bool) {
	if issuerSPKI == "" {
		return false, false
	}
	fp := normalizeFingerprint(cert.Fingerprint)
	var found bool
	for _, path := range p.CandidatePaths {
		if path.Validation != "verified" {
			continue
		}
		for i, c := range path.Certificates {
			if normalizeFingerprint(c.Fingerprint) != fp {
				continue
			}
			if i+1 < len(path.Certificates) {
				found = true
				if normalizeFingerprint(path.Certificates[i+1].SPKIFingerprint) == issuerSPKI {
					return true, true
				}
			} else if c.SelfSigned {
				found = true
				if normalizeFingerprint(c.SPKIFingerprint) == issuerSPKI {
					return true, true
				}
			}
		}
	}
	return false, found
}

func matchCRLEntry(p model.ProbeObservation, cert model.Certificate, meta crlMatchMeta, revokedAt time.Time) string {
	if p.Time.Before(revokedAt) || normalizeFingerprint(cert.IssuerNameSHA256) == "" || normalizeFingerprint(cert.IssuerNameSHA256) != meta.IssuerNameHash {
		return ""
	}
	aki := normalizeFingerprint(cert.AuthorityKeyIdentifier)
	if aki != "" && meta.IssuerSubjectKeyID != "" && aki != meta.IssuerSubjectKeyID {
		return ""
	}
	if aki != "" && meta.AuthorityKeyID != "" && aki != meta.AuthorityKeyID {
		return ""
	}
	if signer := normalizeFingerprint(cert.VerifiedIssuerSPKIFingerprint); signer != "" {
		if signer == meta.IssuerSPKIFingerprint {
			return "verified_path"
		}
		return ""
	}
	if keyMatches, foundPath := issuerPathMatch(p, cert, meta.IssuerSPKIFingerprint); foundPath {
		if keyMatches {
			return "verified_path"
		}
		return ""
	}
	// A precise issuer DN and serial are insufficient when two CA keys share
	// a subject. Without a verified path, require a matching key identifier
	// and explicitly label the identity as a candidate, not a verified issuer.
	if aki != "" && ((meta.IssuerSubjectKeyID != "" && aki == meta.IssuerSubjectKeyID) || (meta.AuthorityKeyID != "" && aki == meta.AuthorityKeyID)) {
		return "key_identifier_candidate"
	}
	return ""
}

func insertRevocationFinding(tx *sql.Tx, meta crlMatchMeta, p model.ProbeObservation, candidate revocationCandidate, serial, issuerMatch string) error {
	_, err := tx.Exec(`INSERT OR IGNORE INTO revocation_findings(crl_id,probe_id,destination_id,evidence,issuer_match,certificate_fingerprint,certificate_serial,observed_at) VALUES(?,?,?,?,?,?,?,?)`,
		meta.ID, p.ID, p.DestinationID, candidate.Evidence, issuerMatch, normalizeFingerprint(candidate.Cert.Fingerprint), serial, timestamp(p.Time))
	return err
}

func evaluateCRLAgainstProbeTx(tx *sql.Tx, meta crlMatchMeta, entries map[string]revocation.Entry, p model.ProbeObservation) error {
	for _, candidate := range uniqueProbeCertificates(p) {
		serial, ok := canonicalSerial(candidate.Cert.Serial)
		if !ok {
			continue
		}
		entry, ok := entries[serial]
		if !ok {
			continue
		}
		issuerMatch := matchCRLEntry(p, candidate.Cert, meta, entry.RevokedAt)
		if issuerMatch == "" {
			continue
		}
		if err := insertRevocationFinding(tx, meta, p, candidate, serial, issuerMatch); err != nil {
			return err
		}
	}
	return nil
}

// evaluateRevocationsForProbeTx evaluates each new independent probe against
// imported CRLs without loading full CRL entry sets into application memory.
func evaluateRevocationsForProbeTx(tx *sql.Tx, p model.ProbeObservation) error {
	for _, candidate := range uniqueProbeCertificates(p) {
		serial, ok := canonicalSerial(candidate.Cert.Serial)
		if !ok || candidate.Cert.IssuerNameSHA256 == "" {
			continue
		}
		rows, err := tx.Query(`SELECT c.id,c.issuer_name_hash,c.issuer_spki_fingerprint,c.authority_key_id,c.issuer_subject_key_id,c.next_update,e.revoked_at
		 FROM crl_imports c JOIN crl_entries e ON e.crl_id=c.id WHERE c.issuer_name_hash=? AND e.serial=?`, normalizeFingerprint(candidate.Cert.IssuerNameSHA256), serial)
		if err != nil {
			return err
		}
		type result struct {
			meta      crlMatchMeta
			revokedAt time.Time
		}
		var matches []result
		for rows.Next() {
			var m result
			var nextUpdate, revokedAt string
			if err = rows.Scan(&m.meta.ID, &m.meta.IssuerNameHash, &m.meta.IssuerSPKIFingerprint, &m.meta.AuthorityKeyID, &m.meta.IssuerSubjectKeyID, &nextUpdate, &revokedAt); err != nil {
				break
			}
			if m.meta.NextUpdate, err = parseTime(nextUpdate); err != nil {
				break
			}
			if m.revokedAt, err = parseTime(revokedAt); err != nil {
				break
			}
			matches = append(matches, m)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		for _, m := range matches {
			if issuerMatch := matchCRLEntry(p, candidate.Cert, m.meta, m.revokedAt); issuerMatch != "" {
				if err = insertRevocationFinding(tx, m.meta, p, candidate, serial, issuerMatch); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Store) ListCRLs() ([]CRLRecord, error) {
	rows, err := s.db.Query(`SELECT id,fingerprint,issuer_fingerprint,issuer_spki_fingerprint,issuer_name_hash,issuer,authority_key_id,issuer_subject_key_id,this_update,next_update,number,source,imported_at,entry_count FROM crl_imports ORDER BY this_update DESC,id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []CRLRecord
	for rows.Next() {
		var r CRLRecord
		var thisUpdate, nextUpdate, importedAt string
		if err = rows.Scan(&r.ID, &r.Fingerprint, &r.IssuerFingerprint, &r.IssuerSPKIFingerprint, &r.IssuerNameHash, &r.Issuer, &r.AuthorityKeyID, &r.IssuerSubjectKeyID, &thisUpdate, &nextUpdate, &r.Number, &r.Source, &importedAt, &r.EntryCount); err != nil {
			return nil, err
		}
		if r.ThisUpdate, err = parseTime(thisUpdate); err != nil {
			return nil, err
		}
		if r.NextUpdate, err = parseTime(nextUpdate); err != nil {
			return nil, err
		}
		if r.ImportedAt, err = parseTime(importedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) ListRevocationFindings(f RevocationFindingFilter) ([]RevocationFinding, error) {
	where := ` WHERE 1=1`
	var args []any
	if f.CRLID > 0 {
		where += ` AND f.crl_id=?`
		args = append(args, f.CRLID)
	}
	if f.DestinationID > 0 {
		where += ` AND f.destination_id=?`
		args = append(args, f.DestinationID)
	}
	if f.From != nil {
		where += ` AND f.observed_at>=?`
		args = append(args, timestamp(*f.From))
	}
	if f.To != nil {
		where += ` AND f.observed_at<?`
		args = append(args, timestamp(*f.To))
	}
	if f.Evidence == "direct" || f.Evidence == "candidate" {
		where += ` AND f.evidence=?`
		args = append(args, f.Evidence)
	}
	args = append(args, validLimit(f.Limit))
	rows, err := s.db.Query(`SELECT f.id,f.crl_id,f.probe_id,f.destination_id,f.evidence,f.issuer_match,f.certificate_fingerprint,f.certificate_serial,f.observed_at,
	 e.revoked_at,e.reason_code,e.reason,c.fingerprint,c.issuer,c.source,c.this_update,c.next_update,
	 lower(d.hostname),d.ip,d.port,d.vantage
	 FROM revocation_findings f JOIN crl_imports c ON c.id=f.crl_id JOIN crl_entries e ON e.crl_id=f.crl_id AND e.serial=f.certificate_serial
	 JOIN destination_events d ON d.id=f.destination_id`+where+` ORDER BY f.observed_at DESC,f.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []RevocationFinding
	for rows.Next() {
		var finding RevocationFinding
		var observedAt, revokedAt, thisUpdate, nextUpdate string
		var hostname, ip, vantage string
		var port int
		if err = rows.Scan(&finding.ID, &finding.CRLID, &finding.ProbeID, &finding.DestinationID, &finding.Evidence, &finding.IssuerMatch, &finding.CertificateFingerprint, &finding.CertificateSerial,
			&observedAt, &revokedAt, &finding.ReasonCode, &finding.Reason, &finding.CRLFingerprint, &finding.Issuer, &finding.Source, &thisUpdate, &nextUpdate,
			&hostname, &ip, &port, &vantage); err != nil {
			return nil, err
		}
		key, err := json.Marshal([4]any{hostname, ip, port, vantage})
		if err != nil {
			return nil, err
		}
		finding.DestinationKey = string(key)
		if finding.Time, err = parseTime(observedAt); err != nil {
			return nil, err
		}
		if finding.RevokedAt, err = parseTime(revokedAt); err != nil {
			return nil, err
		}
		if finding.CRLThisUpdate, err = parseTime(thisUpdate); err != nil {
			return nil, err
		}
		if finding.CRLNextUpdate, err = parseTime(nextUpdate); err != nil {
			return nil, err
		}
		finding.CRLThisUpdateAfterProbe = finding.Time.Before(finding.CRLThisUpdate)
		finding.CRLStaleAtProbe = !finding.Time.Before(finding.CRLNextUpdate)
		result = append(result, finding)
	}
	return result, rows.Err()
}
