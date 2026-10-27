package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ShareSource contains only the local fields needed to construct a public
// report. It is never serialized as an outbound payload.
type ShareSource struct {
	ID                string
	Kind              string
	Hostname          string
	Port              int
	TargetIP          string
	ObservedAt        time.Time
	CertificateSHA256 string
	Evidence          string
	CRLSHA256         string
	IssuerCertSHA256  string
	IssuerSPKISHA256  string
	CertificateSerial string
	RevokedAt         time.Time
	CRLThisUpdate     time.Time
	CRLNextUpdate     time.Time
	IssuerMatch       string
	WatchMatchType    string
	WatchMatchSHA256  string
	WatchStatus       string
	WatchSeverity     string
}

type SharingSettings struct {
	Mode      string     `json:"mode"`
	EnabledAt *time.Time `json:"enabled_at,omitempty"`
}

const sharingSchema = `
CREATE TABLE IF NOT EXISTS community_sharing_settings (
 id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL CHECK(mode IN ('manual','auto')),
 enabled_at TEXT NOT NULL
);
INSERT OR IGNORE INTO community_sharing_settings(id,mode,enabled_at) VALUES(1,'manual','');
CREATE TABLE IF NOT EXISTS community_shared_reports (
 report_id TEXT PRIMARY KEY, shared_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS community_processed_sources (
 source_id TEXT PRIMARY KEY, report_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('shared','ineligible')),
 processed_at TEXT NOT NULL
);
`

func (s *Store) initSharing() error {
	_, err := s.db.Exec(sharingSchema)
	return err
}

func (s *Store) SharingSettings() (SharingSettings, error) {
	var out SharingSettings
	var enabled string
	err := s.db.QueryRow(`SELECT mode,enabled_at FROM community_sharing_settings WHERE id=1`).Scan(&out.Mode, &enabled)
	if err != nil {
		return out, err
	}
	if enabled != "" {
		t, err := parseTime(enabled)
		if err != nil {
			return out, err
		}
		out.EnabledAt = &t
	}
	return out, nil
}

// SetSharingMode resets the activation boundary every time automatic sharing
// is turned on. Historical findings are therefore never sent automatically.
func (s *Store) SetSharingMode(mode string) (SharingSettings, error) {
	if mode != "manual" && mode != "auto" {
		return SharingSettings{}, errors.New("sharing mode must be manual or auto")
	}
	current, err := s.SharingSettings()
	if err != nil {
		return SharingSettings{}, err
	}
	if current.Mode == mode {
		return current, nil
	}
	var enabled string
	if mode == "auto" {
		enabled = timestamp(time.Now().UTC())
	}
	_, err = s.db.Exec(`UPDATE community_sharing_settings SET mode=?,enabled_at=? WHERE id=1`, mode, enabled)
	if err != nil {
		return SharingSettings{}, err
	}
	return s.SharingSettings()
}

func (s *Store) HasSharedReport(reportID string) (bool, error) {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM community_shared_reports WHERE report_id=?`, reportID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) MarkSharedReport(reportID string) error {
	if len(reportID) != 64 || strings.Trim(reportID, "0123456789abcdef") != "" {
		return errors.New("invalid report id")
	}
	_, err := s.db.Exec(`INSERT OR IGNORE INTO community_shared_reports(report_id,shared_at) VALUES(?,?)`, reportID, timestamp(time.Now().UTC()))
	return err
}

func (s *Store) MarkProcessedSource(sourceID, reportID, status string) error {
	if status != "shared" && status != "ineligible" {
		return errors.New("invalid share source status")
	}
	if !validShareSourceID(sourceID) {
		return errors.New("invalid share source id")
	}
	if status == "shared" && (len(reportID) != 64 || strings.Trim(reportID, "0123456789abcdef") != "") {
		return errors.New("invalid report id")
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO community_processed_sources(source_id,report_id,status,processed_at) VALUES(?,?,?,?)`, sourceID, reportID, status, timestamp(time.Now().UTC()))
	return err
}

func validShareSourceID(id string) bool {
	kind, rawID, ok := strings.Cut(id, ":")
	if !ok || (kind != "crl" && kind != "watch") {
		return false
	}
	n, err := strconv.ParseInt(rawID, 10, 64)
	return err == nil && n > 0 && fmt.Sprintf("%s:%d", kind, n) == id
}

// The direct CRL branch needs both a presented certificate and a verified
// issuer-key relationship. CA watches require exact fingerprint/key matching
// and a CA certificate; manually assigned names are never published as facts.
const shareSourcesSQL = `
SELECT kind,local_id,hostname,port,target_ip,observed_at,certificate_fingerprint,evidence,
 crl_fingerprint,issuer_fingerprint,issuer_spki,certificate_serial,revoked_at,this_update,next_update,issuer_match,
 watch_match_type,watch_value,watch_status,watch_severity
FROM (
 SELECT 'crl' AS kind,f.id AS local_id,d.hostname AS hostname,d.port AS port,p.target_ip AS target_ip,
  f.observed_at AS observed_at,f.certificate_fingerprint AS certificate_fingerprint,f.evidence AS evidence,
  c.fingerprint AS crl_fingerprint,c.issuer_fingerprint AS issuer_fingerprint,c.issuer_spki_fingerprint AS issuer_spki,
  f.certificate_serial AS certificate_serial,e.revoked_at AS revoked_at,c.this_update AS this_update,c.next_update AS next_update,
  f.issuer_match AS issuer_match,'' AS watch_match_type,'' AS watch_value,'' AS watch_status,'' AS watch_severity
 FROM revocation_findings f JOIN crl_imports c ON c.id=f.crl_id
 JOIN crl_entries e ON e.crl_id=f.crl_id AND e.serial=f.certificate_serial
 JOIN probe_observations p ON p.id=f.probe_id JOIN destination_events d ON d.id=f.destination_id
 WHERE f.evidence='direct' AND f.issuer_match='verified_path' AND p.failure=''
 UNION ALL
 SELECT 'watch',f.id,d.hostname,d.port,p.target_ip,f.observed_at,f.certificate_fingerprint,f.evidence,
  '','','','','','','','',w.match_type,w.value,w.status,
  json_extract(w.evidence_json,'$.severity')
 FROM findings f JOIN watches w ON w.id=f.watch_id
 JOIN probe_observations p ON p.id=f.probe_id JOIN destination_events d ON d.id=f.destination_id
 WHERE f.evidence IN ('direct','candidate') AND p.failure=''
  AND w.match_type IN ('cert_sha256','spki_sha256')
  AND w.status IN ('under investigation','distrusted','compromised')
  AND EXISTS (SELECT 1 FROM probe_certificates pc WHERE pc.probe_id=f.probe_id
   AND pc.fingerprint=f.certificate_fingerprint AND pc.is_ca=1 AND pc.kind=CASE f.evidence WHEN 'direct' THEN 'presented' ELSE 'candidate' END)
)
`

// ListShareSources returns a bounded set, newest first for review and oldest
// first after an auto-sharing activation boundary. Eligibility and redaction
// are checked again when a report is constructed.
func (s *Store) ListShareSources(since *time.Time, limit int) ([]ShareSource, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("share candidate limit must be between 1 and 1000")
	}
	query := shareSourcesSQL
	var args []any
	order := "DESC"
	if since != nil {
		query += ` WHERE observed_at>=? AND NOT EXISTS (SELECT 1 FROM community_processed_sources done WHERE done.source_id=kind||':'||local_id)`
		args = append(args, timestamp(*since))
		order = "ASC"
	}
	query += ` ORDER BY observed_at ` + order + `,kind,local_id ` + order + ` LIMIT ?`
	args = append(args, limit)
	return s.readShareSources(query, args...)
}

func (s *Store) GetShareSource(id string) (ShareSource, error) {
	if !validShareSourceID(id) {
		return ShareSource{}, errors.New("invalid share candidate id")
	}
	kind, rawID, _ := strings.Cut(id, ":")
	n, _ := strconv.ParseInt(rawID, 10, 64)
	rows, err := s.readShareSources(shareSourcesSQL+` WHERE kind=? AND local_id=? LIMIT 1`, kind, n)
	if err != nil {
		return ShareSource{}, err
	}
	if len(rows) == 0 {
		return ShareSource{}, sql.ErrNoRows
	}
	return rows[0], nil
}

func (s *Store) readShareSources(query string, args ...any) ([]ShareSource, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ShareSource
	for rows.Next() {
		var source ShareSource
		var localID int64
		var observed, revoked, thisUpdate, nextUpdate string
		if err := rows.Scan(&source.Kind, &localID, &source.Hostname, &source.Port, &source.TargetIP,
			&observed, &source.CertificateSHA256, &source.Evidence,
			&source.CRLSHA256, &source.IssuerCertSHA256, &source.IssuerSPKISHA256, &source.CertificateSerial,
			&revoked, &thisUpdate, &nextUpdate, &source.IssuerMatch,
			&source.WatchMatchType, &source.WatchMatchSHA256, &source.WatchStatus, &source.WatchSeverity); err != nil {
			return nil, err
		}
		source.ID = fmt.Sprintf("%s:%d", source.Kind, localID)
		if source.ObservedAt, err = parseTime(observed); err != nil {
			return nil, err
		}
		if source.Kind == "crl" {
			if source.RevokedAt, err = parseTime(revoked); err != nil {
				return nil, err
			}
			if source.CRLThisUpdate, err = parseTime(thisUpdate); err != nil {
				return nil, err
			}
			if source.CRLNextUpdate, err = parseTime(nextUpdate); err != nil {
				return nil, err
			}
		}
		out = append(out, source)
	}
	return out, rows.Err()
}
