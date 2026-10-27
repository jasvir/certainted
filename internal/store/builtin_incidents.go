package store

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

//go:embed incidents/emudhra-2026-10.json
var incidentFiles embed.FS

// IncidentCertificate is one exact certificate variant of an affected key.
type IncidentCertificate struct {
	IssuedBy  string `json:"issued_by"`
	SHA256    string `json:"sha256"`
	SerialHex string `json:"serial_hex"`
}

// IncidentIntermediate groups cross-signed certificates by the same CA key.
type IncidentIntermediate struct {
	Name         string                `json:"name"`
	Usage        string                `json:"usage"`
	SPKISHA256   string                `json:"spki_sha256"`
	Certificates []IncidentCertificate `json:"certificates"`
}

// IncidentManifest describes the exact bundled identities and their sources.
// It does not assert that an application encountered any of these certificates.
type IncidentManifest struct {
	ID            string                 `json:"id"`
	AsOf          string                 `json:"as_of"`
	Sources       []string               `json:"sources"`
	Description   string                 `json:"description"`
	Intermediates []IncidentIntermediate `json:"intermediates"`
}

// BuiltinIncidentManifest returns a newly decoded copy so callers cannot
// mutate the watch definitions subsequently used for seeding.
func BuiltinIncidentManifest() (IncidentManifest, error) {
	data, err := incidentFiles.ReadFile("incidents/emudhra-2026-10.json")
	if err != nil {
		return IncidentManifest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest IncidentManifest
	if err := decoder.Decode(&manifest); err != nil {
		return IncidentManifest{}, fmt.Errorf("decode bundled incident: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return IncidentManifest{}, errors.New("bundled incident contains trailing data")
	}
	return manifest, nil
}

// SeedBuiltinIncidentWatches adds exact key watches for the documented
// October 2026 eMudhra incident. The embedded list makes no network requests.
// It is an incident notice, not a signed-CRL import. Existing watches for a
// key take precedence, and a deleted or edited built-in watch is never reset.
// Newly added keys in a later bundled manifest are added on a later startup.
// Every new rule reevaluates retained probe history in the same transaction.
func (s *Store) SeedBuiltinIncidentWatches(ctx context.Context) (WatchImportResult, error) {
	manifest, err := BuiltinIncidentManifest()
	if err != nil {
		return WatchImportResult{}, err
	}
	return s.seedIncidentWatches(ctx, manifest)
}

func (s *Store) seedIncidentWatches(ctx context.Context, manifest IncidentManifest) (WatchImportResult, error) {
	result := WatchImportResult{IDs: []int64{}}
	if manifest.ID == "" || len(manifest.ID) > 128 || len(manifest.Intermediates) == 0 || len(manifest.Intermediates) > MaxWatchImportEntries || len(manifest.Sources) == 0 {
		return result, errors.New("bundled incident has invalid metadata")
	}
	if len(manifest.Sources[0]) > 800 {
		return result, errors.New("bundled incident source is too long")
	}
	prepared := make([]model.WatchEntry, 0, len(manifest.Intermediates))
	seenKeys := make(map[string]bool)
	seenCerts := make(map[string]bool)
	for _, ca := range manifest.Intermediates {
		if ca.Usage != "tls" && ca.Usage != "code-signing" {
			return result, fmt.Errorf("bundled incident has invalid usage for %q", ca.Name)
		}
		if len(ca.Certificates) != 2 {
			return result, fmt.Errorf("bundled incident needs both certificate variants for %q", ca.Name)
		}
		for _, cert := range ca.Certificates {
			fp := normalizeFingerprint(cert.SHA256)
			if len(fp) != 64 || strings.Trim(fp, "0123456789abcdef") != "" || seenCerts[fp] || cert.IssuedBy == "" {
				return result, fmt.Errorf("bundled incident has invalid certificate for %q", ca.Name)
			}
			if _, ok := canonicalSerial(cert.SerialHex); !ok {
				return result, fmt.Errorf("bundled incident has invalid serial for %q", ca.Name)
			}
			seenCerts[fp] = true
		}
		reason := "eMudhra and browser root programs reported this intermediate CA private key compromised because of insufficient key entropy; eMudhra reported revoking it in October 2026. This built-in incident watch is not a locally signature-verified CRL."
		if ca.Usage == "code-signing" {
			reason += " This code-signing key is outside Certainted's TLS-probe scope."
		}
		entry, err := normalizeWatch(model.WatchEntry{
			Name: ca.Name, Group: "eMudhra October 2026 weak-key intermediates", MatchType: "spki_sha256",
			Value: ca.SPKISHA256, Status: "compromised", Severity: "critical", Reason: reason,
			Source: "Built-in eMudhra incident notice: " + manifest.Sources[0],
		})
		if err != nil {
			return result, fmt.Errorf("bundled incident %q: %w", ca.Name, err)
		}
		key := watchImportKey(entry)
		if seenKeys[key] {
			return result, fmt.Errorf("bundled incident repeats key for %q", ca.Name)
		}
		seenKeys[key] = true
		prepared = append(prepared, entry)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	for _, entry := range prepared {
		if err := ctx.Err(); err != nil {
			return WatchImportResult{}, err
		}
		var alreadyApplied int
		err := tx.QueryRowContext(ctx, `SELECT 1 FROM builtin_watch_keys WHERE bundle_id=? AND match_type=? AND value=?`, manifest.ID, entry.MatchType, entry.Value).Scan(&alreadyApplied)
		if err == nil {
			result.Skipped++
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return WatchImportResult{}, err
		}
		var existing int
		err = tx.QueryRowContext(ctx, `SELECT 1 FROM watches WHERE match_type=? AND value=? LIMIT 1`, entry.MatchType, entry.Value).Scan(&existing)
		if err == nil {
			result.Skipped++
		} else if !errors.Is(err, sql.ErrNoRows) {
			return WatchImportResult{}, err
		} else {
			if err := saveWatchTx(ctx, tx, &entry); err != nil {
				return WatchImportResult{}, err
			}
			result.Imported++
			result.IDs = append(result.IDs, entry.ID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO builtin_watch_keys(bundle_id,match_type,value,applied_at) VALUES(?,?,?,?)`, manifest.ID, entry.MatchType, entry.Value, timestamp(time.Now())); err != nil {
			return WatchImportResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return WatchImportResult{}, err
	}
	return result, nil
}
