// Package community defines the deliberately small, public report format.
// A report is a claim from an unauthenticated observer, not verified evidence.
package community

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"
)

const ReportVersion = 1

// Report contains only fields selected for publication. In particular it has
// no IP address, workload, network vantage, URL, local database ID, or exact
// probe time. A public hostname is still sensitive and must be shared opt-in.
type Report struct {
	Version           int            `json:"version"`
	Kind              string         `json:"kind"` // crl or watch
	Hostname          string         `json:"hostname"`
	Port              int            `json:"port"`
	ObservedDay       string         `json:"observed_day"` // UTC YYYY-MM-DD
	CertificateSHA256 string         `json:"certificate_sha256"`
	Evidence          string         `json:"evidence"` // direct or candidate
	CRL               *CRLEvidence   `json:"crl,omitempty"`
	Watch             *WatchEvidence `json:"watch,omitempty"`
}

type CRLEvidence struct {
	CertificateSerial string `json:"certificate_serial"`
	CRLSHA256         string `json:"crl_sha256"`
	IssuerCertSHA256  string `json:"issuer_cert_sha256"`
	IssuerSPKISHA256  string `json:"issuer_spki_sha256"`
	RevokedAt         string `json:"revoked_at"`
	ThisUpdate        string `json:"this_update"`
	NextUpdate        string `json:"next_update"`
	IssuerMatch       string `json:"issuer_match"` // verified_path or key_identifier_candidate
}

type WatchEvidence struct {
	MatchType   string `json:"match_type"` // cert_sha256 or spki_sha256
	MatchSHA256 string `json:"match_sha256"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
}

// ValidateReport checks syntax and public-hostname eligibility. It cannot
// authenticate the reporter or establish that a destination served a chain.
func ValidateReport(r Report) error {
	if r.Version != ReportVersion {
		return fmt.Errorf("version must be %d", ReportVersion)
	}
	if r.Kind != "crl" && r.Kind != "watch" {
		return errors.New("kind must be crl or watch")
	}
	if !PublicHostname(r.Hostname) {
		return errors.New("hostname must be a public DNS name")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	day, err := time.Parse("2006-01-02", r.ObservedDay)
	if err != nil || day.Format("2006-01-02") != r.ObservedDay || day.Year() < 1990 || day.After(time.Now().UTC().Add(24*time.Hour)) {
		return errors.New("observed_day must be a plausible UTC date in YYYY-MM-DD form")
	}
	if !sha256Hex(r.CertificateSHA256) {
		return errors.New("certificate_sha256 must be a SHA-256 hex fingerprint")
	}
	if r.Evidence != "direct" && r.Evidence != "candidate" {
		return errors.New("evidence must be direct or candidate")
	}
	if r.Kind == "crl" {
		if r.CRL == nil || r.Watch != nil {
			return errors.New("crl report requires crl evidence only")
		}
		if r.Evidence != "direct" || r.CRL.IssuerMatch != "verified_path" {
			return errors.New("public CRL reports require a direct probe match with a verified issuer path")
		}
		return validateCRL(*r.CRL, day)
	}
	if r.Watch == nil || r.CRL != nil {
		return errors.New("watch report requires watch evidence only")
	}
	return validateWatch(*r.Watch, r.CertificateSHA256)
}

func validateCRL(c CRLEvidence, observedDay time.Time) error {
	serial := strings.TrimSpace(strings.ToLower(c.CertificateSerial))
	if len(serial) == 0 || len(serial) > 128 || strings.Trim(serial, "0123456789abcdef") != "" {
		return errors.New("certificate_serial must be positive hexadecimal")
	}
	n := new(big.Int)
	if _, ok := n.SetString(serial, 16); !ok || n.Sign() <= 0 {
		return errors.New("certificate_serial must be positive hexadecimal")
	}
	for _, item := range []struct{ name, value string }{
		{"crl_sha256", c.CRLSHA256},
		{"issuer_cert_sha256", c.IssuerCertSHA256},
		{"issuer_spki_sha256", c.IssuerSPKISHA256},
	} {
		if !sha256Hex(item.value) {
			return fmt.Errorf("%s must be a SHA-256 hex fingerprint", item.name)
		}
	}
	revoked, err := time.Parse(time.RFC3339, c.RevokedAt)
	if err != nil {
		return errors.New("revoked_at must be RFC3339")
	}
	thisUpdate, err := time.Parse(time.RFC3339, c.ThisUpdate)
	if err != nil {
		return errors.New("this_update must be RFC3339")
	}
	nextUpdate, err := time.Parse(time.RFC3339, c.NextUpdate)
	if err != nil || !nextUpdate.After(thisUpdate) {
		return errors.New("next_update must be RFC3339 and after this_update")
	}
	if !revoked.Before(observedDay.Add(24 * time.Hour)) {
		return errors.New("revoked_at must be on or before observed_day")
	}
	if c.IssuerMatch != "verified_path" && c.IssuerMatch != "key_identifier_candidate" {
		return errors.New("issuer_match must be verified_path or key_identifier_candidate")
	}
	return nil
}

func validateWatch(w WatchEvidence, certSHA256 string) error {
	if w.MatchType != "cert_sha256" && w.MatchType != "spki_sha256" {
		return errors.New("match_type must be cert_sha256 or spki_sha256")
	}
	if !sha256Hex(w.MatchSHA256) {
		return errors.New("match_sha256 must be a SHA-256 hex fingerprint")
	}
	if w.MatchType == "cert_sha256" && !strings.EqualFold(w.MatchSHA256, certSHA256) {
		return errors.New("cert_sha256 match must identify certificate_sha256")
	}
	switch w.Status {
	case "under investigation", "distrusted", "compromised":
	default:
		return errors.New("unsupported watch status")
	}
	switch w.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return errors.New("unsupported watch severity")
	}
	return nil
}

func sha256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// PublicHostname permits ASCII DNS names and rejects IP literals, local and
// special-use suffixes. It does not claim a hostname is safe to probe; the
// public service never resolves or connects to submitted hostnames.
func PublicHostname(host string) bool {
	if host == "" || len(host) > 253 || host != strings.TrimSpace(host) || strings.HasSuffix(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	name := strings.ToLower(host)
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	for _, suffix := range []string{"localhost", "local", "internal", "lan", "home", "onion", "test", "invalid", "arpa", "example"} {
		if tld == suffix {
			return false
		}
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	if strings.Trim(tld, "0123456789") == "" {
		return false
	}
	return true
}

func canonicalReport(r Report) Report {
	r.Hostname = strings.ToLower(r.Hostname)
	r.CertificateSHA256 = strings.ToLower(r.CertificateSHA256)
	if r.CRL != nil {
		c := *r.CRL
		c.CertificateSerial = strings.ToLower(c.CertificateSerial)
		n := new(big.Int)
		if _, ok := n.SetString(c.CertificateSerial, 16); ok {
			c.CertificateSerial = n.Text(16)
		}
		c.CRLSHA256 = strings.ToLower(c.CRLSHA256)
		c.IssuerCertSHA256 = strings.ToLower(c.IssuerCertSHA256)
		c.IssuerSPKISHA256 = strings.ToLower(c.IssuerSPKISHA256)
		c.RevokedAt = canonicalTime(c.RevokedAt)
		c.ThisUpdate = canonicalTime(c.ThisUpdate)
		c.NextUpdate = canonicalTime(c.NextUpdate)
		r.CRL = &c
	}
	if r.Watch != nil {
		w := *r.Watch
		w.MatchSHA256 = strings.ToLower(w.MatchSHA256)
		r.Watch = &w
	}
	return r
}

func canonicalTime(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// ReportID is a stable content hash for deduplicating repeated submissions.
// Call ValidateReport before using its result as an accepted report ID.
func ReportID(r Report) string {
	b, _ := json.Marshal(canonicalReport(r))
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
