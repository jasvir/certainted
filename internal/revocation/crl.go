// Package revocation verifies imported, offline certificate revocation lists.
// It intentionally does not fetch CRLs or assert that an application received
// the certificate observed by an independent probe.
package revocation

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	defaultMaxCRLBytes    = 8 << 20
	defaultMaxIssuerBytes = 256 << 10
	defaultMaxEntries     = 100_000
)

var (
	oidCRLNumber                = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCertificateIssuer        = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidAuthorityKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidFreshestCRL              = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// Limits bound untrusted input before parsing. A zero field uses the default.
type Limits struct {
	MaxCRLBytes    int
	MaxIssuerBytes int
	MaxEntries     int
}

// Entry is a revocation record from a signature-verified, current full CRL.
// Serial is lowercase hexadecimal, matching the probe certificate inventory.
type Entry struct {
	Serial     string    `json:"serial"`
	RevokedAt  time.Time `json:"revoked_at"`
	ReasonCode int       `json:"reason_code"`
	Reason     string    `json:"reason"`
}

// List retains CRL provenance and revocation entries. The issuer certificate
// identifies the signer; it is not thereby established as a trusted root.
// IssuerNameHash hashes the raw DER issuer name, not its display string.
type List struct {
	Fingerprint           string    `json:"fingerprint_sha256"`
	IssuerFingerprint     string    `json:"issuer_fingerprint_sha256"`
	IssuerSPKIFingerprint string    `json:"issuer_spki_sha256"`
	Issuer                string    `json:"issuer"`
	IssuerNameHash        string    `json:"issuer_name_sha256"`
	AuthorityKeyID        string    `json:"authority_key_id,omitempty"`
	IssuerSubjectKeyID    string    `json:"issuer_subject_key_id,omitempty"`
	ThisUpdate            time.Time `json:"this_update"`
	NextUpdate            time.Time `json:"next_update"`
	Number                string    `json:"number,omitempty"`
	Entries               []Entry   `json:"entries"`

	verified   bool
	seal       [sha256.Size]byte
	issuerCert *x509.Certificate
	bySerial   map[string]int
}

// Verified reports whether ParseAndVerify established the list's signature,
// issuer, full scope and freshness. It distinguishes a parsed list from a
// caller-constructed List before persistence.
func (l *List) Verified() bool {
	if l == nil || !l.verified {
		return false
	}
	// Fields are exported so the storage layer can persist them. Recheck the
	// parse-time seal before a caller can rely on the verification marker.
	b, err := json.Marshal(l)
	return err == nil && sha256.Sum256(b) == l.seal
}

// ParseAndVerify accepts one PEM or DER CRL and one PEM or DER issuer
// certificate. It rejects unsupported scoped, indirect, delta or critical
// extensions rather than presenting their entries as a full issuer CRL.
// Freshness is checked at now; callers should recheck NextUpdate before using
// a stored list. No network access occurs.
func ParseAndVerify(crlBytes, issuerCertBytes []byte, now time.Time, limits Limits) (*List, error) {
	if now.IsZero() {
		return nil, errors.New("verification time is required")
	}
	limits = effectiveLimits(limits)
	crlDER, err := decodeOne(crlBytes, "X509 CRL", limits.MaxCRLBytes)
	if err != nil {
		return nil, fmt.Errorf("CRL: %w", err)
	}
	issuerDER, err := decodeOne(issuerCertBytes, "CERTIFICATE", limits.MaxIssuerBytes)
	if err != nil {
		return nil, fmt.Errorf("issuer certificate: %w", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		return nil, fmt.Errorf("parse issuer certificate: %w", err)
	}
	if !issuer.IsCA || !issuer.BasicConstraintsValid {
		return nil, errors.New("CRL issuer certificate is not a CA certificate")
	}
	if len(issuer.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("CRL issuer certificate has unhandled critical extensions")
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	if len(crl.RevokedCertificateEntries) > limits.MaxEntries {
		return nil, fmt.Errorf("CRL contains %d entries; limit is %d", len(crl.RevokedCertificateEntries), limits.MaxEntries)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return nil, errors.New("CRL issuer name does not match supplied issuer certificate")
	}
	if len(crl.AuthorityKeyId) != 0 && len(issuer.SubjectKeyId) != 0 &&
		!bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return nil, errors.New("CRL authority key ID does not match issuer subject key ID")
	}
	if err := checkExtensions(crl.Extensions, false); err != nil {
		return nil, err
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL signature: %w", err)
	}
	now = now.UTC()
	if crl.ThisUpdate.IsZero() || crl.NextUpdate.IsZero() || !crl.NextUpdate.After(crl.ThisUpdate) {
		return nil, errors.New("CRL lacks a usable thisUpdate/nextUpdate interval")
	}
	if now.Before(crl.ThisUpdate) {
		return nil, errors.New("CRL thisUpdate is in the future")
	}
	if !now.Before(crl.NextUpdate) {
		return nil, errors.New("CRL is stale (nextUpdate has passed)")
	}
	l := &List{
		Fingerprint:           digest(crl.Raw),
		IssuerFingerprint:     digest(issuer.Raw),
		IssuerSPKIFingerprint: digest(issuer.RawSubjectPublicKeyInfo),
		Issuer:                crl.Issuer.String(),
		IssuerNameHash:        digest(crl.RawIssuer),
		AuthorityKeyID:        hex.EncodeToString(crl.AuthorityKeyId),
		IssuerSubjectKeyID:    hex.EncodeToString(issuer.SubjectKeyId),
		ThisUpdate:            crl.ThisUpdate.UTC(),
		NextUpdate:            crl.NextUpdate.UTC(),
		Entries:               make([]Entry, 0, len(crl.RevokedCertificateEntries)),
		issuerCert:            issuer,
		bySerial:              make(map[string]int, len(crl.RevokedCertificateEntries)),
	}
	if crl.Number != nil {
		l.Number = crl.Number.String()
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if err := checkExtensions(entry.Extensions, true); err != nil {
			return nil, err
		}
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 {
			return nil, errors.New("CRL contains an invalid revoked serial number")
		}
		if entry.RevocationTime.IsZero() || entry.RevocationTime.After(now) {
			return nil, errors.New("CRL contains an invalid or future revocation time")
		}
		if entry.ReasonCode == 8 { // removeFromCRL applies to delta CRLs, not a revocation.
			return nil, errors.New("CRL contains unsupported removeFromCRL entry")
		}
		serial := entry.SerialNumber.Text(16)
		if _, exists := l.bySerial[serial]; exists {
			return nil, fmt.Errorf("CRL contains duplicate revoked serial %s", serial)
		}
		l.bySerial[serial] = len(l.Entries)
		l.Entries = append(l.Entries, Entry{
			Serial: serial, RevokedAt: entry.RevocationTime.UTC(),
			ReasonCode: entry.ReasonCode, Reason: reasonName(entry.ReasonCode),
		})
	}
	b, err := json.Marshal(l)
	if err != nil {
		return nil, fmt.Errorf("encode verified CRL: %w", err)
	}
	l.seal = sha256.Sum256(b)
	l.verified = true
	return l, nil
}

// Match finds a revocation entry only when cert's issuer is cryptographically
// verified by the same issuer certificate that signed this CRL. Absence of a
// match says nothing about revocation status in other CRLs or OCSP.
func (l *List) Match(cert *x509.Certificate) (Entry, bool, error) {
	if !l.Verified() || l.issuerCert == nil {
		return Entry{}, false, errors.New("unverified CRL")
	}
	if cert == nil || cert.SerialNumber == nil {
		return Entry{}, false, errors.New("missing certificate")
	}
	if !bytes.Equal(cert.RawIssuer, l.issuerCert.RawSubject) {
		return Entry{}, false, nil
	}
	if len(cert.AuthorityKeyId) != 0 && len(l.issuerCert.SubjectKeyId) != 0 &&
		!bytes.Equal(cert.AuthorityKeyId, l.issuerCert.SubjectKeyId) {
		return Entry{}, false, nil
	}
	if err := cert.CheckSignatureFrom(l.issuerCert); err != nil {
		return Entry{}, false, nil
	}
	i, ok := l.bySerial[cert.SerialNumber.Text(16)]
	if !ok {
		return Entry{}, false, nil
	}
	return l.Entries[i], true, nil
}

func effectiveLimits(l Limits) Limits {
	if l.MaxCRLBytes <= 0 {
		l.MaxCRLBytes = defaultMaxCRLBytes
	}
	if l.MaxIssuerBytes <= 0 {
		l.MaxIssuerBytes = defaultMaxIssuerBytes
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = defaultMaxEntries
	}
	return l
}

func decodeOne(input []byte, pemType string, maxBytes int) ([]byte, error) {
	// The encoded form is bounded too, so PEM whitespace cannot consume
	// unbounded memory before its decoded DER length is checked.
	maxInput := maxBytes + maxBytes/2 + 4096
	if len(input) == 0 || len(input) > maxInput {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", maxInput)
	}
	if bytes.HasPrefix(bytes.TrimSpace(input), []byte("-----BEGIN")) {
		block, rest := pem.Decode(input)
		if block == nil || block.Type != pemType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("expected exactly one PEM %s block", pemType)
		}
		input = block.Bytes
	}
	if len(input) > maxBytes {
		return nil, fmt.Errorf("DER data exceeds %d-byte limit", maxBytes)
	}
	return input, nil
}

func checkExtensions(extensions []pkix.Extension, entry bool) error {
	for _, ext := range extensions {
		switch {
		case !entry && ext.Id.Equal(oidDeltaCRLIndicator):
			return errors.New("delta CRLs are unsupported")
		case !entry && ext.Id.Equal(oidIssuingDistributionPoint):
			return errors.New("scoped or indirect CRLs are unsupported")
		case !entry && ext.Id.Equal(oidFreshestCRL):
			return errors.New("CRLs requiring delta updates are unsupported")
		case entry && ext.Id.Equal(oidCertificateIssuer):
			return errors.New("indirect CRL certificateIssuer entry is unsupported")
		case entry && ext.Id.Equal(oidReasonCode):
			// ReasonCode is parsed into the entry by crypto/x509.
		case !entry && (ext.Id.Equal(oidCRLNumber) || ext.Id.Equal(oidAuthorityKeyIdentifier)):
			// These extensions are parsed by crypto/x509.
		case ext.Critical:
			return fmt.Errorf("unsupported critical CRL extension %s", ext.Id.String())
		}
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func reasonName(code int) string {
	switch code {
	case 0:
		return "unspecified"
	case 1:
		return "keyCompromise"
	case 2:
		return "cACompromise"
	case 3:
		return "affiliationChanged"
	case 4:
		return "superseded"
	case 5:
		return "cessationOfOperation"
	case 6:
		return "certificateHold"
	case 9:
		return "privilegeWithdrawn"
	case 10:
		return "aACompromise"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

// EqualSerial can help compare an inventory serial stored in hexadecimal with
// a CRL entry without relying on issuer display names. Use it only after the
// issuer identity and CRL signature have been established.
func EqualSerial(hexSerial string, serial *big.Int) bool {
	if serial == nil || serial.Sign() < 0 {
		return false
	}
	parsed, ok := new(big.Int).SetString(hexSerial, 16)
	return ok && parsed.Cmp(serial) == 0
}
