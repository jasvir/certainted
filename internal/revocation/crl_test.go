package revocation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

var fixtureNow = time.Date(2026, time.October, 25, 12, 0, 0, 0, time.UTC)

type caFixture struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	der  []byte
}

func newCA(t *testing.T, name string) caFixture {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             fixtureNow.Add(-24 * time.Hour),
		NotAfter:              fixtureNow.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return caFixture{cert: cert, key: key, der: der}
}

func newLeaf(t *testing.T, ca caFixture, serial int64) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "service.test"},
		DNSNames:     []string{"service.test"},
		NotBefore:    fixtureNow.Add(-24 * time.Hour),
		NotAfter:     fixtureNow.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newCRL(t *testing.T, ca caFixture, revocationTime time.Time, entries []x509.RevocationListEntry, extra ...pkix.Extension) []byte {
	t.Helper()
	template := &x509.RevocationList{
		Number:                    big.NewInt(7),
		ThisUpdate:                revocationTime.Add(-time.Hour),
		NextUpdate:                revocationTime.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
		ExtraExtensions:           extra,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func revokedEntry(serial int64, reason int) x509.RevocationListEntry {
	return x509.RevocationListEntry{
		SerialNumber:   big.NewInt(serial),
		RevocationTime: fixtureNow.Add(-2 * time.Hour),
		ReasonCode:     reason,
	}
}

func TestParseAndMatchVerifiedFullCRL(t *testing.T) {
	ca := newCA(t, "test CA")
	leaf := newLeaf(t, ca, 42)
	crlDER := newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{revokedEntry(42, 1), revokedEntry(43, 0)})
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	issuerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.der})
	list, err := ParseAndVerify(crlPEM, issuerPEM, fixtureNow, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !list.Verified() || list.Number != "7" || list.IssuerNameHash != digest(ca.cert.RawSubject) {
		t.Fatalf("missing verified provenance: %+v", list)
	}
	if list.IssuerSPKIFingerprint != digest(ca.cert.RawSubjectPublicKeyInfo) || list.AuthorityKeyID != hex.EncodeToString(ca.cert.SubjectKeyId) {
		t.Fatalf("issuer key provenance missing: %+v", list)
	}
	if list.Fingerprint != digest(crlDER) || list.IssuerFingerprint != digest(ca.der) {
		t.Fatal("incorrect CRL or issuer certificate fingerprint")
	}
	entry, found, err := list.Match(leaf)
	if err != nil || !found || entry.Serial != "2a" || entry.Reason != "keyCompromise" {
		t.Fatalf("match = %+v, %v, %v", entry, found, err)
	}
	if list.Entries[1].Reason != "unspecified" {
		t.Fatalf("absent reason should be unspecified, got %q", list.Entries[1].Reason)
	}
	other := newLeaf(t, ca, 44)
	if _, found, err := list.Match(other); err != nil || found {
		t.Fatalf("unlisted certificate matched: %v, %v", found, err)
	}
	// The same serial under another CA must never match this CRL.
	otherCA := newCA(t, "another CA")
	otherIssuerLeaf := newLeaf(t, otherCA, 42)
	if _, found, err := list.Match(otherIssuerLeaf); err != nil || found {
		t.Fatalf("other issuer certificate matched: %v, %v", found, err)
	}
	// Even identical display names, raw names and key IDs are not enough:
	// the leaf signature must verify against the CRL signer.
	sameNameOtherKey := newCA(t, "test CA")
	sameNameLeaf := newLeaf(t, sameNameOtherKey, 42)
	if _, found, err := list.Match(sameNameLeaf); err != nil || found {
		t.Fatalf("same-name, different-key certificate matched: %v, %v", found, err)
	}
	if (&List{Entries: list.Entries}).Verified() {
		t.Fatal("caller-constructed list marked verified")
	}
	list.Entries[0].Serial = "ffff"
	if list.Verified() {
		t.Fatal("mutated parsed list retained verified marker")
	}
}

func TestRejectWrongIssuerAndSignature(t *testing.T) {
	ca := newCA(t, "CA one")
	crl := newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{revokedEntry(42, 0)})
	other := newCA(t, "CA two")
	if _, err := ParseAndVerify(crl, other.der, fixtureNow, Limits{}); err == nil || !strings.Contains(err.Error(), "issuer name") {
		t.Fatalf("wrong issuer name: %v", err)
	}
	// A distinct key with the same subject must not validate the signature.
	other = newCA(t, "CA one")
	if _, err := ParseAndVerify(crl, other.der, fixtureNow, Limits{}); err == nil {
		t.Fatal("accepted CRL signed with another CA key")
	}
	changed := bytes.Clone(crl)
	changed[len(changed)-1] ^= 1
	if _, err := ParseAndVerify(changed, ca.der, fixtureNow, Limits{}); err == nil {
		t.Fatal("accepted CRL with tampered signature")
	}
}

func TestRejectStaleFutureAndOversizedCRL(t *testing.T) {
	ca := newCA(t, "test CA")
	crl := newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{revokedEntry(42, 0)})
	for _, tc := range []struct {
		name string
		now  time.Time
		want string
	}{
		{"stale", fixtureNow.Add(25 * time.Hour), "stale"},
		{"future", fixtureNow.Add(-2 * time.Hour), "future"},
		{"no time", time.Time{}, "verification time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndVerify(crl, ca.der, tc.now, Limits{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{MaxCRLBytes: len(crl) - 1}); err == nil {
		t.Fatal("accepted over-limit CRL")
	}
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{MaxIssuerBytes: len(ca.der) - 1}); err == nil {
		t.Fatal("accepted over-limit issuer certificate")
	}
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{MaxEntries: 1}); err != nil {
		t.Fatalf("one entry should fit limit: %v", err)
	}
	crl = newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{revokedEntry(42, 0), revokedEntry(43, 0)})
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{MaxEntries: 1}); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("entry limit error = %v", err)
	}
}

func TestRejectUnsupportedScopeAndCriticalExtensions(t *testing.T) {
	ca := newCA(t, "test CA")
	seq := []byte{0x30, 0}
	delta, err := asn1.Marshal(big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		ext  pkix.Extension
	}{
		{"scoped", pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: seq}},
		{"delta", pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: delta}},
		{"freshest", pkix.Extension{Id: oidFreshestCRL, Value: seq}},
		{"unknown critical", pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: seq}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crl := newCRL(t, ca, fixtureNow, nil, tc.ext)
			if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{}); err == nil {
				t.Fatal("accepted unsupported CRL extension")
			}
		})
	}
	entry := revokedEntry(42, 0)
	entry.ExtraExtensions = []pkix.Extension{{Id: oidCertificateIssuer, Value: seq}}
	crl := newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{entry})
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{}); err == nil || !strings.Contains(err.Error(), "certificateIssuer") {
		t.Fatalf("indirect entry error = %v", err)
	}
	crl = newCRL(t, ca, fixtureNow, []x509.RevocationListEntry{revokedEntry(42, 8)})
	if _, err := ParseAndVerify(crl, ca.der, fixtureNow, Limits{}); err == nil || !strings.Contains(err.Error(), "removeFromCRL") {
		t.Fatalf("removeFromCRL error = %v", err)
	}
}
