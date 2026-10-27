package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/revocation"
)

func testCert(t *testing.T, template, parent *x509.Certificate, signer ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testCRL(t *testing.T, issuer *x509.Certificate, key ed25519.PrivateKey, serial int64, revokedAt, now time.Time) *revocation.List {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(serial), RevocationTime: revokedAt, ReasonCode: 1}},
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	list, err := revocation.ParseAndVerify(der, issuer.Raw, now, revocation.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func hashHex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func observedCert(cert *x509.Certificate, source string) model.Certificate {
	return model.Certificate{
		Fingerprint: hashHex(cert.Raw), SPKIFingerprint: hashHex(cert.RawSubjectPublicKeyInfo),
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), Serial: cert.SerialNumber.Text(16),
		SubjectNameSHA256: hashHex(cert.RawSubject), IssuerNameSHA256: hashHex(cert.RawIssuer),
		SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId), AuthorityKeyIdentifier: hex.EncodeToString(cert.AuthorityKeyId),
		IsCA: cert.IsCA, Source: source,
	}
}

func TestCRLImportReevaluatesHistoryAndKeepsEvidenceLabels(t *testing.T) {
	s, path := mustOpen(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fixture Root"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	root, rootKey := testCert(t, rootTemplate, nil, nil)
	intermediateTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Fixture Intermediate"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{5, 6, 7, 8}}
	intermediate, intermediateKey := testCert(t, intermediateTemplate, root, rootKey)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "service.test"}, DNSNames: []string{"service.test"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leaf, _ := testCert(t, leafTemplate, intermediate, intermediateKey)
	rootCRL := testCRL(t, root, rootKey, 2, now.Add(-2*time.Hour), now)
	intermediateCRL := testCRL(t, intermediate, intermediateKey, 3, now.Add(-time.Hour), now)
	if _, err := s.ImportCRL(&revocation.List{}, "forged"); err == nil {
		t.Fatal("unverified list was accepted")
	}

	leafModel := observedCert(leaf, "presented")
	intermediateModel := observedCert(intermediate, "trust_store")
	rootModel := observedCert(root, "trust_store")
	// The probe's verified path may contain an intermediate supplied by the
	// configured trust store even though the server did not present it.
	pathEvidence := []model.CandidatePath{{Certificates: []model.Certificate{leafModel, intermediateModel, rootModel}, Validation: "verified"}}
	destinationID := mustDestination(t, s, model.DestinationEvent{Time: now.Add(-3 * time.Hour), Collector: "jsonl", Hostname: "service.test", Port: 443})
	earlierID := mustProbe(t, s, model.ProbeObservation{DestinationID: destinationID, Time: now.Add(-3 * time.Hour), Port: 443, Presented: []model.Certificate{leafModel}, CandidatePaths: pathEvidence})
	currentID := mustProbe(t, s, model.ProbeObservation{DestinationID: destinationID, Time: now, Port: 443, Presented: []model.Certificate{leafModel}, CandidatePaths: pathEvidence})
	rootID, err := s.ImportCRL(rootCRL, "fixture/root.crl")
	if err != nil {
		t.Fatal(err)
	}
	intermediateID, err := s.ImportCRL(intermediateCRL, "fixture/intermediate.crl")
	if err != nil {
		t.Fatal(err)
	}
	if duplicateID, err := s.ImportCRL(rootCRL, "duplicate"); err != nil || duplicateID != rootID {
		t.Fatalf("identical CRL import not idempotent: id=%d err=%v", duplicateID, err)
	}
	findings, err := s.ListRevocationFindings(RevocationFindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected one direct and one candidate historical match: %+v", findings)
	}
	byCRL := map[int64]RevocationFinding{}
	for _, f := range findings {
		if f.ProbeID != currentID || f.ProbeID == earlierID || f.IssuerMatch != "verified_path" || f.CRLThisUpdateAfterProbe || f.CRLStaleAtProbe {
			t.Fatalf("incorrect historical evidence: %+v", f)
		}
		byCRL[f.CRLID] = f
	}
	if byCRL[rootID].Evidence != "candidate" || byCRL[intermediateID].Evidence != "direct" || byCRL[intermediateID].Reason != "keyCompromise" {
		t.Fatalf("presentation or reason provenance lost: %+v", byCRL)
	}
	crls, err := s.ListCRLs()
	if err != nil || len(crls) != 2 || crls[0].EntryCount != 1 || crls[1].EntryCount != 1 {
		t.Fatalf("imported CRL metadata: %+v, %v", crls, err)
	}
	st, err := s.Stats()
	if err != nil || st.RevocationFindings != 2 || st.RevokedDestinations != 1 || st.VerifiedDirectRevocations != 1 {
		t.Fatalf("revocation stats: %+v, %v", st, err)
	}
	// A later independent probe is evaluated on insertion. An expired CRL is
	// still historical evidence, but its freshness limitation is explicit.
	laterID := mustProbe(t, s, model.ProbeObservation{DestinationID: destinationID, Time: now.Add(25 * time.Hour), Port: 443, Presented: []model.Certificate{leafModel}, CandidatePaths: pathEvidence})
	later, err := s.ListRevocationFindings(RevocationFindingFilter{From: ptrTime(now.Add(25 * time.Hour))})
	if err != nil || len(later) != 2 || later[0].ProbeID != laterID || !later[0].CRLStaleAtProbe {
		t.Fatalf("future probe or stale label wrong: %+v, %v", later, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	retained, err := s.ListRevocationFindings(RevocationFindingFilter{Evidence: "direct"})
	if err != nil || len(retained) != 2 {
		t.Fatalf("revocation findings not durable: %+v, %v", retained, err)
	}
	if err := s.DeleteBefore(now.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	remaining, err := s.ListRevocationFindings(RevocationFindingFilter{})
	if err != nil || len(remaining) != 2 || remaining[0].ProbeID != laterID {
		t.Fatalf("retention did not cascade to revocation findings: %+v, %v", remaining, err)
	}
	newerCRL := testCRL(t, intermediate, intermediateKey, 3, now.Add(-time.Hour), now.Add(time.Minute))
	if _, err := s.ImportCRL(newerCRL, "fixture/newer-intermediate.crl"); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats()
	if err != nil || st.RevocationFindings != 3 || st.VerifiedDirectRevocations != 1 {
		t.Fatalf("repeated CRLs inflated verified direct metric: %+v, %v", st, err)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestCRLMatchingRejectsNameOnlyAndDifferentSigner(t *testing.T) {
	s, _ := mustOpen(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Same Display Name"}, NotBefore: now.Add(-24 * time.Hour),
		NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4}}
	root, key := testCert(t, rootTemplate, nil, nil)
	list := testCRL(t, root, key, 42, now.Add(-time.Hour), now)
	crlID, err := s.ImportCRL(list, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	base := model.Certificate{Fingerprint: strings.Repeat("a", 64), Serial: "2a", Issuer: root.Subject.String(), IssuerNameSHA256: hashHex(root.RawSubject), AuthorityKeyIdentifier: hex.EncodeToString(root.SubjectKeyId), Source: "presented"}
	destID := mustDestination(t, s, model.DestinationEvent{Hostname: "test.example", Port: 443})
	otherSigner := base
	otherSigner.VerifiedIssuerSPKIFingerprint = strings.Repeat("b", 64)
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: now, Port: 443, Presented: []model.Certificate{otherSigner}})
	nameOnly := base
	nameOnly.Fingerprint = strings.Repeat("c", 64)
	nameOnly.IssuerNameSHA256 = strings.Repeat("d", 64)
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: now, Port: 443, Presented: []model.Certificate{nameOnly}})
	findings, err := s.ListRevocationFindings(RevocationFindingFilter{})
	if err != nil || len(findings) != 0 {
		t.Fatalf("different signer or name-only match accepted: %+v, %v", findings, err)
	}
	// Matching key identifiers without signature evidence remain labeled as
	// candidates, even though the certificate itself was directly presented.
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: now, Port: 443, Presented: []model.Certificate{base}})
	findings, err = s.ListRevocationFindings(RevocationFindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].IssuerMatch != "key_identifier_candidate" || findings[0].Evidence != "direct" {
		t.Fatalf("unverified issuer relationship was overstated: %+v, %v", findings, err)
	}
	// A signature relationship established from two directly presented
	// certificates remains verified even when no complete trust path exists.
	verified := base
	verified.Fingerprint = strings.Repeat("e", 64)
	verified.VerifiedIssuerSPKIFingerprint = list.IssuerSPKIFingerprint
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: now, Port: 443, Presented: []model.Certificate{verified}, ValidationError: "unknown authority"})
	findings, err = s.ListRevocationFindings(RevocationFindingFilter{})
	if err != nil || len(findings) != 2 || findings[0].IssuerMatch != "verified_path" || findings[0].Evidence != "direct" {
		t.Fatalf("verified issuer relationship lost for incomplete trust path: %+v, %v", findings, err)
	}
	stats, err := s.Stats()
	if err != nil || stats.RevocationFindings != 2 || stats.VerifiedDirectRevocations != 1 {
		t.Fatalf("verified direct metric includes candidate identities: %+v, %v", stats, err)
	}
	retrospectiveCRL := testCRL(t, root, key, 42, now.Add(-time.Hour), now.Add(2*time.Hour))
	retrospectiveID, err := s.ImportCRL(retrospectiveCRL, "fixture/later.crl")
	if err != nil {
		t.Fatal(err)
	}
	retrospective, err := s.ListRevocationFindings(RevocationFindingFilter{CRLID: retrospectiveID})
	if err != nil || len(retrospective) != 2 || !retrospective[0].CRLThisUpdateAfterProbe || !retrospective[1].CRLThisUpdateAfterProbe {
		t.Fatalf("later CRL update was not labeled retrospective: %+v, %v", retrospective, err)
	}
	// Distinct collector events for the same endpoint share a stable key so
	// browser notifications can deduplicate their recurring probe findings.
	repeatedDestination := mustDestination(t, s, model.DestinationEvent{Hostname: "TEST.EXAMPLE", Port: 443})
	mustProbe(t, s, model.ProbeObservation{DestinationID: repeatedDestination, Time: now, Port: 443, Presented: []model.Certificate{verified}})
	latest, err := s.ListRevocationFindings(RevocationFindingFilter{CRLID: crlID})
	if err != nil || len(latest) != 3 {
		t.Fatalf("repeated endpoint findings: %+v, %v", latest, err)
	}
	var verifiedKeys []string
	for _, finding := range latest {
		if finding.IssuerMatch == "verified_path" {
			verifiedKeys = append(verifiedKeys, finding.DestinationKey)
		}
	}
	if len(verifiedKeys) != 2 || verifiedKeys[0] != verifiedKeys[1] || verifiedKeys[0] != `["test.example","",443,""]` {
		t.Fatalf("same endpoint produced different destination keys: %v", verifiedKeys)
	}
}
