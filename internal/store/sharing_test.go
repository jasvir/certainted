package store

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

func TestSharingDefaultsAndEligibleEvidence(t *testing.T) {
	s, _ := mustOpen(t)
	settings, err := s.SharingSettings()
	if err != nil || settings.Mode != "manual" || settings.EnabledAt != nil {
		t.Fatalf("unexpected default sharing settings: %+v, %v", settings, err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	root, key := testCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "Fixture Root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{1, 2, 3, 4},
	}, nil, nil)
	intermediate, _ := testCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(22), Subject: pkix.Name{CommonName: "Fixture Intermediate"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{5, 6, 7, 8},
	}, root, key)
	cert := observedCert(intermediate, "presented")
	cert.VerifiedIssuerSPKIFingerprint = hashHex(root.RawSubjectPublicKeyInfo)
	destID := mustDestination(t, s, model.DestinationEvent{Hostname: "public.example.org", IP: "8.8.8.8", Port: 443})
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: now, Hostname: "public.example.org", TargetIP: "8.8.8.8", Port: 443,
		Presented: []model.Certificate{cert}})
	if _, err := s.AddWatch(model.WatchEntry{Name: "Fixture CA", MatchType: "cert_sha256", Value: cert.Fingerprint, Status: "distrusted", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddWatch(model.WatchEntry{Name: "Ignored monitor", MatchType: "spki_sha256", Value: cert.SPKIFingerprint, Status: "monitored"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddWatch(model.WatchEntry{Name: "Ignored name", MatchType: "name", Value: "Fixture", Status: "compromised"}); err != nil {
		t.Fatal(err)
	}
	list := testCRL(t, root, key, 22, now.Add(-time.Hour), now)
	if _, err := s.ImportCRL(list, "private/path/issuer.crl?secret=top-secret"); err != nil {
		t.Fatal(err)
	}
	sources, err := s.ListShareSources(nil, 100)
	if err != nil || len(sources) != 2 {
		t.Fatalf("share sources = %+v, %v", sources, err)
	}
	kinds := map[string]bool{}
	for _, source := range sources {
		kinds[source.Kind] = true
		if source.Hostname != "public.example.org" || source.TargetIP != "8.8.8.8" || source.CertificateSHA256 != cert.Fingerprint {
			t.Fatalf("wrong source evidence: %+v", source)
		}
		got, err := s.GetShareSource(source.ID)
		if err != nil || got.ID != source.ID {
			t.Fatalf("share source lookup = %+v, %v", got, err)
		}
	}
	if !kinds["crl"] || !kinds["watch"] {
		t.Fatalf("missing direct revocation or exact watch candidate: %+v", kinds)
	}
	if _, err := s.GetShareSource("watch:0 OR 1=1"); err == nil {
		t.Fatal("invalid source id was accepted")
	}
	settings, err = s.SetSharingMode("auto")
	if err != nil || settings.EnabledAt == nil {
		t.Fatalf("auto activation = %+v, %v", settings, err)
	}
	if current, err := s.SetSharingMode("auto"); err != nil || !current.EnabledAt.Equal(*settings.EnabledAt) {
		t.Fatalf("repeated auto activation moved boundary: %+v, %v", current, err)
	}
	if future, err := s.ListShareSources(settings.EnabledAt, 100); err != nil || len(future) != 0 {
		t.Fatalf("historical observations became auto shares: %+v, %v", future, err)
	}
}
