package store

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

func bundledIncident(t *testing.T) IncidentManifest {
	t.Helper()
	data, err := incidentFiles.ReadFile("incidents/emudhra-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest IncidentManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestBundledEMudhraIncidentIdentities(t *testing.T) {
	manifest := bundledIncident(t)
	if len(manifest.Intermediates) != 8 {
		t.Fatalf("intermediate keys = %d, want 8", len(manifest.Intermediates))
	}
	// Official Go crypto/x509 blocklist independently publishes these eight
	// SPKI hashes; the certificate variants are documented by Mozilla and Apple.
	wantKeys := map[string]bool{
		"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": true,
		"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": true,
		"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": true,
		"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": true,
		"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": true,
		"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": true,
		"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": true,
		"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": true,
	}
	certs := map[string]bool{}
	var tls, codeSigning int
	for _, ca := range manifest.Intermediates {
		key := normalizeFingerprint(ca.SPKISHA256)
		if !wantKeys[key] {
			t.Errorf("unexpected key %s for %s", key, ca.Name)
		}
		delete(wantKeys, key)
		if len(ca.Certificates) != 2 {
			t.Errorf("%s has %d variants", ca.Name, len(ca.Certificates))
		}
		for _, cert := range ca.Certificates {
			fp := normalizeFingerprint(cert.SHA256)
			if certs[fp] || len(fp) != 64 {
				t.Errorf("duplicate or malformed certificate %s", fp)
			}
			certs[fp] = true
		}
		switch ca.Usage {
		case "tls":
			tls++
		case "code-signing":
			codeSigning++
		default:
			t.Errorf("unexpected usage %q", ca.Usage)
		}
	}
	if len(wantKeys) != 0 || tls != 6 || codeSigning != 2 || len(certs) != 16 {
		t.Fatalf("incomplete incident: keys missing %d, TLS %d, code-signing %d, certificates %d", len(wantKeys), tls, codeSigning, len(certs))
	}
}

func TestBuiltinIncidentManifestReturnsAnIndependentCopy(t *testing.T) {
	first, err := BuiltinIncidentManifest()
	if err != nil {
		t.Fatal(err)
	}
	first.Sources[0] = "changed"
	first.Intermediates[0].SPKISHA256 = strings.Repeat("0", 64)
	first.Intermediates[0].Certificates[0].SHA256 = strings.Repeat("0", 64)
	second, err := BuiltinIncidentManifest()
	if err != nil {
		t.Fatal(err)
	}
	if second.Sources[0] == "changed" || second.Intermediates[0].SPKISHA256 == first.Intermediates[0].SPKISHA256 || second.Intermediates[0].Certificates[0].SHA256 == first.Intermediates[0].Certificates[0].SHA256 {
		t.Fatal("manifest caller changed the embedded defaults")
	}
}

func TestSeedBuiltinIncidentWatchesReevaluatesHistoryAndKeepsOperatorChoices(t *testing.T) {
	s, path := mustOpen(t)
	manifest := bundledIncident(t)
	first, second := manifest.Intermediates[0], manifest.Intermediates[1]
	when := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	destinationID := mustDestination(t, s, model.DestinationEvent{Time: when, Collector: "fixture", Vantage: "local", Hostname: "example.test", Port: 443})
	probeID := mustProbe(t, s, model.ProbeObservation{
		DestinationID: destinationID, Time: when, Port: 443,
		Presented:      []model.Certificate{{Fingerprint: first.Certificates[0].SHA256, SPKIFingerprint: first.SPKISHA256, IsCA: true, Source: "presented"}},
		CandidatePaths: []model.CandidatePath{{Validation: "verified", Certificates: []model.Certificate{{Fingerprint: second.Certificates[1].SHA256, SPKIFingerprint: second.SPKISHA256, IsCA: true, Source: "trust_store"}}}},
	})
	// A rule installed by the operator for the same key must win over defaults.
	manualID := mustWatch(t, s, model.WatchEntry{Name: "My incident label", MatchType: "spki_sha256", Value: first.SPKISHA256, Status: "monitored", Severity: "low", Source: "my policy"})
	result, err := s.SeedBuiltinIncidentWatches(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 7 || result.Skipped != 1 {
		t.Fatalf("initial seed = %+v", result)
	}
	watches, err := s.ListWatches()
	if err != nil {
		t.Fatal(err)
	}
	if len(watches) != 8 || watches[0].ID != manualID || watches[0].Name != "My incident label" || watches[0].Status != "monitored" {
		t.Fatalf("operator watch was not preserved: %+v", watches)
	}
	if watches[1].Status != "compromised" || watches[1].MatchType != "spki_sha256" || !strings.Contains(watches[1].Reason, "not a locally signature-verified CRL") {
		t.Fatalf("built-in provenance is unclear: %+v", watches[1])
	}
	findings, err := s.ListFindings(FindingFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("historical findings = %+v", findings)
	}
	evidence := map[string]bool{}
	for _, finding := range findings {
		if finding.ProbeID != probeID {
			t.Fatalf("wrong historical probe: %+v", finding)
		}
		evidence[finding.Evidence] = true
	}
	if !evidence["direct"] || !evidence["candidate"] {
		t.Fatalf("missing evidence distinction: %+v", findings)
	}
	result, err = s.SeedBuiltinIncidentWatches(context.Background())
	if err != nil || result.Imported != 0 || result.Skipped != 8 {
		t.Fatalf("repeat seed = %+v, %v", result, err)
	}
	deletedID := watches[1].ID
	if err := s.DeleteWatch(deletedID); err != nil {
		t.Fatal(err)
	}
	// Editing another built-in row is equally durable across restarts.
	changed := watches[2]
	changed.Name = "Local label"
	changed.Status = "monitored"
	if _, err := s.AddWatch(changed); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	result, err = s.SeedBuiltinIncidentWatches(context.Background())
	if err != nil || result.Imported != 0 || result.Skipped != 8 {
		t.Fatalf("seed after deletion/edit = %+v, %v", result, err)
	}
	watches, err = s.ListWatches()
	if err != nil || len(watches) != 7 {
		t.Fatalf("deleted row returned: %+v, %v", watches, err)
	}
	for _, watch := range watches {
		if watch.ID == deletedID {
			t.Fatal("deleted built-in watch was restored")
		}
		if watch.ID == changed.ID && (watch.Name != "Local label" || watch.Status != "monitored") {
			t.Fatalf("edited built-in watch was overwritten: %+v", watch)
		}
	}
	// A later bundled update can append a newly identified key without
	// resetting the deleted and edited rows in the original release.
	manifest.Intermediates = append(manifest.Intermediates, IncidentIntermediate{
		Name: "Future verified key", Usage: "tls", SPKISHA256: strings.Repeat("a", 64),
		Certificates: []IncidentCertificate{
			{IssuedBy: "Issuer A", SHA256: strings.Repeat("b", 64), SerialHex: "1"},
			{IssuedBy: "Issuer B", SHA256: strings.Repeat("c", 64), SerialHex: "2"},
		},
	})
	result, err = s.seedIncidentWatches(context.Background(), manifest)
	if err != nil || result.Imported != 1 || result.Skipped != 8 {
		t.Fatalf("updated bundle = %+v, %v", result, err)
	}
	watches, err = s.ListWatches()
	if err != nil || len(watches) != 8 {
		t.Fatalf("new key was not added: %+v, %v", watches, err)
	}
}

func TestSeedBuiltinIncidentWatchesIsAtomic(t *testing.T) {
	s, _ := mustOpen(t)
	manifest := bundledIncident(t)
	manifest.Intermediates[7].SPKISHA256 = "bad"
	if _, err := s.seedIncidentWatches(context.Background(), manifest); err == nil {
		t.Fatal("accepted malformed bundled identity")
	}
	watches, err := s.ListWatches()
	if err != nil || len(watches) != 0 {
		t.Fatalf("malformed bundle partially seeded: %+v, %v", watches, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SeedBuiltinIncidentWatches(ctx); err == nil {
		t.Fatal("seed ignored cancellation")
	}
	watches, err = s.ListWatches()
	if err != nil || len(watches) != 0 {
		t.Fatalf("canceled seed changed watches: %+v, %v", watches, err)
	}
	// The bundled JSON is a committed resource; this also catches accidental
	// loss of the file before the executable is built.
	if _, err := os.Stat("incidents/emudhra-2026-10.json"); err != nil {
		t.Fatal(err)
	}
}
