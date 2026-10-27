package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

func TestWatchImportIsAdditiveAtomicAndReevaluatesHistory(t *testing.T) {
	s, _ := mustOpen(t)
	when := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	certFP := strings.Repeat("a", 64)
	id := mustDestination(t, s, model.DestinationEvent{Time: when, Collector: "fixture", Vantage: "local", Hostname: "example.test", Port: 443})
	mustProbe(t, s, model.ProbeObservation{DestinationID: id, Time: when, Port: 443, Presented: []model.Certificate{{Fingerprint: certFP, Subject: "CN=Fixture Intermediate", IsCA: true}}})
	other := mustWatch(t, s, model.WatchEntry{MatchType: "cert_sha256", Value: strings.Repeat("b", 64), Name: "Other"})
	entry := model.WatchEntry{ID: other, MatchType: "cert_sha256", Value: certFP, Name: "Fixture Intermediate", Status: "under investigation", Severity: "high"}
	result, err := s.ImportWatches(context.Background(), []model.WatchEntry{entry, entry})
	if err != nil {
		t.Fatal(err)
	}
	if result.Imported != 1 || result.Skipped != 1 || len(result.IDs) != 1 || result.IDs[0] == other {
		t.Fatalf("wrong import result: %+v", result)
	}
	findings, err := s.ListFindings(FindingFilter{WatchID: result.IDs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence != "direct" {
		t.Fatalf("historical reevaluation failed: %+v", findings)
	}
	result, err = s.ImportWatches(context.Background(), []model.WatchEntry{entry})
	if err != nil || result.Imported != 0 || result.Skipped != 1 {
		t.Fatalf("repeat import = %+v, %v", result, err)
	}
	_, err = s.ImportWatches(context.Background(), []model.WatchEntry{
		{MatchType: "cert_sha256", Value: strings.Repeat("c", 64), Name: "Valid"},
		{MatchType: "cert_sha256", Value: "bad", Name: "Invalid"},
	})
	if err == nil {
		t.Fatal("accepted invalid batch")
	}
	watches, err := s.ListWatches()
	if err != nil {
		t.Fatal(err)
	}
	if len(watches) != 2 {
		t.Fatalf("invalid batch partially imported: %+v", watches)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ImportWatches(ctx, []model.WatchEntry{{MatchType: "cert_sha256", Value: strings.Repeat("d", 64)}}); err == nil {
		t.Fatal("canceled import succeeded")
	}
	watches, err = s.ListWatches()
	if err != nil || len(watches) != 2 {
		t.Fatalf("canceled import changed watches: %+v, %v", watches, err)
	}
}
