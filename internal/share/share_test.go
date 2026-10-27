package share

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/community"
	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/store"
)

func TestBuildReportPublishesOnlyAllowlistedFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	source := store.ShareSource{
		ID: "watch:42", Kind: "watch", Hostname: "WWW.EXAMPLE.ORG", Port: 443, TargetIP: "8.8.8.8",
		ObservedAt: now, CertificateSHA256: strings.Repeat("a", 64), Evidence: "direct",
		WatchMatchType: "cert_sha256", WatchMatchSHA256: strings.Repeat("a", 64), WatchStatus: "distrusted", WatchSeverity: "high",
	}
	report, err := BuildReport(source)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if report.Hostname != "www.example.org" || strings.Contains(string(data), "8.8.8.8") || strings.Contains(string(data), "watch:42") {
		t.Fatalf("public report leaked local information: %s", data)
	}
	source.TargetIP = "10.0.0.8"
	if _, err := BuildReport(source); err == nil {
		t.Fatal("private probe target became shareable")
	}
	source.TargetIP = "8.8.8.8"
	source.Hostname = "secret.internal"
	if _, err := BuildReport(source); err == nil {
		t.Fatal("internal hostname became shareable")
	}
}

func TestAutoShareStartsWithFutureFindingsAndStops(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const certFP = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const keyFP = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	destID, err := db.AddDestination(model.DestinationEvent{Time: time.Now().UTC(), Collector: "fixture", Hostname: "public.example.org", IP: "8.8.8.8", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddWatch(model.WatchEntry{Name: "Fixture CA", MatchType: "cert_sha256", Value: certFP, Status: "under investigation", Severity: "medium"}); err != nil {
		t.Fatal(err)
	}
	probe := func() {
		t.Helper()
		if _, err := db.AddProbe(model.ProbeObservation{DestinationID: destID, Time: time.Now().UTC(), Hostname: "public.example.org", TargetIP: "8.8.8.8", Port: 443,
			Presented: []model.Certificate{{Fingerprint: certFP, SPKIFingerprint: keyFP, IsCA: true, Source: "presented"}}}); err != nil {
			t.Fatal(err)
		}
	}
	probe() // Historic evidence exists before consent.
	var sent atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report community.Report
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode report: %v", err)
			return
		}
		sent.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"id":%q,"status":"accepted","trust_status":"unverified"}`, community.ReportID(report))
	}))
	defer receiver.Close()
	client, err := NewClient(receiver.URL + "/api/v1/reports")
	if err != nil {
		t.Fatal(err)
	}
	client.autoBatch(context.Background(), db)
	if sent.Load() != 0 {
		t.Fatal("manual default shared history")
	}
	if _, err := client.SetMode(db, "auto"); err != nil {
		t.Fatal(err)
	}
	client.autoBatch(context.Background(), db)
	if sent.Load() != 0 {
		t.Fatal("auto activation shared historical evidence")
	}
	probe()
	client.autoBatch(context.Background(), db)
	if sent.Load() != 1 {
		t.Fatalf("future evidence sent %d times, want 1", sent.Load())
	}
	client.autoBatch(context.Background(), db)
	if sent.Load() != 1 {
		t.Fatal("auto batch resent processed report")
	}
	if _, err := client.SetMode(db, "manual"); err != nil {
		t.Fatal(err)
	}
	probe()
	client.autoBatch(context.Background(), db)
	if sent.Load() != 1 {
		t.Fatal("manual mode continued automatic sharing")
	}
}
