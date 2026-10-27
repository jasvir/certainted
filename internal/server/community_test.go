package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jasvir/certainted/internal/community"
	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/share"
)

func TestCommunityPreviewAndManualShareAreOptInAndRedacted(t *testing.T) {
	db := testStore(t)
	const certFP = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const keyFP = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct{ host, ip string }{{"www.example.org", "8.8.8.8"}, {"secret.internal", "10.0.0.8"}} {
		id, err := db.AddDestination(model.DestinationEvent{Time: now, Collector: "private collector", Vantage: "private vantage", Hostname: tc.host,
			IP: tc.ip, Port: 443, Workload: "private workload", AttributionReliable: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.AddProbe(model.ProbeObservation{DestinationID: id, Time: now, Vantage: "private vantage", Hostname: tc.host,
			TargetIP: tc.ip, Port: 443, Presented: []model.Certificate{{Fingerprint: certFP, SPKIFingerprint: keyFP,
				Subject: "private subject", Issuer: "private issuer", IsCA: true, Source: "presented"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.AddWatch(model.WatchEntry{Name: "Private watch name", MatchType: "cert_sha256", Value: certFP,
		Status: "distrusted", Severity: "high", Source: "private/source/url?token=secret"}); err != nil {
		t.Fatal(err)
	}
	var sent atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		if r.URL.Path != "/api/v1/reports" {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
		}
		var report community.Report
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode outbound report: %v", err)
			return
		}
		if report.Hostname != "www.example.org" || report.Kind != "watch" || report.Watch == nil || report.Watch.Status != "distrusted" {
			t.Errorf("wrong outbound report: %+v", report)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"id":%q,"status":"accepted","trust_status":"unverified"}`, community.ReportID(report))
	}))
	defer receiver.Close()
	client, err := share.NewClient(receiver.URL + "/api/v1/reports")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithSharing(db, fstest.MapFS{}, "", nil, client)
	preview := serveAPI(t, handler, "/api/community/preview", "same-origin")
	if preview.Code != http.StatusOK {
		t.Fatalf("preview returned %d: %s", preview.Code, preview.Body.String())
	}
	var state share.PreviewState
	if err := json.Unmarshal(preview.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if state.Mode != "manual" || len(state.Reports) != 1 || state.Reports[0].Shared {
		t.Fatalf("unexpected default preview: %+v", state)
	}
	if state.Reports[0].Report.Hostname != "www.example.org" || strings.Contains(preview.Body.String(), "secret.internal") ||
		strings.Contains(preview.Body.String(), "private workload") || strings.Contains(preview.Body.String(), "8.8.8.8") ||
		strings.Contains(preview.Body.String(), "private/source") || strings.Contains(preview.Body.String(), "private vantage") {
		t.Fatalf("preview leaked local metadata: %s", preview.Body.String())
	}
	post := func(path, body, origin, site string, intent bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		req.Header.Set("Sec-Fetch-Site", site)
		if intent {
			req.Header.Set("X-Certainted-Intent", "1")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	body := fmt.Sprintf(`{"id":%q,"report_id":%q}`, state.Reports[0].ID, state.Reports[0].ReportID)
	if got := post("/api/community/share", body, "http://attacker.invalid", "cross-site", true); got.Code != http.StatusForbidden {
		t.Fatalf("cross-origin share returned %d", got.Code)
	}
	if got := post("/api/community/share", body, "http://127.0.0.1", "same-origin", false); got.Code != http.StatusForbidden {
		t.Fatalf("share without intent returned %d", got.Code)
	}
	if got := sent.Load(); got != 0 {
		t.Fatalf("unauthorized share sent %d reports", got)
	}
	if got := post("/api/community/share", fmt.Sprintf(`{"id":%q,"report_id":%q}`, state.Reports[0].ID, strings.Repeat("0", 64)), "http://127.0.0.1", "same-origin", true); got.Code != http.StatusConflict {
		t.Fatalf("changed preview returned %d, want 409", got.Code)
	}
	if got := sent.Load(); got != 0 {
		t.Fatal("changed preview sent a report")
	}
	if got := post("/api/community/share", body, "http://127.0.0.1", "same-origin", true); got.Code != http.StatusOK {
		t.Fatalf("manual share returned %d: %s", got.Code, got.Body.String())
	}
	if got := post("/api/community/share", body, "http://127.0.0.1", "same-origin", true); got.Code != http.StatusOK {
		t.Fatalf("repeat share returned %d: %s", got.Code, got.Body.String())
	}
	if got := sent.Load(); got != 1 {
		t.Fatalf("repeat share sent %d reports", got)
	}
	if got := post("/api/community/mode", `{"mode":"auto"}`, "http://127.0.0.1", "same-origin", true); got.Code != http.StatusOK {
		t.Fatalf("auto mode returned %d: %s", got.Code, got.Body.String())
	}
}

func TestCommunityPreviewScansPastPrivateRecentMatches(t *testing.T) {
	db := testStore(t)
	const certFP = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := db.AddWatch(model.WatchEntry{Name: "Public fixture CA", MatchType: "cert_sha256", Value: certFP,
		Status: "under investigation", Severity: "medium"}); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	add := func(host, ip string, at time.Time) {
		t.Helper()
		id, err := db.AddDestination(model.DestinationEvent{Time: at, Hostname: host, IP: ip, Port: 443})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.AddProbe(model.ProbeObservation{DestinationID: id, Time: at, Hostname: host, TargetIP: ip, Port: 443,
			Presented: []model.Certificate{{Fingerprint: certFP, IsCA: true, Source: "presented"}}}); err != nil {
			t.Fatal(err)
		}
	}
	add("older-public.example.org", "8.8.8.8", base)
	for i := 0; i < 120; i++ {
		add("private.internal", "10.0.0.8", base.Add(time.Duration(i+1)*time.Second))
	}
	client, err := share.NewClient("")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewWithSharing(db, fstest.MapFS{}, "", nil, client)
	response := serveAPI(t, handler, "/api/community/preview", "same-origin")
	if response.Code != http.StatusOK {
		t.Fatalf("preview returned %d: %s", response.Code, response.Body.String())
	}
	var state share.PreviewState
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Reports) != 1 || state.Reports[0].Report.Hostname != "older-public.example.org" {
		t.Fatalf("public report was crowded out by private recent matches: %+v", state.Reports)
	}
}
