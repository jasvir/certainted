package community

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func crlReport() Report {
	return Report{
		Version:           ReportVersion,
		Kind:              "crl",
		Hostname:          "www.example.com",
		Port:              443,
		ObservedDay:       "2025-01-02",
		CertificateSHA256: strings.Repeat("a", 64),
		Evidence:          "direct",
		CRL: &CRLEvidence{
			CertificateSerial: "01",
			CRLSHA256:         strings.Repeat("b", 64),
			IssuerCertSHA256:  strings.Repeat("c", 64),
			IssuerSPKISHA256:  strings.Repeat("d", 64),
			RevokedAt:         "2025-01-01T00:00:00Z",
			ThisUpdate:        "2025-01-01T00:00:00Z",
			NextUpdate:        "2025-02-01T00:00:00Z",
			IssuerMatch:       "verified_path",
		},
	}
}

func watchReport() Report {
	return Report{
		Version:           ReportVersion,
		Kind:              "watch",
		Hostname:          "www.example.com",
		Port:              443,
		ObservedDay:       "2025-01-02",
		CertificateSHA256: strings.Repeat("a", 64),
		Evidence:          "candidate",
		Watch: &WatchEvidence{
			MatchType:   "spki_sha256",
			MatchSHA256: strings.Repeat("e", 64),
			Status:      "under investigation",
			Severity:    "medium",
		},
	}
}

func TestValidateReportPrivacyBoundary(t *testing.T) {
	base := crlReport()
	if err := ValidateReport(base); err != nil {
		t.Fatalf("valid CRL claim rejected: %v", err)
	}
	if err := ValidateReport(watchReport()); err != nil {
		t.Fatalf("valid watch claim rejected: %v", err)
	}
	for _, host := range []string{"localhost", "service.local", "service.internal", "service.example", "127.0.0.1", "[::1]", "https://www.example.com", "user@www.example.com", "www.example.com/path", "www.example.com:443", "a..com", "-bad.com", "a.123"} {
		r := base
		r.Hostname = host
		if err := ValidateReport(r); err == nil {
			t.Errorf("accepted non-public hostname %q", host)
		}
	}
	for _, change := range []struct {
		name string
		edit func(*Report)
	}{
		{"future day", func(r *Report) { r.ObservedDay = "2099-01-01" }},
		{"invalid fingerprint", func(r *Report) { r.CertificateSHA256 = "bad" }},
		{"candidate CRL", func(r *Report) { r.Evidence = "candidate" }},
		{"weak issuer match", func(r *Report) { r.CRL.IssuerMatch = "key_identifier_candidate" }},
		{"zero serial", func(r *Report) { r.CRL.CertificateSerial = "0" }},
		{"revoked after observation", func(r *Report) { r.CRL.RevokedAt = "2025-01-03T00:00:00Z" }},
		{"missing CRL", func(r *Report) { r.CRL = nil }},
	} {
		t.Run(change.name, func(t *testing.T) {
			r := base
			if r.CRL != nil {
				copyCRL := *r.CRL
				r.CRL = &copyCRL
			}
			change.edit(&r)
			if err := ValidateReport(r); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
	w := watchReport()
	w.Watch.Status = "monitored"
	if err := ValidateReport(w); err == nil {
		t.Fatal("monitored watch must not be published")
	}
	w = watchReport()
	w.Watch.MatchType = "name"
	if err := ValidateReport(w); err == nil {
		t.Fatal("name-only watch must not be published")
	}
}

func TestReportIDCanonicalAndPublicStore(t *testing.T) {
	store, err := NewPublicStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	r := crlReport()
	first, inserted, err := store.Add(context.Background(), r)
	if err != nil || !inserted {
		t.Fatalf("first insert: inserted=%v err=%v", inserted, err)
	}
	if first.TrustStatus != "unverified" || first.Report.Hostname != "www.example.com" {
		t.Fatalf("unexpected public record: %+v", first)
	}
	other := crlReport()
	other.Hostname = "WWW.EXAMPLE.COM"
	other.CertificateSHA256 = strings.ToUpper(other.CertificateSHA256)
	other.CRL.CertificateSerial = "0001"
	other.CRL.RevokedAt = "2024-12-31T19:00:00-05:00"
	second, inserted, err := store.Add(context.Background(), other)
	if err != nil || inserted || second.ID != first.ID {
		t.Fatalf("equivalent claim not deduplicated: inserted=%v err=%v first=%s second=%s", inserted, err, first.ID, second.ID)
	}
	if _, inserted, err := store.Add(context.Background(), watchReport()); err != nil || !inserted {
		t.Fatalf("watch insert: inserted=%v err=%v", inserted, err)
	}
	stats, err := store.Stats(context.Background())
	if err != nil || stats.Reports != 2 || stats.CRLReports != 1 || stats.WatchReports != 1 || stats.LatestReceivedAt == "" {
		t.Fatalf("unexpected stats: %+v err=%v", stats, err)
	}
	watchRows, err := store.List(context.Background(), PublicFilter{Kind: "watch", Limit: 1000})
	if err != nil || len(watchRows) != 1 || watchRows[0].Kind != "watch" || watchRows[0].TrustStatus != "unverified" {
		t.Fatalf("unexpected filtered rows: %+v err=%v", watchRows, err)
	}
	if _, err = store.db.Exec(`INSERT INTO community_reports(id,received_at,kind,evidence,observed_day,report_json) VALUES(?,?,?,?,?,?)`,
		"old", time.Now().UTC().Add(-reportRetention-time.Hour).Format(time.RFC3339Nano), "watch", "direct", "2020-01-01", `{}`); err != nil {
		t.Fatal(err)
	}
	store.pruneMu.Lock()
	store.lastPrune = time.Now().Add(-25 * time.Hour)
	store.pruneMu.Unlock()
	// Reading also enforces the age limit, even when no new report arrives.
	if _, err := store.List(context.Background(), PublicFilter{Kind: "watch"}); err != nil {
		t.Fatal(err)
	}
	var oldCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM community_reports WHERE id='old'`).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 {
		t.Fatal("expired claim was not removed")
	}
	stats, err = store.Stats(context.Background())
	if err != nil || stats.Reports != 2 {
		t.Fatalf("retention did not prune old report: %+v err=%v", stats, err)
	}
}

func TestPublicHandlerBoundaries(t *testing.T) {
	store, err := NewPublicStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	assets := fstest.MapFS{
		"publicui/index.html":     &fstest.MapFile{Data: []byte("<h1>Public</h1>")},
		"publicui/styles.css":     &fstest.MapFile{Data: []byte("body{}")},
		"publicui/dist/app.js":    &fstest.MapFile{Data: []byte("void 0")},
		"ui/sir-tainted-mark.svg": &fstest.MapFile{Data: []byte("<svg/>")},
		"ui/favicon.svg":          &fstest.MapFile{Data: []byte("<svg/>")},
	}
	var _ fs.FS = assets
	h := NewPublicHandler(store, assets)
	post := func(body []byte, contentType string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://certainted.com/api/v1/reports", bytes.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	data, err := json.Marshal(crlReport())
	if err != nil {
		t.Fatal(err)
	}
	rec := post(data, "application/json")
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid submission: %d %s", rec.Code, rec.Body.String())
	}
	var receipt map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &receipt); err != nil || receipt["trust_status"] != "unverified" || receipt["status"] != "accepted" {
		t.Fatalf("unexpected receipt: %v %v", receipt, err)
	}
	if rec := post(data, "application/json"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"duplicate"`) {
		t.Fatalf("duplicate submission: %d %s", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/api/v1/reports?kind=crl", "/api/v1/stats", "/", "/styles.css", "/app.js", "/sir-tainted-mark.svg", "/favicon.svg"} {
		req := httptest.NewRequest(http.MethodGet, "http://certainted.com"+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("GET %s: status=%d body=%s", path, rec.Code, rec.Body.String())
		}
	}
	listReq := httptest.NewRequest(http.MethodGet, "http://certainted.com/api/v1/reports?kind=crl", nil)
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, listReq)
	var list struct {
		Reports []map[string]any `json:"reports"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &list); err != nil || len(list.Reports) != 1 || list.Reports[0]["kind"] != "crl" || list.Reports[0]["trust_status"] != "unverified" {
		t.Fatalf("public list shape: %+v err=%v", list, err)
	}
	for _, tc := range []struct {
		name, contentType string
		body              []byte
		want              int
	}{
		{"plain text", "text/plain", data, http.StatusUnsupportedMediaType},
		{"unknown field", "application/json", append(data[:len(data)-1], []byte(`,"workload":"private"}`)...), http.StatusBadRequest},
		{"too large", "application/json", bytes.Repeat([]byte("x"), maxReportBytes+1), http.StatusRequestEntityTooLarge},
		{"trailing JSON", "application/json", append(append([]byte{}, data...), []byte(` {}`)...), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(tc.body, tc.contentType)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
	req := httptest.NewRequest(http.MethodPost, "http://certainted.com/api/v1/reports", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://elsewhere.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin browser POST accepted: %d", rec.Code)
	}
	impl := h.(*publicHandler)
	impl.mu.Lock()
	impl.tokens = 0
	impl.last = time.Now()
	impl.mu.Unlock()
	if rec := post(data, "application/json"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "http://certainted.com/api/v1/reports?kind=bogus", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid listing filter accepted: %d", rec.Code)
	}
}

func TestCapacityKeepsNewReceipt(t *testing.T) {
	store, err := NewPublicStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO community_reports(id,received_at,kind,evidence,observed_day,report_json) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	// Future receipts make the new valid submission the oldest row. The cap
	// must protect its ID even when every existing row sorts ahead of it.
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < maxPublicReports; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("seed-%d", i), future, "crl", "direct", "2025-01-02", `{}`); err != nil {
			t.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	received, inserted, err := store.Add(context.Background(), crlReport())
	if err != nil || !inserted || received.ID == "" {
		t.Fatalf("new report lost at capacity: %+v inserted=%v err=%v", received, inserted, err)
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM community_reports`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != maxPublicReports {
		t.Fatalf("capacity count=%d, want %d", count, maxPublicReports)
	}
}

func TestReceiptTimeSortsChronologically(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	a := base.Format(dbTimeLayout)
	b := base.Add(100 * time.Millisecond).Format(dbTimeLayout)
	if !(a < b) {
		t.Fatalf("SQLite TEXT timestamp order is not chronological: %q >= %q", a, b)
	}
}
