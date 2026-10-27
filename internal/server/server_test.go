package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func serveAPI(t *testing.T, h http.Handler, path, site string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	if site != "" {
		request.Header.Set("Sec-Fetch-Site", site)
	}
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	return response
}

func TestBuiltinIncidentAPIListsExactCertificateVariants(t *testing.T) {
	handler := New(testStore(t), fstest.MapFS{})
	response := serveAPI(t, handler, "/api/incidents", "same-origin")
	if response.Code != http.StatusOK {
		t.Fatalf("incident API returned %d: %s", response.Code, response.Body.String())
	}
	var incident store.IncidentManifest
	if err := json.Unmarshal(response.Body.Bytes(), &incident); err != nil {
		t.Fatal(err)
	}
	if len(incident.Intermediates) != 8 {
		t.Fatalf("got %d affected keys, want 8", len(incident.Intermediates))
	}
	certificates := 0
	for _, ca := range incident.Intermediates {
		certificates += len(ca.Certificates)
	}
	if certificates != 16 {
		t.Fatalf("got %d revoked certificate identities, want 16", certificates)
	}
}

func TestAPIFetchMetadataBlocksCrossOriginReadsAndExports(t *testing.T) {
	handler := New(testStore(t), fstest.MapFS{})
	for _, path := range []string{"/api/stats", "/api/export/probes?format=json"} {
		for _, site := range []string{"cross-site", "same-site"} {
			response := serveAPI(t, handler, path, site)
			if response.Code != http.StatusForbidden {
				t.Errorf("%s from %s returned %d, want 403", path, site, response.Code)
			}
		}
		for _, site := range []string{"same-origin", "none", ""} {
			response := serveAPI(t, handler, path, site)
			if response.Code != http.StatusOK {
				t.Errorf("%s from %q returned %d, want 200", path, site, response.Code)
			}
		}
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		request.Header.Set("Origin", "http://attacker.example")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Errorf("%s with cross-origin Origin returned %d, want 403", path, response.Code)
		}
	}
}

func TestStopControlRequiresSameOriginIntent(t *testing.T) {
	stopped := make(chan struct{}, 1)
	handler := NewWithShutdown(testStore(t), fstest.MapFS{}, "test-only-secret", func() { stopped <- struct{}{} })
	request := func(method, host, origin, site string, intent, token bool) int {
		req := httptest.NewRequest(method, "http://127.0.0.1/api/control/stop", nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		if intent {
			req.Header.Set("X-Certainted-Intent", "1")
		}
		if token {
			req.Header.Set("X-Certainted-Stop-Token", "test-only-secret")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	for _, test := range []struct {
		method, host, origin, site string
		intent, token              bool
	}{
		{http.MethodPost, "attacker.example", "", "", true, true},
		{http.MethodPost, "127.0.0.1", "http://attacker.example", "", true, true},
		{http.MethodPost, "127.0.0.1", "", "cross-site", true, true},
		{http.MethodPost, "127.0.0.1", "", "", false, true},
		{http.MethodPost, "127.0.0.1", "", "", true, false},
	} {
		if code := request(test.method, test.host, test.origin, test.site, test.intent, test.token); code != http.StatusForbidden {
			t.Fatalf("unauthorized control request returned %d", code)
		}
	}
	if code := request(http.MethodGet, "127.0.0.1", "", "", true, true); code != http.StatusNotFound {
		t.Fatalf("GET control request returned %d", code)
	}
	select {
	case <-stopped:
		t.Fatal("unauthorized request stopped server")
	default:
	}
	if code := request(http.MethodPost, "127.0.0.1", "http://127.0.0.1", "same-origin", true, true); code != http.StatusAccepted {
		t.Fatalf("authorized control request returned %d", code)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("authorized control request did not request shutdown")
	}
}

func TestLegacyControlHeadersStillWork(t *testing.T) {
	stopped := make(chan struct{}, 1)
	handler := NewWithShutdown(testStore(t), fstest.MapFS{}, "test-only-secret", func() { stopped <- struct{}{} })
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/control/stop", nil)
	req.Header.Set("X-Certained-Intent", "1")
	req.Header.Set("X-Certained-Stop-Token", "test-only-secret")
	req.Header.Set("Origin", "http://127.0.0.1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != http.StatusAccepted || response.Header().Get("X-Certainted-Control") != "stop" {
		t.Fatalf("legacy control request returned %d with headers %v", response.Code, response.Header())
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("legacy control request did not request shutdown")
	}
}

func TestDashboardServesFavicon(t *testing.T) {
	assets := fstest.MapFS{"ui/favicon.svg": &fstest.MapFile{Data: []byte("<svg/>")}}
	response := serveAPI(t, New(testStore(t), assets), "/favicon.svg", "same-origin")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/svg+xml" || response.Body.String() != "<svg/>" {
		t.Fatalf("favicon: status %d, type %q, body %q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}
}

func TestDashboardHostPolicyMatchesLoopbackListeners(t *testing.T) {
	for _, host := range []string{"localhost:8787", "127.0.0.1:8787", "127.0.0.2:8787", "[::1]:8787", "[0:0:0:0:0:0:0:1]:8787"} {
		if !localHost(host) {
			t.Errorf("rejected loopback listener %q", host)
		}
	}
	for _, host := range []string{"attacker.example:8787", "127.0.0.1.attacker.example:8787", "192.0.2.1:8787"} {
		if localHost(host) {
			t.Errorf("accepted non-loopback host %q", host)
		}
	}
}

func TestProbeExportByteBudgetAndLimit(t *testing.T) {
	db := testStore(t)
	id, err := db.AddDestination(model.DestinationEvent{Time: time.Now().UTC(), Collector: "test", Vantage: "local", IP: "127.0.0.1", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{strings.Repeat("x", 2048), "small failure"} {
		if _, err := db.AddProbe(model.ProbeObservation{DestinationID: id, Time: time.Now().UTC(), Vantage: "local", TargetIP: "127.0.0.1", Port: 443, Failure: failure}); err != nil {
			t.Fatal(err)
		}
	}
	handler := &Server{DB: db, probeExportByteBudget: 512}
	blocked := serveAPI(t, handler, "/api/export/probes?format=json", "same-origin")
	if blocked.Code != http.StatusRequestEntityTooLarge || !strings.Contains(blocked.Body.String(), "?limit=N") {
		t.Fatalf("oversized probe export: status %d, body %q", blocked.Code, blocked.Body.String())
	}
	allowed := serveAPI(t, handler, "/api/export/probes?format=json&limit=1", "same-origin")
	if allowed.Code != http.StatusOK {
		t.Fatalf("bounded probe export: status %d, body %q", allowed.Code, allowed.Body.String())
	}
	var probes []model.ProbeObservation
	if err := json.Unmarshal(allowed.Body.Bytes(), &probes); err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0].Failure != "small failure" {
		t.Fatalf("wrong limited export: %+v", probes)
	}
	invalid := serveAPI(t, handler, "/api/export/probes?limit=0", "same-origin")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid export limit: %d", invalid.Code)
	}
}

func TestCSVExportEscapesFormulaAfterLeadingWhitespace(t *testing.T) {
	db := testStore(t)
	name := " \t=HYPERLINK(\"https://example.invalid\")"
	if _, err := db.AddWatch(model.WatchEntry{Name: name, MatchType: "cert_sha256", Value: strings.Repeat("a", 64), Status: "monitored", Severity: "info"}); err != nil {
		t.Fatal(err)
	}
	response := serveAPI(t, New(db, fstest.MapFS{}), "/api/export/watches?format=csv", "same-origin")
	if response.Code != http.StatusOK {
		t.Fatalf("CSV export status %d: %s", response.Code, response.Body.String())
	}
	rows, err := csv.NewReader(strings.NewReader(response.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("CSV row count = %d", len(rows))
	}
	nameColumn := -1
	for i, header := range rows[0] {
		if header == "name" {
			nameColumn = i
		}
	}
	if nameColumn < 0 || rows[1][nameColumn] != "'"+name {
		t.Fatalf("formula-like name was not escaped: %v", rows)
	}
	for _, value := range []string{"\r\n+1", "\v-1", "\f@cmd", "  =1"} {
		if got := csvSafe(value); got != "'"+value {
			t.Errorf("csvSafe(%q) = %q", value, got)
		}
	}
}
