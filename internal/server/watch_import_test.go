package server

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/store"
)

func postWatchFile(t *testing.T, handler http.Handler, filename, format string, data []byte, intent, origin, site string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	if format != "" {
		if err := m.WriteField("format", format); err != nil {
			t.Fatal(err)
		}
	}
	part, err := m.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/watches/import", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	if intent != "" {
		r.Header.Set("X-Certainted-Intent", intent)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if site != "" {
		r.Header.Set("Sec-Fetch-Site", site)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestWatchImportJSONAndCSVRoundTrip(t *testing.T) {
	source := testStore(t)
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	fp := strings.Repeat("a", 64)
	name := "  =Fixture Intermediate"
	if _, err := source.AddWatch(model.WatchEntry{
		Name: name, Group: "fixture", MatchType: "cert_sha256", Value: fp,
		Status: "under investigation", Severity: "high", Reason: "test reason",
		Source: "fixture", EffectiveFrom: &start,
	}); err != nil {
		t.Fatal(err)
	}
	sourceAPI := New(source, fstest.MapFS{})
	for _, format := range []string{"json", "csv"} {
		t.Run(format, func(t *testing.T) {
			exported := serveAPI(t, sourceAPI, "/api/export/watches?format="+format, "same-origin")
			if exported.Code != http.StatusOK {
				t.Fatalf("export failed: %d %s", exported.Code, exported.Body.String())
			}
			db := testStore(t)
			other, err := db.AddWatch(model.WatchEntry{MatchType: "cert_sha256", Value: strings.Repeat("b", 64), Name: "existing"})
			if err != nil {
				t.Fatal(err)
			}
			dest, err := db.AddDestination(model.DestinationEvent{Time: start.Add(time.Hour), Collector: "fixture", Vantage: "local", Hostname: "example.test", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.AddProbe(model.ProbeObservation{DestinationID: dest, Time: start.Add(time.Hour), Port: 443, Presented: []model.Certificate{{Fingerprint: fp, Subject: "CN=Fixture Intermediate", IsCA: true}}}); err != nil {
				t.Fatal(err)
			}
			api := New(db, fstest.MapFS{})
			response := postWatchFile(t, api, "watches."+format, "", exported.Body.Bytes(), "1", "http://127.0.0.1", "same-origin")
			if response.Code != http.StatusOK {
				t.Fatalf("import failed: %d %s", response.Code, response.Body.String())
			}
			var result store.WatchImportResult
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Imported != 1 || result.Skipped != 0 || len(result.IDs) != 1 || result.IDs[0] == other {
				t.Fatalf("source ID was not remapped: %+v", result)
			}
			watches, err := db.ListWatches()
			if err != nil {
				t.Fatal(err)
			}
			if len(watches) != 2 || watches[1].Name != name || watches[1].Source != "fixture" || watches[1].EffectiveFrom == nil || !watches[1].EffectiveFrom.Equal(start) {
				t.Fatalf("watch did not round-trip: %+v", watches)
			}
			findings, err := db.ListFindings(store.FindingFilter{WatchID: result.IDs[0]})
			if err != nil || len(findings) != 1 || findings[0].Evidence != "direct" {
				t.Fatalf("historical finding = %+v, %v", findings, err)
			}
			again := postWatchFile(t, api, "watches."+format, format, exported.Body.Bytes(), "1", "", "")
			if again.Code != http.StatusOK {
				t.Fatalf("repeat import failed: %d %s", again.Code, again.Body.String())
			}
			if err := json.Unmarshal(again.Body.Bytes(), &result); err != nil || result.Imported != 0 || result.Skipped != 1 {
				t.Fatalf("repeat import = %+v, %v", result, err)
			}
		})
	}
}

func TestWatchImportRecordsFileProvenanceWhenAbsent(t *testing.T) {
	for _, tc := range []struct {
		format string
		data   string
	}{
		{"json", `[{"match_type":"name","value":"Fixture CA"}]`},
		{"csv", "match_type,value\nname,Fixture CA\n"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			db := testStore(t)
			response := postWatchFile(t, New(db, fstest.MapFS{}), "watches."+tc.format, tc.format, []byte(tc.data), "1", "", "")
			if response.Code != http.StatusOK {
				t.Fatalf("import failed: %d %s", response.Code, response.Body.String())
			}
			watches, err := db.ListWatches()
			if err != nil || len(watches) != 1 || watches[0].Source != "imported "+strings.ToUpper(tc.format)+" watchlist" {
				t.Fatalf("watch provenance = %+v, %v", watches, err)
			}
		})
	}
}

func TestWatchImportRejectsUnauthorizedOversizedAndInvalidFiles(t *testing.T) {
	db := testStore(t)
	api := New(db, fstest.MapFS{})
	valid := []byte(`[{"match_type":"cert_sha256","value":"` + strings.Repeat("a", 64) + `"}]`)
	for _, tc := range []struct{ intent, origin, site string }{
		{"", "", ""},
		{"1", "http://attacker.invalid", ""},
		{"1", "", "cross-site"},
	} {
		response := postWatchFile(t, api, "watches.json", "json", valid, tc.intent, tc.origin, tc.site)
		if response.Code != http.StatusForbidden {
			t.Fatalf("unauthorized import got %d: %s", response.Code, response.Body.String())
		}
	}
	large := postWatchFile(t, api, "watches.json", "json", bytes.Repeat([]byte("x"), int(maxWatchImportFile)+1), "1", "", "")
	if large.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized import got %d: %s", large.Code, large.Body.String())
	}
	invalid := []byte(`[{"match_type":"cert_sha256","value":"` + strings.Repeat("a", 64) + `"},{"match_type":"cert_sha256","value":"invalid"}]`)
	response := postWatchFile(t, api, "watches.json", "json", invalid, "1", "", "")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid batch got %d: %s", response.Code, response.Body.String())
	}
	unknown := postWatchFile(t, api, "watches.json", "json", []byte(`[{"match_type":"name","value":"Fixture","surprise":1}]`), "1", "", "")
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown JSON field got %d: %s", unknown.Code, unknown.Body.String())
	}
	watches, err := db.ListWatches()
	if err != nil || len(watches) != 0 {
		t.Fatalf("rejected import changed database: %+v, %v", watches, err)
	}
}
