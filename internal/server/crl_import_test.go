package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func importFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	now := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "dashboard test CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   big.NewInt(42),
			RevocationTime: now.Add(-2 * time.Hour),
			ReasonCode:     1,
		}},
	}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return crlDER, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER})
}

func importRequest(t *testing.T, fields map[string]string, files map[string][]byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		part, err := writer.CreateFormFile(name, name+".pem")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/revocations/import", &buf)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-Certainted-Intent", "1")
	r.Header.Set("Origin", "http://127.0.0.1")
	return r
}

func TestDashboardCRLFileImport(t *testing.T) {
	crl, issuer := importFixture(t)
	db := testStore(t)
	h := New(db, fstest.MapFS{})
	r := importRequest(t, map[string]string{"method": "file", "source": "local fixture"}, map[string][]byte{"crl_file": crl, "issuer_file": issuer})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if contentType := w.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		t.Fatalf("success content type %q", contentType)
	}
	var result struct {
		ID         int64  `json:"id"`
		EntryCount int    `json:"entry_count"`
		Source     string `json:"source"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.ID < 1 || result.EntryCount != 1 || result.Source != "local fixture" {
		t.Fatalf("unexpected result: %+v", result)
	}
	stored, err := db.ListCRLs()
	if err != nil || len(stored) != 1 || stored[0].ID != result.ID || stored[0].EntryCount != 1 {
		t.Fatalf("stored CRL: %+v, %v", stored, err)
	}
	// The import operation is idempotent and preserves original provenance.
	r2 := importRequest(t, map[string]string{"method": "file", "source": "second import"}, map[string][]byte{"crl_file": crl, "issuer_file": issuer})
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("duplicate status %d: %s", w2.Code, w2.Body.String())
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &result); err != nil || result.ID != stored[0].ID || result.Source != "local fixture" {
		t.Fatalf("duplicate result: %+v, %v", result, err)
	}
}

func TestDashboardCRLURLModeRejectsMetadataAddress(t *testing.T) {
	_, issuer := importFixture(t)
	h := New(testStore(t), fstest.MapFS{})
	r := importRequest(t, map[string]string{
		"method":  "url",
		"crl_url": "http://169.254.169.254/latest/meta-data/",
	}, map[string][]byte{"issuer_file": issuer})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !strings.Contains(response["error"], "outside public scope") {
		t.Fatalf("expected JSON scope error, got %q: %v", w.Body.String(), err)
	}
}

func TestDashboardCRLImportRequiresIntentAndSameOrigin(t *testing.T) {
	crl, issuer := importFixture(t)
	h := New(testStore(t), fstest.MapFS{})
	makeRequest := func() *http.Request {
		return importRequest(t, map[string]string{"method": "file"}, map[string][]byte{"crl_file": crl, "issuer_file": issuer})
	}
	for name, change := range map[string]func(*http.Request){
		"no intent":    func(r *http.Request) { r.Header.Del("X-Certainted-Intent") },
		"cross origin": func(r *http.Request) { r.Header.Set("Origin", "http://attacker.invalid") },
		"cross site":   func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDashboardCRLImportRejectsTooLargeAndInvalidCRL(t *testing.T) {
	_, issuer := importFixture(t)
	h := New(testStore(t), fstest.MapFS{})
	for _, tc := range []struct {
		name   string
		crl    []byte
		status int
	}{
		{"too large", bytes.Repeat([]byte("x"), int(maxCRLFile)+1), http.StatusRequestEntityTooLarge},
		{"invalid CRL", []byte("not a CRL"), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := importRequest(t, map[string]string{"method": "file"}, map[string][]byte{"crl_file": tc.crl, "issuer_file": issuer})
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var response map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response["error"] == "" {
				t.Fatalf("expected JSON error, got %q: %v", w.Body.String(), err)
			}
		})
	}
}

func TestCRLURLRejectsUnsafeTargetsWithoutDial(t *testing.T) {
	dialCalls := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, errors.New("unexpected dial")
	}
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "mixed.example":
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
		case "private.example":
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
		default:
			return nil, errors.New("unexpected lookup")
		}
	}
	for _, raw := range []string{
		"http://127.0.0.1/list.crl", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/list.crl",
		"http://private.example/list.crl", "http://mixed.example/list.crl",
		"file:///etc/passwd", "http://user:secret@public.example/list.crl", "http://public.example:8080/list.crl",
		"http://public.example/list.crl#fragment",
	} {
		if _, _, err := fetchCRLURL(context.Background(), raw, lookup, dial); err == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	if dialCalls != 0 {
		t.Fatalf("unsafe URLs caused %d dials", dialCalls)
	}
}

func TestCRLURLFetchPinsIPBlocksRedirectsAndCapsBytes(t *testing.T) {
	crl, _ := importFixture(t)
	requestCount := 0
	fixture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected credentials in URL fetch")
		}
		switch r.URL.Path {
		case "/list.crl":
			_, _ = w.Write(crl)
		case "/redirect":
			http.Redirect(w, r, "http://127.0.0.1/private", http.StatusFound)
		case "/large":
			_, _ = io.Copy(w, strings.NewReader(strings.Repeat("a", int(maxCRLFile)+1)))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	t.Setenv("HTTP_PROXY", "http://user:synthetic-secret@127.0.0.1:9")
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "crl.example" {
			t.Errorf("unexpected DNS lookup %s", host)
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	dialCalls := 0
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialCalls++
		if address != "8.8.8.8:80" || network != "tcp" {
			t.Errorf("did not pin public IP: %s %s", network, address)
		}
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				t.Errorf("read fixture request: %v", err)
				return
			}
			defer req.Body.Close()
			recorder := httptest.NewRecorder()
			fixture.ServeHTTP(recorder, req)
			resp := recorder.Result()
			defer resp.Body.Close()
			if err := resp.Write(server); err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				t.Errorf("write fixture response: %v", err)
			}
		}()
		return client, nil
	}
	got, source, err := fetchCRLURL(context.Background(), "http://crl.example/list.crl?token=synthetic-secret", lookup, dial)
	if err != nil || !bytes.Equal(got, crl) || source != "dashboard URL: http://crl.example" {
		t.Fatalf("fetch: source %q, err %v", source, err)
	}
	if strings.Contains(source, "synthetic-secret") {
		t.Fatal("query token persisted in default provenance")
	}
	if _, _, err := fetchCRLURL(context.Background(), "http://crl.example/redirect", lookup, dial); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect result: %v", err)
	}
	if _, _, err := fetchCRLURL(context.Background(), "http://crl.example/large", lookup, dial); !errors.Is(err, errImportTooLarge) {
		t.Fatalf("oversize result: %v", err)
	}
	if requestCount != 3 || dialCalls != 3 {
		t.Fatalf("request count %d, dial count %d", requestCount, dialCalls)
	}
}
