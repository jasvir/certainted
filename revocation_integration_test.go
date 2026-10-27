package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/server"
	"github.com/jasvir/certainted/internal/store"
)

// TestCRLImportReevaluatesMetadataOnlyProbe exercises the actual ingest and
// CRL-import commands, then checks database, API and export evidence. All
// certificates and the TLS endpoint are generated locally; no proxy or public
// network service is involved.
func TestCRLImportReevaluatesMetadataOnlyProbe(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root, rootKey, rootDER := makeIntegrationCA(t, "fixture root", nil, nil, 100, now)
	intermediate, intermediateKey, intermediateDER := makeIntegrationCA(t, "fixture intermediate", root, rootKey, 200, now)
	leaf, leafKey, leafDER := makeIntegrationLeaf(t, intermediate, intermediateKey, 300, now)
	revokedAt := now.Add(-time.Hour)
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now.Add(-2 * time.Hour),
		NextUpdate: now.Add(24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{
			SerialNumber:   leaf.SerialNumber,
			RevocationTime: revokedAt,
			ReasonCode:     1,
		}},
	}, intermediate, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}

	var httpRequests atomic.Int64
	tlsService := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	tlsService.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leafDER, intermediateDER},
		PrivateKey:  leafKey,
	}}}
	tlsService.StartTLS()
	defer tlsService.Close()
	ip, portText, err := net.SplitHostPort(tlsService.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.db")
	trustPath := filepath.Join(dir, "root.pem")
	issuerPath := filepath.Join(dir, "issuer.pem")
	crlPath := filepath.Join(dir, "revoked.crl")
	jsonlPath := filepath.Join(dir, "destinations.jsonl")
	writeIntegrationFile(t, trustPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))
	writeIntegrationFile(t, issuerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER}))
	writeIntegrationFile(t, crlPath, crlDER)
	event, err := json.Marshal(map[string]any{
		"collector": "local-fixture", "vantage": "fixture-network",
		"hostname": "localhost", "ip": ip, "port": port,
	})
	if err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, jsonlPath, append(event, '\n'))
	if err := ingest([]string{"-db", dbPath, "-file", jsonlPath, "-allow-cidr", "127.0.0.0/8", "-ports", portText,
		"-trust-store", trustPath, "-rate", "1ms"}); err != nil {
		t.Fatal(err)
	}
	if got := httpRequests.Load(); got != 0 {
		t.Fatalf("independent TLS probe sent %d HTTP requests", got)
	}

	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	probes, err := db.ListProbes(10)
	if err != nil || len(probes) != 1 {
		t.Fatalf("probes=%+v, err=%v", probes, err)
	}
	p := probes[0]
	if p.Failure != "" || p.ValidationError != "" || len(p.Presented) != 2 || len(p.CandidatePaths) == 0 {
		t.Fatalf("independent probe failed to present and validate chain: %+v", p)
	}
	if p.Presented[0].Fingerprint != fingerprintIntegration(leafDER) || p.Presented[1].Fingerprint != fingerprintIntegration(intermediateDER) {
		t.Fatalf("wrong server-presented chain: %+v", p.Presented)
	}
	var inferredRoot bool
	for _, path := range p.CandidatePaths {
		for _, cert := range path.Certificates {
			if cert.Fingerprint == fingerprintIntegration(rootDER) && cert.Source == "trust_store" {
				inferredRoot = true
			}
		}
	}
	if !inferredRoot {
		t.Fatalf("test root not labeled as trust-store candidate: %+v", p.CandidatePaths)
	}
	prior, err := db.ListRevocationFindings(store.RevocationFindingFilter{})
	if err != nil || len(prior) != 0 {
		t.Fatalf("unexpected finding before CRL import: %+v, err=%v", prior, err)
	}

	// Import after the probe to verify historical reevaluation by the command.
	if err := crl([]string{"import", "-db", dbPath, "-file", crlPath, "-issuer", issuerPath, "-source", "offline integration fixture"}); err != nil {
		t.Fatal(err)
	}
	findings, err := db.ListRevocationFindings(store.RevocationFindingFilter{})
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings=%+v, err=%v", findings, err)
	}
	f := findings[0]
	if f.Evidence != "direct" || f.IssuerMatch != "verified_path" || f.CertificateFingerprint != fingerprintIntegration(leafDER) ||
		f.CertificateSerial != leaf.SerialNumber.Text(16) || f.ReasonCode != 1 || f.Source != "offline integration fixture" ||
		!f.Time.After(f.RevokedAt) || f.CRLThisUpdateAfterProbe || f.CRLStaleAtProbe {
		t.Fatalf("incorrect direct post-revocation finding: %+v", f)
	}
	if got := httpRequests.Load(); got != 0 {
		t.Fatalf("probe or CRL import sent %d HTTP requests", got)
	}

	handler := server.New(db, dashboard)
	for _, path := range []string{"/api/revocations/findings?evidence=direct", "/api/export/revocations?format=json&limit=10"} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s returned %d: %s", path, rec.Code, rec.Body.String())
		}
		var got []store.RevocationFinding
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s JSON: %v", path, err)
		}
		if len(got) != 1 || got[0].ID != f.ID || got[0].Evidence != "direct" || got[0].IssuerMatch != "verified_path" {
			t.Fatalf("%s returned wrong finding: %+v", path, got)
		}
	}
	stats, err := db.Stats()
	if err != nil || stats.RevocationFindings != 1 || stats.RevokedDestinations != 1 {
		t.Fatalf("revocation overview counts: %+v, err=%v", stats, err)
	}
}

func makeIntegrationCA(t *testing.T, name string, parent *x509.Certificate, parentKey ed25519.PrivateKey, serial int64, now time.Time) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte{byte(serial), byte(serial >> 8), 1, 2, 3},
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func makeIntegrationLeaf(t *testing.T, parent *x509.Certificate, parentKey ed25519.PrivateKey, serial int64, now time.Time) (*x509.Certificate, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key, der
}

func writeIntegrationFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func fingerprintIntegration(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
