package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

type testChain struct {
	rootPEM      []byte
	leafDER      []byte
	interDER     []byte
	privateKey   *ecdsa.PrivateKey
	interKey     *ecdsa.PrivateKey
	rootCert     *x509.Certificate
	intermediate *x509.Certificate
}

func makeTestChain(t *testing.T) testChain {
	t.Helper()
	now := time.Now().UTC()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	newSerial := func() *big.Int {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	rootKey := newKey()
	rootTemplate := &x509.Certificate{
		SerialNumber: newSerial(), Subject: pkix.Name{CommonName: "Fixture Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	interKey := newKey()
	interTemplate := &x509.Certificate{
		SerialNumber: newSerial(), Subject: pkix.Name{CommonName: "Fixture Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLenZero: true,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey := newKey()
	leafTemplate := &x509.Certificate{
		SerialNumber: newSerial(), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	return testChain{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		leafDER: leafDER, interDER: interDER, privateKey: leafKey,
		interKey: interKey,
		rootCert: root, intermediate: inter,
	}
}

type testServer struct {
	data chan int
	sni  chan string
	dial func(context.Context, string, string) (net.Conn, error)
}

func startTestServer(t *testing.T, chain testChain, includeIntermediate bool) testServer {
	t.Helper()
	certs := [][]byte{chain.leafDER}
	if includeIntermediate {
		certs = append(certs, chain.interDER)
	}
	return startTestServerWithChain(t, chain.privateKey, certs)
}

func startTestServerWithChain(t *testing.T, key *ecdsa.PrivateKey, certs [][]byte) testServer {
	t.Helper()
	serverCertificate := tls.Certificate{Certificate: certs, PrivateKey: key}
	sni := make(chan string, 8)
	serverConfig := &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		sni <- hello.ServerName
		return &serverCertificate, nil
	}}
	data := make(chan int, 8)
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clientRaw, serverRaw := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := tls.Server(serverRaw, serverConfig)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			data <- n
		}()
		return clientRaw, nil
	}
	return testServer{data: data, sni: sni, dial: dial}
}

func eventFor(port int) model.DestinationEvent {
	return model.DestinationEvent{ID: 17, Hostname: "localhost", IP: "127.0.0.1", Port: port, Vantage: "local-test"}
}

func TestProbePresentedAndInferredTrustRoot(t *testing.T) {
	chain := makeTestChain(t)
	server := startTestServer(t, chain, true)
	result := Probe(context.Background(), eventFor(443), Config{TrustStorePEM: chain.rootPEM, TrustStoreName: "fixture-root", DialContext: server.dial})
	if result.Failure != "" || result.ValidationError != "" {
		t.Fatalf("unexpected failure: %+v", result)
	}
	if result.SNI != "localhost" || result.TargetIP != "127.0.0.1" || result.TrustStore != "fixture-root" {
		t.Fatalf("wrong probe provenance: %+v", result)
	}
	select {
	case actual := <-server.sni:
		if actual != "localhost" {
			t.Fatalf("TLS SNI = %q, want localhost", actual)
		}
	default:
		t.Fatal("server did not receive TLS SNI")
	}
	if len(result.Presented) != 2 || len(result.CandidatePaths) != 1 {
		t.Fatalf("want presented leaf/intermediate and one path, got %+v", result)
	}
	path := result.CandidatePaths[0]
	if len(path.Certificates) != 3 || path.Validation != "verified" {
		t.Fatalf("wrong candidate path: %+v", path)
	}
	if result.Presented[1].Fingerprint != path.Certificates[1].Fingerprint || path.Certificates[1].Source != "presented" {
		t.Fatal("presented intermediate lost its direct evidence label")
	}
	if path.Certificates[2].Source != "trust_store" || !path.Certificates[2].SelfSigned {
		t.Fatalf("root must be inferred from trust store: %+v", path.Certificates[2])
	}
	if result.Presented[0].SPKIFingerprint == "" || result.Presented[0].KeyBits != 256 || result.TLSVersion == "" {
		t.Fatalf("missing certificate or TLS details: %+v", result)
	}
	select {
	case n := <-server.data:
		if n != 0 {
			t.Fatalf("probe sent %d application bytes", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not finish independent handshake")
	}
}

func TestProbeIncompleteChainRetainsEvidence(t *testing.T) {
	chain := makeTestChain(t)
	server := startTestServer(t, chain, false)
	result := Probe(context.Background(), eventFor(443), Config{TrustStorePEM: chain.rootPEM, DialContext: server.dial})
	if result.Failure != "" || result.ValidationError == "" || !result.IncompleteChain {
		t.Fatalf("expected validation diagnosis with retained evidence: %+v", result)
	}
	if len(result.Presented) != 1 || result.Presented[0].Source != "presented" || len(result.CandidatePaths) != 0 {
		t.Fatalf("wrong incomplete-chain evidence: %+v", result)
	}
}

func TestProbeInvalidTrustStoreRetainsEvidence(t *testing.T) {
	chain := makeTestChain(t)
	server := startTestServer(t, chain, true)
	result := Probe(context.Background(), eventFor(443), Config{TrustStorePEM: []byte("bad pem"), DialContext: server.dial})
	if result.Failure != "" || !strings.Contains(result.ValidationError, "trust store") || len(result.Presented) != 2 {
		t.Fatalf("invalid trust store must not erase presented chain: %+v", result)
	}
}

func TestProbeRejectsInvalidTargetBeforeDial(t *testing.T) {
	called := false
	result := Probe(context.Background(), model.DestinationEvent{Hostname: "localhost/x", Port: 443}, Config{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, nil
		},
	})
	if called || result.Failure == "" {
		t.Fatalf("invalid target reached dialer: %+v", result)
	}
}

func TestProbeScopeAndCertificateLimit(t *testing.T) {
	called := false
	event := eventFor(443)
	blocked := Probe(context.Background(), event, Config{
		AllowIP: func(net.IP) bool { return false },
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, nil
		},
	})
	if called || !strings.Contains(blocked.Failure, "outside probe scope") {
		t.Fatalf("out-of-scope target reached dialer: %+v", blocked)
	}

	chain := makeTestChain(t)
	server := startTestServer(t, chain, true)
	limited := Probe(context.Background(), event, Config{DialContext: server.dial, MaxCertificates: 1})
	if !strings.Contains(limited.Failure, "limit is 1") || len(limited.Presented) != 0 {
		t.Fatalf("certificate limit not enforced: %+v", limited)
	}
}

func TestHostnameOnlyEventResolvesAndPinsAllowedIP(t *testing.T) {
	chain := makeTestChain(t)
	server := startTestServer(t, chain, true)
	event := eventFor(443)
	event.IP = "" // Collector did not report an IP; preserve that in its event.
	dialed := ""
	result := Probe(context.Background(), event, Config{
		TrustStorePEM: chain.rootPEM,
		AllowIP: func(ip net.IP) bool {
			return ip.Equal(net.ParseIP("127.0.0.1"))
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = address
			return server.dial(ctx, network, address)
		},
	})
	if result.Failure != "" || result.ValidationError != "" || result.TargetIP != "127.0.0.1" {
		t.Fatalf("hostname-only probe failed: %+v", result)
	}
	if dialed != "127.0.0.1:443" || result.SNI != "localhost" {
		t.Fatalf("target not pinned while retaining SNI: dialed %q, result %+v", dialed, result)
	}
}

func TestCrossSignedIntermediateKeepsMultipleCandidateRoots(t *testing.T) {
	chain := makeTestChain(t)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	otherTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(999), Subject: pkix.Name{CommonName: "Fixture Root B"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: 1,
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := x509.ParseCertificate(otherDER)
	if err != nil {
		t.Fatal(err)
	}
	otherIntermediateDER, err := x509.CreateCertificate(rand.Reader, chain.intermediate, otherRoot, &chain.interKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	server := startTestServerWithChain(t, chain.privateKey, [][]byte{chain.leafDER, chain.interDER, otherIntermediateDER})
	trustPEM := append(append([]byte(nil), chain.rootPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER})...)
	result := Probe(context.Background(), eventFor(443), Config{TrustStorePEM: trustPEM, DialContext: server.dial})
	if result.Failure != "" || result.ValidationError != "" || len(result.CandidatePaths) != 2 {
		t.Fatalf("expected two verified paths: %+v", result)
	}
	roots := map[string]bool{}
	for _, path := range result.CandidatePaths {
		root := path.Certificates[len(path.Certificates)-1]
		if root.Source != "trust_store" {
			t.Fatalf("candidate root was not labeled trust_store: %+v", path)
		}
		roots[root.Fingerprint] = true
	}
	if len(roots) != 2 || len(result.Presented) != 3 {
		t.Fatalf("cross-signed alternatives collapsed: %+v", result)
	}
}

func TestProbeHandshakeTimeout(t *testing.T) {
	var remote net.Conn
	started := time.Now()
	result := Probe(context.Background(), eventFor(443), Config{
		Timeout: 30 * time.Millisecond,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			remote = server // Peer accepts TCP but never speaks TLS.
			return client, nil
		},
	})
	if remote != nil {
		defer remote.Close()
	}
	if !strings.Contains(result.Failure, "TLS handshake") || time.Since(started) > time.Second {
		t.Fatalf("handshake did not obey timeout: %+v", result)
	}
}
