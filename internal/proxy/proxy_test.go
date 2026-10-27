package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/observe"
	"github.com/jasvir/certainted/internal/probe"
)

type recordingSink struct {
	events       chan model.DestinationEvent
	returnError  error
	probeResults chan model.ProbeObservation
}

func (s *recordingSink) Submit(event model.DestinationEvent) error {
	s.events <- event
	if s.probeResults != nil {
		go func() {
			// A deliberately strict certificate limit makes this independent
			// TLS handshake fail while the application's tunnel keeps working.
			s.probeResults <- probe.Probe(context.Background(), event, probe.Config{MaxCertificates: 1, Timeout: time.Second})
		}()
	}
	return s.returnError
}

func localScope(port int) observe.Scope {
	return observe.Scope{
		AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		Ports:      map[int]bool{port: true},
	}
}

func startProxy(t *testing.T, sink Submitter, cfg Config) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := New(sink, cfg)
	served := make(chan error, 1)
	go func() { served <- p.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
		_ = listener.Close()
		if err := <-served; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("proxy server: %v", err)
		}
	})
	return listener.Addr().String()
}

func makeLocalTLSService(t *testing.T, handler http.Handler) (*httptest.Server, *x509.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Certainted test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLenZero: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	// Present the original leaf and its issuing root so the independent
	// probe's one-certificate limit rejects this chain.
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return server, leaf, roots
}

func TestConnectPreservesApplicationTLSAndIgnoresProbeFailure(t *testing.T) {
	const secretPath = "/private/synthetic-path-72"
	const secretHeader = "synthetic-authorization-318"
	const secretBody = "synthetic-body-541"
	requests := make(chan bool, 1)
	service, originalLeaf, roots := makeLocalTLSService(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- r.URL.Path == secretPath && r.Header.Get("X-Test-Secret") == secretHeader && string(body) == secretBody
		_, _ = io.WriteString(w, "destination response")
	}))
	port := service.Listener.Addr().(*net.TCPAddr).Port
	sink := &recordingSink{
		events:       make(chan model.DestinationEvent, 2),
		returnError:  errors.New("observation queue unavailable"),
		probeResults: make(chan model.ProbeObservation, 1),
	}
	proxyAddress := startProxy(t, sink, Config{Scope: localScope(port), MaxTunnelDuration: 10 * time.Second})
	transport := &http.Transport{
		Proxy:              http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddress}),
		TLSClientConfig:    &tls.Config{RootCAs: roots},
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Basic synthetic-proxy-secret-965"}},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequest(http.MethodPost, service.URL+secretPath, strings.NewReader(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Test-Secret", secretHeader)
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("application TLS through CONNECT failed: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(responseBody) != "destination response" {
		t.Fatalf("unexpected destination response: %d %q", response.StatusCode, responseBody)
	}
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 ||
		sha256.Sum256(response.TLS.PeerCertificates[0].Raw) != sha256.Sum256(originalLeaf.Raw) {
		t.Fatal("client did not receive the destination's original certificate")
	}
	select {
	case correct := <-requests:
		if !correct {
			t.Fatal("destination did not receive the encrypted request content")
		}
	case <-time.After(time.Second):
		t.Fatal("destination handler did not receive the request")
	}
	select {
	case event := <-sink.events:
		if event.Collector != "connect" || event.IP != "127.0.0.1" || event.Port != port || event.Hostname != "" {
			t.Fatalf("wrong destination metadata: %+v", event)
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{secretPath, secretHeader, secretBody, "synthetic-proxy-secret-965"} {
			if bytes.Contains(encoded, []byte(secret)) {
				t.Fatalf("destination metadata contains tunneled data or credentials: %s", secret)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("CONNECT destination event was not emitted")
	}
	select {
	case observation := <-sink.probeResults:
		if !strings.Contains(observation.Failure, "limit is 1") {
			t.Fatalf("expected independent probe failure: %+v", observation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent probe did not finish")
	}
}

func rawConnect(t *testing.T, proxyAddress, target string) (net.Conn, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	return conn, response
}

func TestRejectsPlaintextHTTP(t *testing.T) {
	sink := &recordingSink{events: make(chan model.DestinationEvent, 1)}
	proxyAddress := startProxy(t, sink, Config{})
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	response, err := client.Get("http://" + proxyAddress + "/synthetic-plaintext-secret")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("plaintext request status = %d, want 405", response.StatusCode)
	}
	select {
	case event := <-sink.events:
		t.Fatalf("plaintext request emitted destination event: %+v", event)
	default:
	}
}

func TestConnectScopeAndConnectionLimit(t *testing.T) {
	t.Run("scope rejects loopback by default", func(t *testing.T) {
		sink := &recordingSink{events: make(chan model.DestinationEvent, 1)}
		proxyAddress := startProxy(t, sink, Config{})
		conn, response := rawConnect(t, proxyAddress, "127.0.0.1:443")
		defer conn.Close()
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("out-of-scope CONNECT status = %d, want 403", response.StatusCode)
		}
		select {
		case event := <-sink.events:
			t.Fatalf("out-of-scope CONNECT emitted event: %+v", event)
		default:
		}
	})

	t.Run("second live tunnel exceeds limit", func(t *testing.T) {
		target, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			conn, err := target.Accept()
			if err == nil {
				accepted <- conn
			}
		}()
		port := target.Addr().(*net.TCPAddr).Port
		sink := &recordingSink{events: make(chan model.DestinationEvent, 2)}
		proxyAddress := startProxy(t, sink, Config{Scope: localScope(port), MaxConnections: 1, IdleTimeout: 5 * time.Second})
		first, firstResponse := rawConnect(t, proxyAddress, target.Addr().String())
		defer first.Close()
		defer firstResponse.Body.Close()
		if firstResponse.StatusCode != http.StatusOK {
			t.Fatalf("first CONNECT status = %d, want 200", firstResponse.StatusCode)
		}
		select {
		case conn := <-accepted:
			defer conn.Close()
		case <-time.After(time.Second):
			t.Fatal("target did not accept first tunnel")
		}
		second, secondResponse := rawConnect(t, proxyAddress, target.Addr().String())
		defer second.Close()
		defer secondResponse.Body.Close()
		if secondResponse.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("second CONNECT status = %d, want 503", secondResponse.StatusCode)
		}
	})
}
