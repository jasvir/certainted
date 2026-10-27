package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/server"
	"github.com/jasvir/certainted/internal/store"
)

func TestMetadataOnlyIngestionProbesWithoutHTTPOrProxy(t *testing.T) {
	var requests atomic.Int64
	tlsService := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusOK) }))
	defer tlsService.Close()
	host, portText, err := net.SplitHostPort(tlsService.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.db")
	file := filepath.Join(dir, "events.jsonl")
	event := fmt.Sprintf("{\"collector\":\"fixture-flow\",\"vantage\":\"lab\",\"hostname\":\"localhost\",\"ip\":%q,\"port\":%d,\"workload\":\"fixture-app\",\"attribution_reliable\":true}\n", host, port)
	if err := os.WriteFile(file, []byte(event), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ingest([]string{"-db", dbPath, "-file", file, "-allow-cidr", "127.0.0.0/8", "-ports", portText, "-rate", "1ms"}); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, err := db.ListDestinations(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	probes, err := db.ListProbes(10)
	if err != nil || len(probes) != 1 {
		t.Fatalf("probes=%+v err=%v", probes, err)
	}
	if probes[0].Failure != "" || len(probes[0].Presented) != 1 {
		t.Fatalf("missing independent probe evidence: %+v", probes[0])
	}
	if probes[0].ValidationError == "" {
		t.Fatal("expected validation diagnostic for fixture's unrelated hostname")
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("probe sent %d HTTP requests", got)
	}
}

func TestDefaultInventoryPrefersExistingPreviousDatabase(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "certainted.db")
	previous := filepath.Join(dir, "certained.db")
	if got := preferredInventoryDBPath(current, previous); got != current {
		t.Fatalf("empty directory selected %q, want %q", got, current)
	}
	if err := os.WriteFile(previous, []byte("old inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := preferredInventoryDBPath(current, previous); got != previous {
		t.Fatalf("existing previous inventory selected %q, want %q", got, previous)
	}
	if err := os.WriteFile(current, []byte("new inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := preferredInventoryDBPath(current, previous); got != current {
		t.Fatalf("two inventories selected %q, want %q", got, current)
	}
}

func TestLocalInventoryStartsWithIncidentWatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	for attempt := 0; attempt < 2; attempt++ {
		db, err := openLocalInventory(path)
		if err != nil {
			t.Fatal(err)
		}
		watches, err := db.ListWatches()
		if closeErr := db.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err != nil || len(watches) != 8 {
			t.Fatalf("attempt %d: got %d built-in watches, err=%v", attempt, len(watches), err)
		}
	}
}

func TestIngestionDrainsAcceptedEventsBeforeReportingLaterError(t *testing.T) {
	tlsService := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsService.Close()
	host, portText, err := net.SplitHostPort(tlsService.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "inventory.db")
	file := filepath.Join(dir, "events.jsonl")
	data := fmt.Sprintf("{\"collector\":\"fixture-flow\",\"ip\":%q,\"port\":%d}\n{malformed}\n", host, port)
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ingest([]string{"-db", dbPath, "-file", file, "-allow-cidr", "127.0.0.0/8", "-ports", portText, "-rate", "1ms"}); err == nil {
		t.Fatal("malformed second line accepted")
	}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	events, err := db.ListDestinations(10)
	if err != nil || len(events) != 1 {
		t.Fatalf("accepted event was lost: events=%+v err=%v", events, err)
	}
	probes, err := db.ListProbes(10)
	if err != nil || len(probes) != 1 || len(probes[0].Presented) != 1 {
		t.Fatalf("accepted event was not probed: probes=%+v err=%v", probes, err)
	}
}

func TestLocalAPIRejectsCrossOriginMutationAndForeignHost(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := server.New(db, dashboard)
	body := `{"name":"test CA","match_type":"cert_sha256","value":"` + strings.Repeat("a", 64) + `"}`
	request := func(host, origin string, intent bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/watches", strings.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if intent {
			req.Header.Set("X-Certainted-Intent", "1")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if code := request("attacker.example", "", true).Code; code != http.StatusForbidden {
		t.Fatalf("foreign Host: %d", code)
	}
	if code := request("127.0.0.1", "http://attacker.example", true).Code; code != http.StatusForbidden {
		t.Fatalf("foreign Origin: %d", code)
	}
	if code := request("127.0.0.1", "", false).Code; code != http.StatusForbidden {
		t.Fatalf("missing intent header: %d", code)
	}
	if code := request("127.0.0.1", "http://127.0.0.1", true).Code; code != http.StatusCreated {
		t.Fatalf("same-origin request: %d", code)
	}
	if _, err := loopbackListen("0.0.0.0:0"); err == nil {
		t.Fatal("public listener accepted")
	}
}

func availableLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestServeProxyFlags(t *testing.T) {
	tests := []struct {
		name, args, wantAddress, wantError string
	}{
		{name: "default", wantAddress: defaultProxyAddr},
		{name: "custom address", args: "-proxy 127.0.0.1:9090", wantAddress: "127.0.0.1:9090"},
		{name: "disabled", args: "-noproxy"},
		{name: "conflicting flags", args: "-proxy 127.0.0.1:9090 -noproxy", wantError: "cannot be used together"},
		{name: "empty proxy address", args: "-proxy=", wantError: "requires an address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := flag.NewFlagSet("serve", flag.ContinueOnError)
			var cfg serveProxyFlags
			cfg.register(fs)
			if err := fs.Parse(strings.Fields(tt.args)); err != nil {
				t.Fatal(err)
			}
			address, err := cfg.listenAddress(fs)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("listenAddress error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil || address != tt.wantAddress {
				t.Fatalf("listenAddress = %q, %v; want %q", address, err, tt.wantAddress)
			}
		})
	}
}

func TestServeNoProxyStartsDashboard(t *testing.T) {
	httpAddr := availableLoopbackAddress(t)
	dbPath := filepath.Join(t.TempDir(), "noproxy.db")
	done := make(chan error, 1)
	go func() {
		done <- serve([]string{"-db", dbPath, "-http", httpAddr, "-noproxy", "-refresh", "0"})
	}()
	defer func() { _ = stopServe([]string{"-http", httpAddr}) }()

	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + httpAddr + "/api/stats")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("serve -noproxy exited before stop: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("dashboard did not start with -noproxy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := stopServe([]string{"-http", httpAddr}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve -noproxy shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve -noproxy did not finish after stop")
	}
}

func TestStopCommandShutsDownDashboardAndProxy(t *testing.T) {
	httpAddr := availableLoopbackAddress(t)
	proxyAddr := availableLoopbackAddress(t)
	dbPath := filepath.Join(t.TempDir(), "stop-test.db")
	done := make(chan error, 1)
	go func() {
		done <- serve([]string{"-db", dbPath, "-http", httpAddr, "-proxy", proxyAddr, "-refresh", "0"})
	}()
	defer func() { _ = stopServe([]string{"-http", httpAddr}) }()

	client := &http.Client{Timeout: 200 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get("http://" + httpAddr + "/api/stats")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case err := <-done:
			t.Fatalf("serve exited before stop: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("dashboard did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for {
		conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	tokenPath, err := stopTokenPath(httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stop token missing while serving: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("stop token is readable by other users: %v", info.Mode())
	}
	if err := stopServe([]string{"-http", "192.0.2.1:8787"}); err == nil {
		t.Fatal("stop accepted a non-loopback target")
	}
	if err := stopServe([]string{"-http", httpAddr}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not finish after stop")
	}
	if conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("proxy still listening after stop")
	}
	if err := stopServe([]string{"-http", httpAddr}); err == nil {
		t.Fatal("second stop should report no running instance")
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("stop token was not removed: %v", err)
	}
	db, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("inventory unavailable after shutdown: %v", err)
	}
	_ = db.Close()
}

func TestStopCommandCanStopPreviousVersion(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	tokenPath, err := controlTokenPath(address, "certained-control-", true)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	defer os.Remove(tokenPath)
	token := strings.Repeat("a", 64)
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var web *http.Server
	web = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/control/stop" || r.Method != http.MethodPost || r.Header.Get("X-Certained-Intent") != "1" || r.Header.Get("X-Certained-Stop-Token") != token {
			http.Error(w, "old control headers required", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Certained-Control", "stop")
		w.WriteHeader(http.StatusAccepted)
		go func() {
			time.Sleep(20 * time.Millisecond)
			_ = os.Remove(tokenPath)
			_ = web.Close()
		}()
	})}
	go func() { _ = web.Serve(listener) }()
	defer web.Close()
	if err := stopServe([]string{"-http", address}); err != nil {
		t.Fatal(err)
	}
}
