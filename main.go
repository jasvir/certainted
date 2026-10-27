package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jasvir/certainted/internal/collector"
	"github.com/jasvir/certainted/internal/community"
	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/observe"
	"github.com/jasvir/certainted/internal/probe"
	"github.com/jasvir/certainted/internal/proxy"
	"github.com/jasvir/certainted/internal/revocation"
	"github.com/jasvir/certainted/internal/server"
	"github.com/jasvir/certainted/internal/share"
	"github.com/jasvir/certainted/internal/store"
)

//go:embed ui/index.html ui/styles.css ui/dist/app.js ui/sir-tainted-mark.svg ui/favicon.svg
var dashboard embed.FS

//go:embed publicui/index.html publicui/styles.css publicui/dist/app.js ui/sir-tainted-mark.svg ui/favicon.svg
var publicDashboard embed.FS

type common struct {
	db, allowCIDR, ports, trustStore, vantage string
	allowPrivate                              bool
	workers, queue, cacheEntries              int
	timeout, rate, cacheTTL, refresh          time.Duration
}

const (
	defaultInventoryDB = "certainted.db"
	legacyInventoryDB  = "certained.db" // Existing inventories keep working after the name change.
)

func defaultInventoryDBPath() string {
	return preferredInventoryDBPath(defaultInventoryDB, legacyInventoryDB)
}

// openLocalInventory installs bundled incident watches for CLI and dashboard
// inventories. Store.Open remains unseeded for callers that need a blank store.
func openLocalInventory(path string) (*store.Store, error) {
	db, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := db.SeedBuiltinIncidentWatches(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("seed built-in incident watches: %w", err)
	}
	return db, nil
}

func preferredInventoryDBPath(current, previous string) string {
	if _, err := os.Lstat(current); err == nil || !errors.Is(err, os.ErrNotExist) {
		return current
	}
	if info, err := os.Lstat(previous); err == nil && info.Mode().IsRegular() {
		return previous
	}
	return current
}

func (c *common) flags(fs *flag.FlagSet) {
	fs.StringVar(&c.db, "db", defaultInventoryDBPath(), "SQLite inventory path")
	fs.StringVar(&c.allowCIDR, "allow-cidr", "", "comma-separated CIDRs permitted for probes and tunnels")
	fs.BoolVar(&c.allowPrivate, "allow-private", false, "permit private global-unicast IPs (use allow-cidr for narrower scope)")
	fs.StringVar(&c.ports, "ports", "443,8443", "comma-separated allowed destination ports")
	fs.StringVar(&c.trustStore, "trust-store", "", "PEM trust store for candidate-path validation")
	fs.StringVar(&c.vantage, "vantage", "local", "network vantage label")
	fs.IntVar(&c.workers, "workers", 4, "concurrent probe workers, max 64")
	fs.IntVar(&c.queue, "queue", 256, "bounded observation queue")
	fs.DurationVar(&c.timeout, "timeout", 8*time.Second, "independent probe timeout")
	fs.DurationVar(&c.rate, "rate", 200*time.Millisecond, "minimum interval between probe starts")
	fs.DurationVar(&c.cacheTTL, "cache-ttl", 15*time.Minute, "recent probe reuse interval per destination and vantage")
	fs.IntVar(&c.cacheEntries, "cache-entries", 10000, "maximum recent probe cache entries")
	fs.DurationVar(&c.refresh, "refresh", time.Hour, "scheduled independent re-probe interval; 0 disables")
}

func (c common) scope() (observe.Scope, error) {
	ports, err := observe.ParsePorts(c.ports)
	if err != nil || len(ports) == 0 {
		return observe.Scope{}, errors.New("at least one valid destination port required")
	}
	s := observe.Scope{Ports: ports, AllowPrivate: c.allowPrivate}
	for _, piece := range strings.Split(c.allowCIDR, ",") {
		if strings.TrimSpace(piece) == "" {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(piece))
		if err != nil {
			return s, fmt.Errorf("invalid allow-cidr %q", piece)
		}
		s.AllowCIDRs = append(s.AllowCIDRs, p.Masked())
	}
	return s, nil
}

func (c common) observer(ctx context.Context, db *store.Store) (*observe.Observer, error) {
	scope, err := c.scope()
	if err != nil {
		return nil, err
	}
	pc := probe.Config{Timeout: c.timeout, MaxCertificates: 16, MaxCertificateBytes: 256 << 10}
	if c.trustStore != "" {
		pem, err := os.ReadFile(c.trustStore)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("trust store contains no valid PEM certificates")
		}
		sum := sha256.Sum256(pem)
		pc.TrustStorePEM = pem
		pc.TrustStoreName = fmt.Sprintf("custom PEM sha256:%x", sum)
	}
	pc.AllowIP = func(ip net.IP) bool { a, ok := netip.AddrFromSlice(ip); return ok && scope.AllowedIP(a) }
	return observe.New(ctx, db, observe.Config{Scope: scope, Probe: pc, Workers: c.workers, QueueSize: c.queue, MinProbeInterval: c.rate, CacheTTL: c.cacheTTL, MaxCacheEntries: c.cacheEntries, RefreshInterval: c.refresh, OnStorageError: func() { log.Print("observation storage failed") }}), nil
}

func loopbackListen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("listener must have host:port: %w", err)
	}
	if host != "localhost" {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() {
			return nil, errors.New("listeners are loopback-only in Phase 1")
		}
	}
	return net.Listen("tcp", addr)
}

const defaultProxyAddr = "127.0.0.1:8080"

type serveProxyFlags struct {
	address  string
	disabled bool
}

func (p *serveProxyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&p.address, "proxy", defaultProxyAddr, "loopback CONNECT listener")
	fs.BoolVar(&p.disabled, "noproxy", false, "disable the CONNECT listener")
}

func (p serveProxyFlags) listenAddress(fs *flag.FlagSet) (string, error) {
	proxyExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "proxy" {
			proxyExplicit = true
		}
	})
	if p.disabled {
		if proxyExplicit {
			return "", errors.New("-proxy and -noproxy cannot be used together")
		}
		return "", nil
	}
	if p.address == "" {
		return "", errors.New("-proxy requires an address; use -noproxy to disable the CONNECT listener")
	}
	return p.address, nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	var c common
	c.flags(fs)
	httpAddr := fs.String("http", "127.0.0.1:8787", "dashboard/API listener")
	var proxyFlags serveProxyFlags
	proxyFlags.register(fs)
	maxConns := fs.Int("max-connections", 128, "maximum simultaneous CONNECT tunnels")
	idle := fs.Duration("tunnel-idle", 2*time.Minute, "tunnel idle timeout")
	maxDuration := fs.Duration("tunnel-max", 10*time.Minute, "maximum tunnel duration")
	retention := fs.Int("retention-days", 365, "delete evidence older than this many days; 0 disables")
	shareURL := fs.String("share-url", "https://certainted.com/api/v1/reports", "public report receiver (certainted.com HTTPS or loopback HTTP for tests)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	proxyAddr, err := proxyFlags.listenAddress(fs)
	if err != nil {
		return err
	}
	shareClient, err := share.NewClient(*shareURL)
	if err != nil {
		return err
	}
	if *retention < 0 {
		return errors.New("retention-days cannot be negative")
	}
	scope, err := c.scope()
	if err != nil {
		return err
	}
	db, err := openLocalInventory(c.db)
	if err != nil {
		return err
	}
	defer db.Close()
	if *retention > 0 {
		if err := db.DeleteBefore(time.Now().UTC().AddDate(0, 0, -*retention)); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	observer, err := c.observer(ctx, db)
	if err != nil {
		return err
	}
	defer observer.Close()
	webListener, err := loopbackListen(*httpAddr)
	if err != nil {
		return err
	}
	controlAddr := *httpAddr
	if _, requestedPort, _ := net.SplitHostPort(*httpAddr); requestedPort == "0" {
		controlAddr = webListener.Addr().String()
	}
	stopToken, removeStopToken, err := createStopToken(controlAddr)
	if err != nil {
		_ = webListener.Close()
		return err
	}
	defer removeStopToken()
	web := &http.Server{Handler: server.NewWithSharing(db, dashboard, stopToken, stop, shareClient), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	errCh := make(chan error, 2)
	go func() { errCh <- web.Serve(webListener) }()
	shareDone := make(chan struct{})
	go func() {
		defer close(shareDone)
		shareClient.Run(ctx, db)
	}()
	defer func() {
		stop()
		<-shareDone
	}()
	log.Printf("dashboard: http://%s", webListener.Addr())
	var px *proxy.Proxy
	if proxyAddr != "" {
		proxyListener, err := loopbackListen(proxyAddr)
		if err != nil {
			_ = web.Shutdown(context.Background())
			return err
		}
		px = proxy.New(observer, proxy.Config{Scope: scope, Vantage: c.vantage, DialTimeout: c.timeout, IdleTimeout: *idle, MaxTunnelDuration: *maxDuration, MaxConnections: *maxConns})
		go func() { errCh <- px.Serve(proxyListener) }()
		log.Printf("CONNECT adapter: %s", proxyListener.Addr())
	}
	var pruneTick *time.Ticker
	if *retention > 0 {
		pruneTick = time.NewTicker(24 * time.Hour)
		defer pruneTick.Stop()
	}
	for {
		var prune <-chan time.Time
		if pruneTick != nil {
			prune = pruneTick.C
		}
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = web.Shutdown(shutdownCtx)
			if px != nil {
				_ = px.Shutdown(shutdownCtx)
			}
			return nil
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				continue
			}
			return err
		case <-prune:
			if err := db.DeleteBefore(time.Now().UTC().AddDate(0, 0, -*retention)); err != nil {
				log.Printf("retention cleanup failed: %v", err)
			}
		}
	}
}

// publicServe exposes only redacted, unauthenticated community claims. It has
// its own database and handler, so local inventory and proxy routes cannot be
// reached through the public reverse proxy.
func publicServe(args []string) error {
	fs := flag.NewFlagSet("public-serve", flag.ContinueOnError)
	dbPath := fs.String("db", "community.db", "separate public report SQLite path")
	httpAddr := fs.String("http", "127.0.0.1:8790", "loopback public dashboard listener")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("public-serve does not accept positional arguments")
	}
	listener, err := loopbackListen(*httpAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	db, err := community.NewPublicStore(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	web := &http.Server{
		Handler:           community.NewPublicHandler(db, publicDashboard),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- web.Serve(listener) }()
	log.Printf("public dashboard: http://%s", listener.Addr())
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return web.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func stopServe(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	httpAddr := fs.String("http", "127.0.0.1:8787", "local dashboard/API listener of the instance to stop")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("stop does not accept positional arguments")
	}
	host, portText, err := net.SplitHostPort(*httpAddr)
	if err != nil {
		return fmt.Errorf("invalid dashboard address: %w", err)
	}
	if host != "localhost" {
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !ip.IsLoopback() {
			return errors.New("stop requires a loopback dashboard address")
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("stop requires a valid dashboard port")
	}
	credentials, err := readStopTokens(*httpAddr)
	if err != nil {
		return err
	}
	target := (&url.URL{Scheme: "http", Host: *httpAddr, Path: "/api/control/stop"}).String()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("stop does not follow redirects")
		},
	}
	var tokenPath string
	for _, credential := range credentials {
		req, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Certainted-Intent", "1")
		req.Header.Set("X-Certained-Intent", "1") // Previous CLI versions.
		req.Header.Set("X-Certainted-Stop-Token", credential.token)
		req.Header.Set("X-Certained-Stop-Token", credential.token)
		req.Header.Set("Origin", "http://"+*httpAddr)
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("no running Certainted at %s: %w", *httpAddr, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusAccepted && (resp.Header.Get("X-Certainted-Control") == "stop" || resp.Header.Get("X-Certained-Control") == "stop") {
			tokenPath = credential.path
			break
		}
	}
	if tokenPath == "" {
		return fmt.Errorf("no compatible Certainted stop endpoint at %s (an older running instance must be restarted once)", *httpAddr)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(tokenPath); errors.Is(statErr, os.ErrNotExist) {
			conn, dialErr := net.DialTimeout("tcp", *httpAddr, 150*time.Millisecond)
			if errors.Is(dialErr, syscall.ECONNREFUSED) {
				fmt.Fprintln(os.Stdout, "Certainted stopped.")
				return nil
			}
			if conn != nil {
				_ = conn.Close()
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("shutdown requested, but Certainted did not finish stopping within 10 seconds")
}

type reliableSink struct {
	ctx      context.Context
	observer *observe.Observer
}

func (s reliableSink) Submit(e model.DestinationEvent) error {
	for {
		err := s.observer.Submit(e)
		if err == nil {
			return nil
		}
		if err.Error() != "observation queue full" {
			return err
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func ingest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	var c common
	c.flags(fs)
	file := fs.String("file", "-", "JSON Lines file, or - for standard input")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openLocalInventory(c.db)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c.refresh = 0
	o, err := c.observer(ctx, db)
	if err != nil {
		return err
	}
	defer o.Close()
	var input io.Reader = os.Stdin
	if *file != "-" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}
	count, collectErr := (collector.JSONL{Reader: input}).Collect(ctx, reliableSink{ctx: ctx, observer: o})
	storageErr := o.Wait()
	if collectErr != nil || storageErr != nil {
		if storageErr != nil {
			storageErr = fmt.Errorf("observation storage failed: %w", storageErr)
		}
		return errors.Join(collectErr, storageErr)
	}
	fmt.Fprintf(os.Stderr, "accepted %d destination events\n", count)
	return nil
}

func watch(args []string) error {
	if len(args) == 0 {
		return errors.New("watch requires add, list, or delete")
	}
	action := args[0]
	fs := flag.NewFlagSet("watch "+action, flag.ContinueOnError)
	dbPath := fs.String("db", defaultInventoryDBPath(), "SQLite inventory path")
	name := fs.String("name", "", "human-readable watch name")
	group := fs.String("group", "", "organization or grouping")
	matchType := fs.String("type", "cert_sha256", "cert_sha256, spki_sha256, or name")
	value := fs.String("value", "", "exact fingerprint or name search value")
	status := fs.String("status", "monitored", "manual status label")
	severity := fs.String("severity", "info", "severity label")
	reason := fs.String("reason", "", "reason for watch")
	source := fs.String("source", "manual", "source/reference")
	from := fs.String("from", "", "effective start, RFC3339")
	to := fs.String("to", "", "effective end, RFC3339")
	id := fs.Int64("id", 0, "watch ID for update/delete")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	db, err := openLocalInventory(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	switch action {
	case "list":
		v, err := db.ListWatches()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(v)
	case "delete":
		if *id < 1 {
			return errors.New("delete requires -id")
		}
		return db.DeleteWatch(*id)
	case "add":
		entry := model.WatchEntry{ID: *id, Name: *name, Group: *group, MatchType: *matchType, Value: *value, Status: *status, Severity: *severity, Reason: *reason, Source: *source}
		if *from != "" {
			t, e := time.Parse(time.RFC3339, *from)
			if e != nil {
				return e
			}
			entry.EffectiveFrom = &t
		}
		if *to != "" {
			t, e := time.Parse(time.RFC3339, *to)
			if e != nil {
				return e
			}
			entry.EffectiveTo = &t
		}
		newID, err := db.AddWatch(entry)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, newID)
		return nil
	default:
		return errors.New("watch requires add, list, or delete")
	}
}

// crl imports signed revocation evidence supplied by the operator. It never
// fetches CRLs or issuer certificates from the network.
func crl(args []string) error {
	if len(args) == 0 {
		return errors.New("crl requires import or list")
	}
	action := args[0]
	fs := flag.NewFlagSet("crl "+action, flag.ContinueOnError)
	dbPath := fs.String("db", defaultInventoryDBPath(), "SQLite inventory path")
	file := fs.String("file", "", "PEM or DER CRL file; - for standard input")
	issuer := fs.String("issuer", "", "PEM or DER CRL issuer certificate file")
	source := fs.String("source", "manual file import", "provenance label for imported CRL")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch action {
	case "import":
		if *file == "" || *issuer == "" {
			return errors.New("crl import requires -file and -issuer")
		}
		if *file == "-" && *issuer == "-" {
			return errors.New("CRL and issuer certificate cannot both be read from standard input")
		}
		crlBytes, err := readLimitedInput(*file, 8<<20)
		if err != nil {
			return err
		}
		issuerBytes, err := readLimitedInput(*issuer, 1<<20)
		if err != nil {
			return err
		}
		list, err := revocation.ParseAndVerify(crlBytes, issuerBytes, time.Now().UTC(), revocation.Limits{})
		if err != nil {
			return err
		}
		db, err := openLocalInventory(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		id, err := db.ImportCRL(list, *source)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "imported CRL %d with %d revoked certificates\n", id, len(list.Entries))
		return nil
	case "list":
		db, err := openLocalInventory(*dbPath)
		if err != nil {
			return err
		}
		defer db.Close()
		lists, err := db.ListCRLs()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(lists)
	default:
		return errors.New("crl requires import or list")
	}
}

func readLimitedInput(path string, max int64) ([]byte, error) {
	var input io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		input = f
	}
	b, err := io.ReadAll(io.LimitReader(input, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input exceeds %d bytes", max)
	}
	return b, nil
}

func prune(args []string) error {
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	dbPath := fs.String("db", defaultInventoryDBPath(), "SQLite inventory path")
	before := fs.String("before", "", "delete evidence before YYYY-MM-DD")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *before == "" {
		return errors.New("prune requires -before YYYY-MM-DD")
	}
	t, err := time.Parse("2006-01-02", *before)
	if err != nil {
		return err
	}
	db, err := openLocalInventory(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.DeleteBefore(t)
}

func export(args []string) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	dbPath := fs.String("db", defaultInventoryDBPath(), "SQLite inventory path")
	resource := fs.String("resource", "findings", "findings, revocations, crls, destinations, probes, cas, or watches")
	format := fs.String("format", "json", "json or csv")
	maxRows := fs.Int("limit", 100000, "maximum recent rows to export, 1 through 100000")
	watchID := fs.Int64("watch-id", 0, "filter findings by watch ID")
	from := fs.String("from", "", "filter findings from RFC3339 time")
	to := fs.String("to", "", "filter findings through RFC3339 time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := openLocalInventory(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	u := fmt.Sprintf("http://127.0.0.1/api/export/%s?format=%s&watch_id=%d&limit=%d", *resource, *format, *watchID, *maxRows)
	if *from != "" {
		u += "&from=" + urlQueryEscape(*from)
	}
	if *to != "" {
		u += "&to=" + urlQueryEscape(*to)
	}
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	server.New(db, dashboard).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return fmt.Errorf("export failed: %s", strings.TrimSpace(rec.Body.String()))
	}
	_, err = io.Copy(os.Stdout, rec.Body)
	return err
}

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "public-serve":
		err = publicServe(os.Args[2:])
	case "stop":
		err = stopServe(os.Args[2:])
	case "ingest":
		err = ingest(os.Args[2:])
	case "watch":
		err = watch(os.Args[2:])
	case "crl":
		err = crl(os.Args[2:])
	case "prune":
		err = prune(os.Args[2:])
	case "export":
		err = export(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "certainted:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Certainted: local certificate and revocation observation")
	fmt.Fprintln(os.Stderr, "Usage: certainted serve|public-serve|stop|ingest|crl|watch|export|prune [flags]")
	fmt.Fprintln(os.Stderr, "Run certainted <command> -h for command flags.")
}
