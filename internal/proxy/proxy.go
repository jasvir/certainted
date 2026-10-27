package proxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/observe"
)

type Submitter interface {
	Submit(model.DestinationEvent) error
}

type Config struct {
	Scope             observe.Scope
	Vantage           string
	DialTimeout       time.Duration
	IdleTimeout       time.Duration
	MaxTunnelDuration time.Duration
	MaxConnections    int
}

type Proxy struct {
	cfg    Config
	sink   Submitter
	slots  chan struct{}
	server *http.Server
	active sync.Map
}

func New(sink Submitter, cfg Config) *Proxy {
	if cfg.Vantage == "" {
		cfg.Vantage = "local"
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 8 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 2 * time.Minute
	}
	if cfg.MaxTunnelDuration <= 0 {
		cfg.MaxTunnelDuration = 10 * time.Minute
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = 128
	}
	p := &Proxy{cfg: cfg, sink: sink, slots: make(chan struct{}, cfg.MaxConnections)}
	p.server = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return p
}

func (p *Proxy) Serve(l net.Listener) error { return p.server.Serve(l) }
func (p *Proxy) Shutdown(ctx context.Context) error {
	err := p.server.Shutdown(ctx)
	p.active.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
	return err
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT tunnels are supported", http.StatusMethodNotAllowed)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "connection limit reached", http.StatusServiceUnavailable)
		return
	}
	if r.URL == nil || r.URL.User != nil || strings.ContainsAny(r.Host, "/@?#\r\n") {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	host, portText, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "CONNECT target must include port", http.StatusBadRequest)
		return
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		http.Error(w, "invalid target port", http.StatusBadRequest)
		return
	}
	event, err := observe.Normalize(model.DestinationEvent{Time: time.Now().UTC(), Collector: "connect", Vantage: p.cfg.Vantage, Hostname: host, Port: port})
	if err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	scoped, err := p.cfg.Scope.Resolve(r.Context(), event)
	if err != nil {
		http.Error(w, "target outside policy", http.StatusForbidden)
		return
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), p.cfg.DialTimeout)
	dst, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(scoped.IP, strconv.Itoa(port)))
	cancel()
	if err != nil {
		http.Error(w, "target connection failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = dst.Close()
		http.Error(w, "CONNECT unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		_ = dst.Close()
		return
	}
	p.active.Store(client, struct{}{})
	defer p.active.Delete(client)
	defer client.Close()
	defer dst.Close()
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	// This metadata is all the collector emits. The application stream below
	// remains opaque, and a failed inspection cannot change the tunnel result.
	if err := p.sink.Submit(scoped); err != nil {
		log.Print("CONNECT destination metadata dropped")
	}
	timer := time.AfterFunc(p.cfg.MaxTunnelDuration, func() { _ = client.Close(); _ = dst.Close() })
	defer timer.Stop()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyOpaque(dst, client, rw.Reader, p.cfg.IdleTimeout); closeWrite(dst) }()
	go func() { defer wg.Done(); copyOpaque(client, dst, dst, p.cfg.IdleTimeout); closeWrite(client) }()
	wg.Wait()
}

type deadlineReader struct {
	conn   net.Conn
	reader io.Reader
	idle   time.Duration
}

func (d deadlineReader) Read(b []byte) (int, error) {
	_ = d.conn.SetReadDeadline(time.Now().Add(d.idle))
	return d.reader.Read(b)
}
func copyOpaque(dst net.Conn, src net.Conn, reader io.Reader, idle time.Duration) {
	// io.Copy uses no application-layer parser and never retains tunneled bytes.
	_, _ = io.Copy(dst, deadlineReader{conn: src, reader: reader, idle: idle})
}
func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	} else {
		_ = conn.Close()
	}
}
