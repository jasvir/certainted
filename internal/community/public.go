package community

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxReportBytes   = 8 << 10
	maxPublicReports = 25000
	reportRetention  = 365 * 24 * time.Hour
	defaultPageSize  = 100
	maxPageSize      = 200
	// Fixed-width UTC timestamps retain chronological order in SQLite TEXT.
	dbTimeLayout = "2006-01-02T15:04:05.000000000Z"
)

const publicSchema = `
CREATE TABLE IF NOT EXISTS community_reports (
 id TEXT PRIMARY KEY,
 received_at TEXT NOT NULL,
 kind TEXT NOT NULL,
 evidence TEXT NOT NULL,
 observed_day TEXT NOT NULL,
 report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS community_reports_received ON community_reports(received_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS community_reports_kind_received ON community_reports(kind,received_at DESC,id DESC);
`

type PublicStore struct {
	db        *sql.DB
	pruneMu   sync.Mutex
	lastPrune time.Time
}

// NewPublicStore opens a database dedicated to publicly submitted claims.
// It must never be pointed at the local private inventory database.
func NewPublicStore(path string) (*PublicStore, error) {
	if path == "" || strings.HasPrefix(path, "file:") {
		return nil, errors.New("a plain public database path is required")
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("public database path must not be a symbolic link")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0600); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One connection also makes :memory: databases and PRAGMA state predictable.
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{"PRAGMA busy_timeout = 5000", "PRAGMA journal_mode = WAL"} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("public sqlite setup: %w", err)
		}
	}
	if _, err := db.Exec(publicSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("public sqlite schema: %w", err)
	}
	store := &PublicStore{db: db}
	if err := store.pruneIfDue(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *PublicStore) Close() error { return s.db.Close() }

// pruneIfDue removes expired reports on startup and on active services at
// least once per day when a listing or stats request arrives.
func (s *PublicStore) pruneIfDue(ctx context.Context) error {
	s.pruneMu.Lock()
	defer s.pruneMu.Unlock()
	now := time.Now().UTC()
	if !s.lastPrune.IsZero() && now.Sub(s.lastPrune) < 24*time.Hour {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM community_reports WHERE received_at < ?`, now.Add(-reportRetention).Format(dbTimeLayout)); err != nil {
		return err
	}
	s.lastPrune = now
	return nil
}

// PublishedReport carries a server receipt time and an explicit trust label.
// That label never changes merely because several clients submit the same ID.
type PublishedReport struct {
	ID          string    `json:"id"`
	ReceivedAt  time.Time `json:"received_at"`
	TrustStatus string    `json:"trust_status"`
	Report
}

// Add validates and deduplicates a claim. It never resolves the hostname,
// fetches CRLs, or performs a TLS probe from the public server.
func (s *PublicStore) Add(ctx context.Context, r Report) (PublishedReport, bool, error) {
	if err := ValidateReport(r); err != nil {
		return PublishedReport{}, false, err
	}
	r = canonicalReport(r)
	id := ReportID(r)
	data, err := json.Marshal(r)
	if err != nil {
		return PublishedReport{}, false, err
	}
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PublishedReport{}, false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM community_reports WHERE received_at < ?`, now.Add(-reportRetention).Format(dbTimeLayout)); err != nil {
		return PublishedReport{}, false, err
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO community_reports(id,received_at,kind,evidence,observed_day,report_json) VALUES(?,?,?,?,?,?)`,
		id, now.Format(dbTimeLayout), r.Kind, r.Evidence, r.ObservedDay, string(data))
	if err != nil {
		return PublishedReport{}, false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return PublishedReport{}, false, err
	}
	if inserted == 1 {
		// Protect the just-accepted ID when records share a receipt timestamp.
		// A plain ORDER BY/LIMIT can otherwise discard the new row and turn a
		// successful insert into a failed receipt lookup.
		if _, err = tx.ExecContext(ctx, `DELETE FROM community_reports WHERE id IN (
		 SELECT id FROM community_reports WHERE id<>? ORDER BY received_at DESC,id DESC LIMIT -1 OFFSET ?
		)`, id, maxPublicReports-1); err != nil {
			return PublishedReport{}, false, err
		}
	}
	var received string
	if err = tx.QueryRowContext(ctx, `SELECT received_at FROM community_reports WHERE id=?`, id).Scan(&received); err != nil {
		return PublishedReport{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return PublishedReport{}, false, err
	}
	when, err := time.Parse(time.RFC3339Nano, received)
	if err != nil {
		return PublishedReport{}, false, err
	}
	return PublishedReport{ID: id, ReceivedAt: when, TrustStatus: "unverified", Report: r}, inserted == 1, nil
}

type PublicFilter struct {
	Kind     string
	Evidence string
	Limit    int
}

func (s *PublicStore) List(ctx context.Context, f PublicFilter) ([]PublishedReport, error) {
	if err := s.pruneIfDue(ctx); err != nil {
		return nil, err
	}
	if f.Kind != "" && f.Kind != "crl" && f.Kind != "watch" {
		return nil, errors.New("kind must be crl or watch")
	}
	if f.Evidence != "" && f.Evidence != "direct" && f.Evidence != "candidate" {
		return nil, errors.New("evidence must be direct or candidate")
	}
	if f.Limit <= 0 {
		f.Limit = defaultPageSize
	}
	if f.Limit > maxPageSize {
		f.Limit = maxPageSize
	}
	query := `SELECT id,received_at,report_json FROM community_reports WHERE 1=1`
	var args []any
	if f.Kind != "" {
		query += ` AND kind=?`
		args = append(args, f.Kind)
	}
	if f.Evidence != "" {
		query += ` AND evidence=?`
		args = append(args, f.Evidence)
	}
	query += ` ORDER BY received_at DESC,id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reports := make([]PublishedReport, 0)
	for rows.Next() {
		var p PublishedReport
		var received, data string
		if err := rows.Scan(&p.ID, &received, &data); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(data), &p.Report); err != nil {
			return nil, err
		}
		p.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return nil, err
		}
		p.TrustStatus = "unverified"
		reports = append(reports, p)
	}
	return reports, rows.Err()
}

type PublicStats struct {
	Reports          int64  `json:"reports"`
	CRLReports       int64  `json:"crl_reports"`
	WatchReports     int64  `json:"watch_reports"`
	LatestReceivedAt string `json:"latest_received_at,omitempty"`
}

func (s *PublicStore) Stats(ctx context.Context) (PublicStats, error) {
	if err := s.pruneIfDue(ctx); err != nil {
		return PublicStats{}, err
	}
	var stats PublicStats
	var latest sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
	 COALESCE(SUM(CASE WHEN kind='crl' THEN 1 ELSE 0 END),0),
	 COALESCE(SUM(CASE WHEN kind='watch' THEN 1 ELSE 0 END),0),
	 MAX(received_at) FROM community_reports`).Scan(&stats.Reports, &stats.CRLReports, &stats.WatchReports, &latest)
	if latest.Valid {
		stats.LatestReceivedAt = latest.String
	}
	return stats, err
}

type publicHandler struct {
	store  *PublicStore
	assets fs.FS
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewPublicHandler exposes only public reports and static public assets.
// The local inventory/API handler must never be placed behind this service.
func NewPublicHandler(store *PublicStore, assets fs.FS) http.Handler {
	return &publicHandler{store: store, assets: assets, tokens: 60, last: time.Now()}
}

func (h *publicHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/api/v1/reports":
		switch r.Method {
		case http.MethodPost:
			h.postReport(w, r)
		case http.MethodGet:
			h.listReports(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case "/api/v1/stats":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		stats, err := h.store.Stats(r.Context())
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		writePublicJSON(w, stats)
	case "/", "/index.html", "/styles.css", "/app.js", "/sir-tainted-mark.svg", "/favicon.svg":
		h.asset(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *publicHandler) postReport(w http.ResponseWriter, r *http.Request) {
	if !sameOriginIfBrowser(r) {
		http.Error(w, "cross-origin browser submission rejected", http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
		return
	}
	if !h.allowSubmission() {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "submission rate limit reached", http.StatusTooManyRequests)
		return
	}
	if r.ContentLength > maxReportBytes {
		http.Error(w, "report is too large", http.StatusRequestEntityTooLarge)
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxReportBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			http.Error(w, "report is too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid report JSON", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		http.Error(w, "trailing JSON", http.StatusBadRequest)
		return
	}
	p, inserted, err := h.store.Add(r.Context(), report)
	if err != nil {
		if err := ValidateReport(report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "storage failed", http.StatusInternalServerError)
		return
	}
	status := "duplicate"
	code := http.StatusOK
	if inserted {
		status = "accepted"
		code = http.StatusCreated
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(struct {
		ID          string    `json:"id"`
		Status      string    `json:"status"`
		TrustStatus string    `json:"trust_status"`
		ReceivedAt  time.Time `json:"received_at"`
	}{p.ID, status, p.TrustStatus, p.ReceivedAt})
}

func (h *publicHandler) allowSubmission() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.tokens += now.Sub(h.last).Seconds() * 5 // five submissions/second, 60 burst
	if h.tokens > 60 {
		h.tokens = 60
	}
	h.last = now
	if h.tokens < 1 {
		return false
	}
	h.tokens--
	return true
}

func sameOriginIfBrowser(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
	default:
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host != r.Host {
			return false
		}
	}
	return true
}

func (h *publicHandler) listReports(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := defaultPageSize
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, "limit must be positive", http.StatusBadRequest)
			return
		}
		limit = n
	}
	reports, err := h.store.List(r.Context(), PublicFilter{Kind: q.Get("kind"), Evidence: q.Get("evidence"), Limit: limit})
	if err != nil {
		if q.Get("kind") != "" && q.Get("kind") != "crl" && q.Get("kind") != "watch" || q.Get("evidence") != "" && q.Get("evidence") != "direct" && q.Get("evidence") != "candidate" {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writePublicJSON(w, struct {
		Reports []PublishedReport `json:"reports"`
	}{reports})
}

func (h *publicHandler) asset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.assets == nil {
		http.Error(w, "public assets unavailable", http.StatusInternalServerError)
		return
	}
	name := "publicui/index.html"
	contentType := "text/html; charset=utf-8"
	switch r.URL.Path {
	case "/styles.css":
		name, contentType = "publicui/styles.css", "text/css; charset=utf-8"
	case "/app.js":
		name, contentType = "publicui/dist/app.js", "text/javascript; charset=utf-8"
	case "/sir-tainted-mark.svg":
		name, contentType = "ui/sir-tainted-mark.svg", "image/svg+xml"
	case "/favicon.svg":
		name, contentType = "ui/favicon.svg", "image/svg+xml"
	}
	data, err := fs.ReadFile(h.assets, name)
	if err != nil {
		http.Error(w, "public asset missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func writePublicJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(data)
}
