package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/share"
	"github.com/jasvir/certainted/internal/store"
)

type Server struct {
	DB                    *store.Store
	Assets                fs.FS
	probeExportByteBudget int64
	requestShutdown       func()
	shutdownToken         string
	Sharing               *share.Client
}

const defaultProbeExportByteBudget int64 = 32 << 20

func New(db *store.Store, assets fs.FS) http.Handler {
	return &Server{DB: db, Assets: assets, probeExportByteBudget: defaultProbeExportByteBudget}
}

// NewWithShutdown enables the local CLI control request for a live serve process.
// Handlers created with New do not expose this control route.
func NewWithShutdown(db *store.Store, assets fs.FS, token string, shutdown func()) http.Handler {
	return &Server{DB: db, Assets: assets, probeExportByteBudget: defaultProbeExportByteBudget, requestShutdown: shutdown, shutdownToken: token}
}

// NewWithSharing enables the opt-in local bridge to the community service.
// Other constructors keep all sharing routes unavailable.
func NewWithSharing(db *store.Store, assets fs.FS, token string, shutdown func(), client *share.Client) http.Handler {
	return &Server{DB: db, Assets: assets, probeExportByteBudget: defaultProbeExportByteBudget, requestShutdown: shutdown, shutdownToken: token, Sharing: client}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
	if !localHost(r.Host) {
		http.Error(w, "local hostname required", http.StatusForbidden)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if !apiFetchAllowed(r) {
			http.Error(w, "cross-origin API requests are not supported", http.StatusForbidden)
			return
		}
		s.api(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := "ui/index.html"
	switch r.URL.Path {
	case "/", "/index.html":
	case "/styles.css":
		name = "ui/styles.css"
	case "/app.js":
		name = "ui/dist/app.js"
	case "/sir-tainted-mark.svg":
		name = "ui/sir-tainted-mark.svg"
	case "/favicon.svg":
		name = "ui/favicon.svg"
	default:
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(s.Assets, name)
	if err != nil {
		http.Error(w, "dashboard asset missing", http.StatusInternalServerError)
		return
	}
	switch r.URL.Path {
	case "/styles.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case "/app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case "/sir-tainted-mark.svg", "/favicon.svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	_, _ = w.Write(b)
}

// Browsers set Sec-Fetch-Site; direct CLI requests commonly omit it. API
// responses contain sensitive local inventory, and large exports are costly
// even when cross-origin JavaScript cannot read their response bodies.
func apiFetchAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
	default:
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || u.Host != r.Host {
			return false
		}
	}
	return true
}

func localHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, err error) { http.Error(w, err.Error(), http.StatusBadRequest) }
func limit(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if n <= 0 {
		return 1000
	}
	if n > 10000 {
		return 10000
	}
	return n
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/api/control/stop" && r.Method == http.MethodPost {
		s.stop(w, r)
		return
	}
	if path == "/api/revocations/import" && r.Method == http.MethodPost {
		s.importCRL(w, r)
		return
	}
	if path == "/api/watches/import" && r.Method == http.MethodPost {
		s.importWatches(w, r)
		return
	}
	if path == "/api/watches" && r.Method == http.MethodPost {
		s.addWatch(w, r)
		return
	}
	if path == "/api/community/mode" && r.Method == http.MethodPost {
		s.communityMode(w, r)
		return
	}
	if path == "/api/community/share" && r.Method == http.MethodPost {
		s.communityShare(w, r)
		return
	}
	if strings.HasPrefix(path, "/api/watches/") && r.Method == http.MethodDelete {
		s.deleteWatch(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var v any
	var err error
	switch path {
	case "/api/stats":
		v, err = s.DB.Stats()
	case "/api/destinations":
		v, err = s.DB.ListDestinations(limit(r))
	case "/api/probes":
		v, err = s.DB.ListProbes(limit(r))
	case "/api/cas":
		v, err = s.DB.CAInventory()
	case "/api/watches":
		v, err = s.DB.ListWatches()
	case "/api/incidents":
		v, err = store.BuiltinIncidentManifest()
	case "/api/findings":
		var f store.FindingFilter
		f, err = parseFindingFilter(r)
		if err == nil {
			v, err = s.DB.ListFindings(f)
		}
	case "/api/alerts":
		var f store.FindingFilter
		f, err = parseFindingFilter(r)
		if err == nil {
			v, err = s.DB.ListAlerts(f)
		}
	case "/api/revocations/crls":
		v, err = s.DB.ListCRLs()
	case "/api/revocations/findings":
		var f store.RevocationFindingFilter
		f, err = parseRevocationFilter(r)
		if err == nil {
			v, err = s.DB.ListRevocationFindings(f)
		}
	case "/api/community/preview":
		if s.Sharing == nil {
			http.NotFound(w, r)
			return
		}
		v, err = s.Sharing.Preview(s.DB)
	default:
		if strings.HasPrefix(path, "/api/export/") {
			s.export(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, v)
}

func decodeCommunityJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	if !mutationAllowed(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("same-origin JSON request with explicit intent required")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (s *Server) communityMode(w http.ResponseWriter, r *http.Request) {
	if s.Sharing == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if err := decodeCommunityJSON(w, r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	settings, err := s.Sharing.SetMode(s.DB, body.Mode)
	if err != nil {
		problem(w, err)
		return
	}
	writeJSON(w, settings)
}

func (s *Server) communityShare(w http.ResponseWriter, r *http.Request) {
	if s.Sharing == nil {
		http.NotFound(w, r)
		return
	}
	var body struct {
		ID       string `json:"id"`
		ReportID string `json:"report_id"`
	}
	if err := decodeCommunityJSON(w, r, &body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 9*time.Second)
	defer cancel()
	result, err := s.Sharing.ShareID(ctx, s.DB, body.ID, body.ReportID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.NotFound(w, r)
			return
		}
		if errors.Is(err, share.ErrPreviewChanged) {
			http.Error(w, "report changed; refresh the preview before sharing", http.StatusConflict)
			return
		}
		if errors.Is(err, share.ErrPreviewRequired) {
			problem(w, err)
			return
		}
		// Local eligibility and remote delivery can both fail; return a generic
		// error so private source details never appear in browser/network logs.
		http.Error(w, "report was not shared; check eligibility and community availability", http.StatusBadGateway)
		return
	}
	writeJSON(w, result)
}

func (s *Server) stop(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Certainted-Stop-Token")
	if token == "" {
		token = r.Header.Get("X-Certained-Stop-Token") // Previous CLI versions.
	}
	if !mutationAllowed(r) || s.shutdownToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.shutdownToken)) != 1 {
		http.Error(w, "authorized local control request required", http.StatusForbidden)
		return
	}
	if s.requestShutdown == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Certainted-Control", "stop")
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, `{"status":"stopping"}`+"\n")
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	// Respond before cancellation: graceful shutdown waits for this handler.
	go s.requestShutdown()
}

func parseFindingFilter(r *http.Request) (store.FindingFilter, error) {
	q := r.URL.Query()
	f := store.FindingFilter{Limit: limit(r), Evidence: q.Get("evidence")}
	var err error
	if q.Get("watch_id") != "" {
		f.WatchID, err = strconv.ParseInt(q.Get("watch_id"), 10, 64)
		if err != nil {
			return f, err
		}
	}
	if q.Get("destination_id") != "" {
		f.DestinationID, err = strconv.ParseInt(q.Get("destination_id"), 10, 64)
		if err != nil {
			return f, err
		}
	}
	if q.Get("from") != "" {
		t, e := time.Parse(time.RFC3339, q.Get("from"))
		if e != nil {
			return f, e
		}
		f.From = &t
	}
	if q.Get("to") != "" {
		t, e := time.Parse(time.RFC3339, q.Get("to"))
		if e != nil {
			return f, e
		}
		f.To = &t
	}
	return f, nil
}

func parseRevocationFilter(r *http.Request) (store.RevocationFindingFilter, error) {
	q := r.URL.Query()
	f := store.RevocationFindingFilter{Limit: limit(r), Evidence: q.Get("evidence")}
	var err error
	if q.Get("crl_id") != "" {
		f.CRLID, err = strconv.ParseInt(q.Get("crl_id"), 10, 64)
		if err != nil || f.CRLID < 1 {
			return f, errors.New("invalid crl_id")
		}
	}
	if q.Get("destination_id") != "" {
		f.DestinationID, err = strconv.ParseInt(q.Get("destination_id"), 10, 64)
		if err != nil || f.DestinationID < 1 {
			return f, errors.New("invalid destination_id")
		}
	}
	if q.Get("from") != "" {
		t, e := time.Parse(time.RFC3339, q.Get("from"))
		if e != nil {
			return f, e
		}
		f.From = &t
	}
	if q.Get("to") != "" {
		t, e := time.Parse(time.RFC3339, q.Get("to"))
		if e != nil {
			return f, e
		}
		f.To = &t
	}
	if f.Evidence != "" && f.Evidence != "direct" && f.Evidence != "candidate" {
		return f, errors.New("evidence must be direct or candidate")
	}
	return f, nil
}

func mutationAllowed(r *http.Request) bool {
	if r.Header.Get("X-Certainted-Intent") != "1" && r.Header.Get("X-Certained-Intent") != "1" {
		return false
	}
	if !apiFetchAllowed(r) {
		return false
	}
	return true
}

func (s *Server) addWatch(w http.ResponseWriter, r *http.Request) {
	if !mutationAllowed(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "same-origin JSON request required", http.StatusForbidden)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 16<<10)
	defer body.Close()
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	var entry model.WatchEntry
	if err := dec.Decode(&entry); err != nil {
		problem(w, err)
		return
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		problem(w, errors.New("trailing JSON"))
		return
	}
	id, err := s.DB.AddWatch(entry)
	if err != nil {
		problem(w, err)
		return
	}
	entry.ID = id
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, entry)
}

func (s *Server) deleteWatch(w http.ResponseWriter, r *http.Request) {
	if !mutationAllowed(r) {
		http.Error(w, "same-origin request required", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, "/api/watches/"), 10, 64)
	if err != nil || id < 1 {
		problem(w, errors.New("invalid watch id"))
		return
	}
	if err := s.DB.DeleteWatch(id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/export/")
	exportLimit, err := parseExportLimit(r)
	if err != nil {
		problem(w, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "csv" {
		problem(w, errors.New("format must be json or csv"))
		return
	}
	var v any
	switch name {
	case "destinations":
		v, err = s.DB.ListDestinations(exportLimit)
	case "probes":
		budget := s.probeExportByteBudget
		if budget <= 0 {
			budget = defaultProbeExportByteBudget
		}
		v, err = s.DB.ListProbesBounded(exportLimit, budget)
	case "cas":
		v, err = s.DB.CAInventory()
	case "watches":
		v, err = s.DB.ListWatches()
	case "findings":
		var f store.FindingFilter
		f, err = parseFindingFilter(r)
		if err == nil {
			f.Limit = exportLimit
			v, err = s.DB.ListFindings(f)
		}
	case "revocations":
		var f store.RevocationFindingFilter
		f, err = parseRevocationFilter(r)
		if err == nil {
			f.Limit = exportLimit
			v, err = s.DB.ListRevocationFindings(f)
		}
	case "crls":
		v, err = s.DB.ListCRLs()
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		if errors.Is(err, store.ErrExportTooLarge) {
			http.Error(w, "probe export exceeds the local byte budget; request fewer recent records with ?limit=N", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "export failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=certainted-%s.%s", name, format))
	if format == "json" {
		writeJSON(w, v)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	if err := writeCSV(w, v); err != nil {
		return
	}
}

func parseExportLimit(r *http.Request) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 100000, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100000 {
		return 0, errors.New("export limit must be between 1 and 100000")
	}
	return n, nil
}

func writeCSV(w io.Writer, data any) error {
	c := csv.NewWriter(w)
	rows := reflect.ValueOf(data)
	if rows.Kind() != reflect.Slice {
		return errors.New("export expects list")
	}
	typ := rows.Type().Elem()
	headers := make([]string, 0, typ.NumField())
	fields := make([]int, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		if tag == "-" {
			continue
		}
		if tag == "" {
			tag = f.Name
		}
		headers = append(headers, tag)
		fields = append(fields, i)
	}
	if err := c.Write(headers); err != nil {
		return err
	}
	for i := 0; i < rows.Len(); i++ {
		row := make([]string, len(fields))
		for j, k := range fields {
			x := rows.Index(i).Field(k).Interface()
			switch v := x.(type) {
			case string:
				row[j] = csvSafe(v)
			case int, int64, bool:
				row[j] = fmt.Sprint(v)
			case time.Time:
				row[j] = v.Format(time.RFC3339Nano)
			default:
				b, _ := json.Marshal(x)
				row[j] = string(b)
			}
		}
		if err := c.Write(row); err != nil {
			return err
		}
	}
	c.Flush()
	return c.Error()
}

func csvSafe(s string) string {
	first := strings.TrimLeft(s, " \t\r\n\v\f")
	if first != "" && strings.ContainsRune("=+-@", rune(first[0])) {
		return "'" + s
	}
	return s
}
