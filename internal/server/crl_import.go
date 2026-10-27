package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/observe"
	"github.com/jasvir/certainted/internal/revocation"
)

const (
	maxImportBody   int64 = 9 << 20
	maxCRLFile      int64 = 8 << 20
	maxIssuerFile   int64 = 256 << 10
	maxCRLURL       int64 = 2048
	maxSource       int64 = 1024
	maxFormValue    int64 = 32
	crlFetchTimeout       = 10 * time.Second
)

// One import at a time bounds simultaneous URL fetches, CRL parsing, watch
// parsing, and historical SQLite reevaluation across local dashboards.
var importSlot = make(chan struct{}, 1)

type importForm struct {
	method string
	crl    []byte
	crlURL string
	issuer []byte
	source string
}

func importProblem(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSON(w, map[string]string{"error": message})
}

func (s *Server) importCRL(w http.ResponseWriter, r *http.Request) {
	if !mutationAllowed(r) {
		importProblem(w, http.StatusForbidden, "same-origin request with X-Certainted-Intent: 1 required")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		importProblem(w, http.StatusUnsupportedMediaType, "multipart/form-data required")
		return
	}
	select {
	case importSlot <- struct{}{}:
		defer func() { <-importSlot }()
	default:
		importProblem(w, http.StatusTooManyRequests, "another CRL import is in progress")
		return
	}
	// net/http can enforce this on a live connection. MaxBytesReader below also
	// bounds fast or synthetic requests, including multipart headers.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBody)
	defer r.Body.Close()
	form, err := readImportForm(r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) || errors.Is(err, errImportTooLarge) {
			importProblem(w, http.StatusRequestEntityTooLarge, "CRL import exceeds its size limit")
		} else {
			importProblem(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	if form.method == "file" && len(form.crl) == 0 {
		importProblem(w, http.StatusBadRequest, "CRL file is required")
		return
	}
	if form.method == "url" && form.crlURL == "" {
		importProblem(w, http.StatusBadRequest, "CRL URL is required")
		return
	}
	if len(form.issuer) == 0 {
		importProblem(w, http.StatusBadRequest, "issuer certificate file is required")
		return
	}
	if form.method == "url" {
		// URL retrieval happens only for this explicit operator request. The
		// client never sends cookies, proxy credentials, or application secrets.
		var sanitizedSource string
		form.crl, sanitizedSource, err = fetchCRLURL(r.Context(), form.crlURL, net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: 3 * time.Second}).DialContext)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errImportTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			importProblem(w, status, err.Error())
			return
		}
		if form.source == "" {
			form.source = sanitizedSource
		}
	} else if form.source == "" {
		form.source = "dashboard file upload"
	}
	list, err := revocation.ParseAndVerify(form.crl, form.issuer, time.Now().UTC(), revocation.Limits{})
	if err != nil {
		importProblem(w, http.StatusBadRequest, "CRL verification failed: "+err.Error())
		return
	}
	id, err := s.DB.ImportCRL(list, form.source)
	if err != nil {
		importProblem(w, http.StatusInternalServerError, "CRL import failed")
		return
	}
	// A duplicate CRL keeps the provenance recorded at its first import.
	storedSource := form.source
	if records, err := s.DB.ListCRLs(); err == nil {
		for _, record := range records {
			if record.ID == id {
				storedSource = record.Source
				break
			}
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, struct {
		ID         int64  `json:"id"`
		EntryCount int    `json:"entry_count"`
		Source     string `json:"source"`
	}{id, len(list.Entries), storedSource})
}

var errImportTooLarge = errors.New("CRL import exceeds its size limit")

func readImportForm(r *http.Request) (importForm, error) {
	var form importForm
	reader, err := r.MultipartReader()
	if err != nil {
		return form, errors.New("invalid multipart form")
	}
	seen := make(map[string]bool)
	for partCount := 0; ; partCount++ {
		if partCount >= 6 {
			return form, errors.New("too many form fields")
		}
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return form, err
		}
		name := part.FormName()
		if seen[name] {
			part.Close()
			return form, errors.New("duplicate form field")
		}
		seen[name] = true
		var max int64
		switch name {
		case "method":
			max = maxFormValue
		case "crl_file":
			max = maxCRLFile
		case "crl_url":
			max = maxCRLURL
		case "issuer_file":
			max = maxIssuerFile
		case "source":
			max = maxSource
		default:
			part.Close()
			return form, errors.New("unknown form field")
		}
		data, err := io.ReadAll(io.LimitReader(part, max+1))
		part.Close()
		if err != nil {
			return form, err
		}
		if int64(len(data)) > max {
			return form, errImportTooLarge
		}
		switch name {
		case "method":
			form.method = string(data)
		case "crl_file":
			form.crl = data
		case "crl_url":
			form.crlURL = string(data)
		case "issuer_file":
			form.issuer = data
		case "source":
			form.source = strings.TrimSpace(string(data))
		}
	}
	if form.method != "file" && form.method != "url" {
		return form, errors.New("method must be file or url")
	}
	if form.method == "file" && form.crlURL != "" || form.method == "url" && len(form.crl) != 0 {
		return form, errors.New("provide a CRL file or URL, not both")
	}
	if strings.ContainsAny(form.source, "\x00\r\n") {
		return form, errors.New("source contains invalid characters")
	}
	return form, nil
}

type crlLookup func(context.Context, string, string) ([]netip.Addr, error)
type crlDial func(context.Context, string, string) (net.Conn, error)

// fetchCRLURL resolves once, rejects every non-public DNS answer, and pins
// the selected public IP for the single HTTP request. It does not use system
// proxy settings, follow redirects, or fetch any issuer/AIA/other URLs.
func fetchCRLURL(ctx context.Context, raw string, lookup crlLookup, dial crlDial) ([]byte, string, error) {
	u, host, port, err := parseCRLURL(raw)
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, crlFetchTimeout)
	defer cancel()
	ip, err := resolveCRLHost(ctx, host, lookup)
	if err != nil {
		return nil, "", err
	}
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "tcp", address) },
		TLSClientConfig:        &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  5 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableKeepAlives:      true,
		DisableCompression:     true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: crlFetchTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", errors.New("invalid CRL URL")
	}
	resp, err := client.Do(req)
	if err != nil {
		// net/url errors include the entire URL, possibly with query secrets.
		return nil, "", errors.New("CRL URL fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, "", errors.New("CRL URL redirects are not followed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("CRL URL returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxCRLFile {
		return nil, "", errImportTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLFile+1))
	if err != nil {
		return nil, "", errors.New("CRL URL response could not be read")
	}
	if int64(len(body)) > maxCRLFile {
		return nil, "", errImportTooLarge
	}
	return body, "dashboard URL: " + u.Scheme + "://" + u.Host, nil
}

func parseCRLURL(raw string) (*url.URL, string, int, error) {
	if raw == "" || int64(len(raw)) > maxCRLURL || strings.Contains(raw, "#") {
		return nil, "", 0, errors.New("invalid CRL URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, "", 0, errors.New("CRL URL must be HTTP or HTTPS without credentials or fragment")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if rawPort := u.Port(); rawPort != "" {
		port, err = strconv.Atoi(rawPort)
		if err != nil || (port != 80 && port != 443) {
			return nil, "", 0, errors.New("CRL URL port must be 80 or 443")
		}
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", 0, errors.New("CRL URL is missing a hostname")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() != "" {
		return nil, "", 0, errors.New("CRL URL cannot use a scoped IP address")
	}
	event, err := observe.Normalize(model.DestinationEvent{Hostname: host, Port: port})
	if err != nil {
		return nil, "", 0, errors.New("invalid CRL URL hostname")
	}
	if event.IP != "" {
		host = event.IP
	} else {
		host = event.Hostname
	}
	return u, host, port, nil
}

func resolveCRLHost(ctx context.Context, host string, lookup crlLookup) (netip.Addr, error) {
	scope := observe.Scope{}
	if ip, err := netip.ParseAddr(host); err == nil {
		if !scope.AllowedIP(ip) {
			return netip.Addr{}, errors.New("CRL URL IP is outside public scope")
		}
		return ip.Unmap(), nil
	}
	addrs, err := lookup(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, errors.New("CRL URL hostname resolution failed")
	}
	if len(addrs) == 0 {
		return netip.Addr{}, errors.New("CRL URL hostname has no IP address")
	}
	for _, ip := range addrs {
		if !scope.AllowedIP(ip) || ip.Zone() != "" {
			return netip.Addr{}, errors.New("CRL URL DNS answer contains a non-public IP")
		}
	}
	return addrs[0].Unmap(), nil
}
