// Package share sends explicitly selected, redacted reports to the community
// service. It never sends local inventory, exports, proxy traffic, or secrets.
package share

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jasvir/certainted/internal/community"
	"github.com/jasvir/certainted/internal/observe"
	"github.com/jasvir/certainted/internal/store"
)

const DefaultEndpoint = "https://certainted.com/api/v1/reports"

var ErrPreviewChanged = errors.New("report changed since preview; refresh before sharing")
var ErrPreviewRequired = errors.New("preview receipt is required")

type Client struct {
	endpoint string
	http     *http.Client
	mu       sync.Mutex
	wake     chan struct{}
}

type PreviewReport struct {
	ID       string           `json:"id"`
	ReportID string           `json:"report_id"`
	Report   community.Report `json:"report"`
	Shared   bool             `json:"shared"`
}

type PreviewState struct {
	Mode    string          `json:"mode"`
	Reports []PreviewReport `json:"reports"`
}

type Result struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	TrustStatus string `json:"trust_status"`
}

// NewClient permits the fixed production HTTPS endpoint, or a loopback HTTP
// receiver for local tests. Environment proxy variables are intentionally not
// inherited, so an application proxy cannot see a shared report.
func NewClient(endpoint string) (*Client, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/api/v1/reports" {
		return nil, errors.New("invalid community endpoint")
	}
	host := u.Hostname()
	if u.Scheme == "https" {
		if u.Host != "certainted.com" {
			return nil, errors.New("community HTTPS endpoint must be certainted.com")
		}
	} else if u.Scheme == "http" {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("HTTP community endpoint must be loopback")
		}
	} else {
		return nil, errors.New("community endpoint must use HTTPS")
	}
	return &Client{
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second,
				DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("community report redirects are not followed")
			},
		},
		wake: make(chan struct{}, 1),
	}, nil
}

// BuildReport is the sole allowlist for outbound fields. Even if a local
// source contains rich certificate or destination metadata, only this DTO is
// serialized. A public target IP is required but intentionally not published.
func BuildReport(source store.ShareSource) (community.Report, error) {
	ip, err := netip.ParseAddr(source.TargetIP)
	if err != nil || !(observe.Scope{}).AllowedIP(ip) {
		return community.Report{}, errors.New("probe target IP is not public")
	}
	r := community.Report{
		Version: community.ReportVersion, Kind: source.Kind,
		Hostname: strings.ToLower(source.Hostname), Port: source.Port,
		ObservedDay:       source.ObservedAt.UTC().Format("2006-01-02"),
		CertificateSHA256: strings.ToLower(source.CertificateSHA256), Evidence: source.Evidence,
	}
	switch source.Kind {
	case "crl":
		r.CRL = &community.CRLEvidence{
			CertificateSerial: strings.ToLower(source.CertificateSerial),
			CRLSHA256:         strings.ToLower(source.CRLSHA256),
			IssuerCertSHA256:  strings.ToLower(source.IssuerCertSHA256),
			IssuerSPKISHA256:  strings.ToLower(source.IssuerSPKISHA256),
			RevokedAt:         source.RevokedAt.UTC().Format(time.RFC3339Nano),
			ThisUpdate:        source.CRLThisUpdate.UTC().Format(time.RFC3339Nano),
			NextUpdate:        source.CRLNextUpdate.UTC().Format(time.RFC3339Nano),
			IssuerMatch:       source.IssuerMatch,
		}
	case "watch":
		r.Watch = &community.WatchEvidence{
			MatchType: source.WatchMatchType, MatchSHA256: strings.ToLower(source.WatchMatchSHA256),
			Status: source.WatchStatus, Severity: source.WatchSeverity,
		}
	default:
		return community.Report{}, errors.New("unsupported share evidence")
	}
	if err := community.ValidateReport(r); err != nil {
		return community.Report{}, err
	}
	return r, nil
}

func (c *Client) Preview(db *store.Store) (PreviewState, error) {
	settings, err := db.SharingSettings()
	if err != nil {
		return PreviewState{}, err
	}
	// Inspect a larger bounded window because private-network findings are
	// deliberately filtered from the published preview.
	sources, err := db.ListShareSources(nil, 1000)
	if err != nil {
		return PreviewState{}, err
	}
	out := PreviewState{Mode: settings.Mode, Reports: make([]PreviewReport, 0, len(sources))}
	for _, source := range sources {
		report, err := BuildReport(source)
		if err != nil {
			continue
		}
		reportID := community.ReportID(report)
		shared, err := db.HasSharedReport(reportID)
		if err != nil {
			return PreviewState{}, err
		}
		out.Reports = append(out.Reports, PreviewReport{ID: source.ID, ReportID: reportID, Report: report, Shared: shared})
		if len(out.Reports) == 100 {
			break
		}
	}
	return out, nil
}

func (c *Client) SetMode(db *store.Store, mode string) (store.SharingSettings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	settings, err := db.SetSharingMode(mode)
	if err == nil && settings.Mode == "auto" {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	return settings, err
}

// ShareID rechecks eligibility immediately before sending. The mutex prevents
// a manual click and the auto worker from posting the same report together.
func (c *Client) ShareID(ctx context.Context, db *store.Store, id, expectedReportID string) (Result, error) {
	if expectedReportID == "" {
		return Result{}, ErrPreviewRequired
	}
	return c.shareID(ctx, db, id, expectedReportID, nil)
}

func (c *Client) shareID(ctx context.Context, db *store.Store, id, expectedReportID string, autoSince *time.Time) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if autoSince != nil {
		settings, err := db.SharingSettings()
		if err != nil || settings.Mode != "auto" || settings.EnabledAt == nil || !settings.EnabledAt.Equal(*autoSince) {
			return Result{}, errors.New("automatic sharing was turned off")
		}
	}
	source, err := db.GetShareSource(id)
	if err != nil {
		return Result{}, err
	}
	report, err := BuildReport(source)
	if err != nil {
		return Result{}, err
	}
	reportID := community.ReportID(report)
	if expectedReportID != "" && reportID != expectedReportID {
		return Result{}, ErrPreviewChanged
	}
	shared, err := db.HasSharedReport(reportID)
	if err != nil {
		return Result{}, err
	}
	if shared {
		if err := db.MarkProcessedSource(id, reportID, "shared"); err != nil {
			return Result{}, err
		}
		return Result{ID: reportID, Status: "duplicate", TrustStatus: "unverified"}, nil
	}
	data, err := json.Marshal(report)
	if err != nil || len(data) > 8<<10 {
		return Result{}, errors.New("community report could not be encoded within its size limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(data))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("community share failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("community share returned HTTP %d", resp.StatusCode)
	}
	var result Result
	dec := json.NewDecoder(io.LimitReader(resp.Body, 4<<10))
	if err := dec.Decode(&result); err != nil || result.ID != reportID || (result.Status != "accepted" && result.Status != "duplicate") || result.TrustStatus != "unverified" {
		return Result{}, errors.New("community share returned an invalid receipt")
	}
	if err := db.MarkSharedReport(reportID); err != nil {
		return Result{}, err
	}
	if err := db.MarkProcessedSource(id, reportID, "shared"); err != nil {
		return Result{}, err
	}
	return result, nil
}

// Run checks for new eligible findings after opt-in. It never sweeps earlier
// history into automatic sharing, and it sends at most ten reports per tick.
func (c *Client) Run(ctx context.Context, db *store.Store) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		c.autoBatch(ctx, db)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-c.wake:
		}
	}
}

func (c *Client) autoBatch(ctx context.Context, db *store.Store) {
	settings, err := db.SharingSettings()
	if err != nil || settings.Mode != "auto" || settings.EnabledAt == nil {
		return
	}
	sources, err := db.ListShareSources(settings.EnabledAt, 10)
	if err != nil {
		return
	}
	for _, source := range sources {
		if ctx.Err() != nil {
			return
		}
		current, err := db.SharingSettings()
		if err != nil || current.Mode != "auto" || current.EnabledAt == nil || !current.EnabledAt.Equal(*settings.EnabledAt) {
			return
		}
		if _, err := BuildReport(source); err != nil {
			_ = db.MarkProcessedSource(source.ID, "", "ineligible")
			continue
		}
		if _, err := c.shareID(ctx, db, source.ID, "", settings.EnabledAt); err != nil {
			return // retry after the next tick; never leak a report in an error log
		}
	}
}
