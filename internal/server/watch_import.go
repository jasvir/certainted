package server

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/store"
)

const (
	maxWatchImportFile int64 = 2 << 20
	maxWatchImportBody int64 = maxWatchImportFile + (8 << 10)
)

func (s *Server) importWatches(w http.ResponseWriter, r *http.Request) {
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
		importProblem(w, http.StatusTooManyRequests, "another import is in progress")
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer controller.SetReadDeadline(time.Time{})
	r.Body = http.MaxBytesReader(w, r.Body, maxWatchImportBody)
	defer r.Body.Close()
	data, format, err := readWatchImportForm(r)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) || errors.Is(err, errImportTooLarge) {
			importProblem(w, http.StatusRequestEntityTooLarge, "watch import exceeds its size limit")
		} else {
			importProblem(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	if !utf8.Valid(data) {
		importProblem(w, http.StatusBadRequest, "watch import must use UTF-8")
		return
	}
	var entries []model.WatchEntry
	switch format {
	case "json":
		entries, err = parseWatchJSON(data)
	case "csv":
		entries, err = parseWatchCSV(data)
	default:
		err = errors.New("format must be json or csv")
	}
	if err != nil {
		importProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	for i := range entries {
		if strings.TrimSpace(entries[i].Source) == "" {
			entries[i].Source = "imported " + strings.ToUpper(format) + " watchlist"
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.DB.ImportWatches(ctx, entries)
	if err != nil {
		if ctx.Err() != nil {
			importProblem(w, http.StatusRequestTimeout, "watch import timed out or was canceled")
			return
		}
		if errors.Is(err, store.ErrInvalidWatchImport) {
			importProblem(w, http.StatusBadRequest, err.Error())
			return
		}
		importProblem(w, http.StatusInternalServerError, "watch import failed")
		return
	}
	writeJSON(w, result)
}

func readWatchImportForm(r *http.Request) ([]byte, string, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return nil, "", errors.New("invalid multipart form")
	}
	var data []byte
	var format, filename string
	seen := map[string]bool{}
	for partCount := 0; ; partCount++ {
		if partCount >= 3 {
			return nil, "", errors.New("too many form fields")
		}
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		name := part.FormName()
		if seen[name] {
			part.Close()
			return nil, "", errors.New("duplicate form field")
		}
		seen[name] = true
		switch name {
		case "file":
			filename = part.FileName()
			data, err = io.ReadAll(io.LimitReader(part, maxWatchImportFile+1))
			part.Close()
			if err != nil {
				return nil, "", err
			}
			if int64(len(data)) > maxWatchImportFile {
				return nil, "", errImportTooLarge
			}
		case "format":
			raw, err := io.ReadAll(io.LimitReader(part, 17))
			part.Close()
			if err != nil {
				return nil, "", err
			}
			if len(raw) > 16 {
				return nil, "", errImportTooLarge
			}
			format = strings.TrimSpace(string(raw))
		default:
			part.Close()
			return nil, "", errors.New("unknown form field")
		}
	}
	if !seen["file"] || len(data) == 0 {
		return nil, "", errors.New("watch file is required")
	}
	if format == "" {
		switch strings.ToLower(filepath.Ext(filename)) {
		case ".json":
			format = "json"
		case ".csv":
			format = "csv"
		}
	}
	if format != "json" && format != "csv" {
		return nil, "", errors.New("format must be json or csv")
	}
	return data, format, nil
}

func parseWatchJSON(data []byte) ([]model.WatchEntry, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var entries []model.WatchEntry
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("invalid watch JSON: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	if len(entries) == 0 || len(entries) > store.MaxWatchImportEntries {
		return nil, fmt.Errorf("watch import requires 1 through %d entries", store.MaxWatchImportEntries)
	}
	return entries, nil
}

var watchCSVFields = map[string]bool{
	"id": true, "name": true, "group": true, "match_type": true, "value": true,
	"status": true, "severity": true, "reason": true, "source": true,
	"effective_from": true, "effective_to": true,
}

func parseWatchCSV(data []byte) ([]model.WatchEntry, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("invalid watch CSV header: %w", err)
	}
	columns := make(map[string]int, len(header))
	for i, field := range header {
		if i == 0 {
			field = strings.TrimPrefix(field, "\ufeff")
		}
		if !watchCSVFields[field] {
			return nil, fmt.Errorf("unknown watch CSV column %q", field)
		}
		if _, exists := columns[field]; exists {
			return nil, fmt.Errorf("duplicate watch CSV column %q", field)
		}
		columns[field] = i
	}
	if _, ok := columns["match_type"]; !ok {
		return nil, errors.New("watch CSV requires match_type column")
	}
	if _, ok := columns["value"]; !ok {
		return nil, errors.New("watch CSV requires value column")
	}
	reader.FieldsPerRecord = len(header)
	entries := make([]model.WatchEntry, 0)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid watch CSV row %d: %w", len(entries)+2, err)
		}
		if len(entries) >= store.MaxWatchImportEntries {
			return nil, fmt.Errorf("watch import requires at most %d entries", store.MaxWatchImportEntries)
		}
		get := func(name string) string {
			if i, ok := columns[name]; ok {
				return watchCSVText(row[i])
			}
			return ""
		}
		if raw := get("id"); raw != "" {
			if id, err := strconv.ParseInt(raw, 10, 64); err != nil || id < 0 {
				return nil, fmt.Errorf("invalid watch CSV id on row %d", len(entries)+2)
			}
		}
		from, err := parseWatchCSVTime(get("effective_from"))
		if err != nil {
			return nil, fmt.Errorf("invalid effective_from on row %d: %w", len(entries)+2, err)
		}
		to, err := parseWatchCSVTime(get("effective_to"))
		if err != nil {
			return nil, fmt.Errorf("invalid effective_to on row %d: %w", len(entries)+2, err)
		}
		entries = append(entries, model.WatchEntry{
			Name: get("name"), Group: get("group"), MatchType: get("match_type"),
			Value: get("value"), Status: get("status"), Severity: get("severity"),
			Reason: get("reason"), Source: get("source"), EffectiveFrom: from, EffectiveTo: to,
		})
	}
	if len(entries) == 0 {
		return nil, errors.New("watch CSV contains no entries")
	}
	return entries, nil
}

// CSV exports prefix an apostrophe before spreadsheet formula-like strings.
// Remove that export prefix on import. JSON remains the lossless interchange
// format for literal strings that themselves begin with such an apostrophe.
func watchCSVText(value string) string {
	if strings.HasPrefix(value, "'") {
		rest := strings.TrimLeft(value[1:], " \t\r\n\v\f")
		if rest != "" && strings.ContainsRune("=+-@", rune(rest[0])) {
			return value[1:]
		}
	}
	return value
}

func parseWatchCSVTime(value string) (*time.Time, error) {
	if value == "" || value == "null" {
		return nil, nil
	}
	if strings.HasPrefix(value, "\"") {
		var decoded string
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			return nil, err
		}
		value = decoded
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
