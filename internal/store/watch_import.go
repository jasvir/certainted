package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

// WatchImportResult describes an additive, atomic import. Exported IDs are
// deliberately ignored: they identify rows in the source database, not this one.
type WatchImportResult struct {
	Imported int     `json:"imported"`
	Skipped  int     `json:"skipped"`
	IDs      []int64 `json:"ids"`
}

const MaxWatchImportEntries = 256

var ErrInvalidWatchImport = errors.New("invalid watch import")

// ImportWatches adds watches and reevaluates historical probes in one
// transaction. Entries identical to an existing or earlier imported entry are
// counted as skipped; other entries are imported even if they watch the same
// fingerprint with different status or effective dates.
func (s *Store) ImportWatches(ctx context.Context, entries []model.WatchEntry) (WatchImportResult, error) {
	result := WatchImportResult{IDs: []int64{}}
	if len(entries) == 0 || len(entries) > MaxWatchImportEntries {
		return result, fmt.Errorf("%w: requires 1 through %d entries", ErrInvalidWatchImport, MaxWatchImportEntries)
	}
	prepared := make([]model.WatchEntry, len(entries))
	for i, entry := range entries {
		entry.ID = 0
		var err error
		prepared[i], err = normalizeWatch(entry)
		if err != nil {
			return result, fmt.Errorf("%w: entry %d: %v", ErrInvalidWatchImport, i+1, err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	existing, err := listWatchesTx(tx)
	if err != nil {
		return result, err
	}
	byMatch := make(map[string][]model.WatchEntry)
	for _, entry := range existing {
		byMatch[watchImportKey(entry)] = append(byMatch[watchImportKey(entry)], entry)
	}
	for _, entry := range prepared {
		if err := ctx.Err(); err != nil {
			return WatchImportResult{}, err
		}
		key := watchImportKey(entry)
		duplicate := false
		for _, previous := range byMatch[key] {
			if sameWatchContents(entry, previous) {
				duplicate = true
				break
			}
		}
		if duplicate {
			result.Skipped++
			continue
		}
		if err := saveWatchTx(ctx, tx, &entry); err != nil {
			return WatchImportResult{}, err
		}
		byMatch[key] = append(byMatch[key], entry)
		result.Imported++
		result.IDs = append(result.IDs, entry.ID)
	}
	if err := tx.Commit(); err != nil {
		return WatchImportResult{}, err
	}
	return result, nil
}

func watchImportKey(w model.WatchEntry) string {
	value := w.Value
	if w.MatchType == "name" {
		value = strings.ToLower(value)
	}
	return w.MatchType + "\x00" + value
}

func sameWatchContents(a, b model.WatchEntry) bool {
	return a.Name == b.Name && a.Group == b.Group && a.MatchType == b.MatchType &&
		a.Value == b.Value && a.Status == b.Status && a.Severity == b.Severity &&
		a.Reason == b.Reason && a.Source == b.Source &&
		sameOptionalTime(a.EffectiveFrom, b.EffectiveFrom) && sameOptionalTime(a.EffectiveTo, b.EffectiveTo)
}

func sameOptionalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}
