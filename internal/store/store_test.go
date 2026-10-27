package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

func mustOpen(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certainted.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database mode = %04o, want 0600", info.Mode().Perm())
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func mustDestination(t *testing.T, s *Store, d model.DestinationEvent) int64 {
	t.Helper()
	id, err := s.AddDestination(d)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustProbe(t *testing.T, s *Store, p model.ProbeObservation) int64 {
	t.Helper()
	id, err := s.AddProbe(p)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustWatch(t *testing.T, s *Store, w model.WatchEntry) int64 {
	t.Helper()
	id, err := s.AddWatch(w)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestHistoricalWatchEvidenceAndRotation(t *testing.T) {
	s, path := mustOpen(t)
	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	destID := mustDestination(t, s, model.DestinationEvent{Time: t1, Collector: "test-jsonl", Vantage: "lab", Hostname: "service.test", IP: "192.0.2.10", Port: 443})
	root := model.Certificate{Fingerprint: strings.Repeat("a", 64), SPKIFingerprint: strings.Repeat("b", 64), Subject: "CN=Test Root", Issuer: "CN=Test Root", IsCA: true, SelfSigned: true, Source: "trust_store"}
	intermediate := model.Certificate{Fingerprint: strings.Repeat("c", 64), SPKIFingerprint: strings.Repeat("d", 64), Subject: "CN=Test Intermediate", Issuer: "CN=Test Root", IsCA: true, Source: "presented"}
	leaf := model.Certificate{Fingerprint: strings.Repeat("e", 64), SPKIFingerprint: strings.Repeat("f", 64), Subject: "CN=service.test", Issuer: "CN=Test Intermediate", Source: "presented"}
	p1 := mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: t1, Vantage: "lab", Hostname: "service.test", TargetIP: "192.0.2.10", Port: 443, SNI: "service.test", Presented: []model.Certificate{leaf, intermediate}, CandidatePaths: []model.CandidatePath{{Certificates: []model.Certificate{leaf, intermediate, root}, Validation: "valid"}}, TrustStore: "test-roots.pem"})
	rotated := intermediate
	rotated.Fingerprint = strings.Repeat("1", 64)
	rotated.Subject = "CN=Test Intermediate Renewed"
	p2 := mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: t2, Vantage: "lab", Hostname: "service.test", TargetIP: "192.0.2.10", Port: 443, SNI: "service.test", Presented: []model.Certificate{leaf, rotated}, CandidatePaths: []model.CandidatePath{{Certificates: []model.Certificate{leaf, rotated, root}, Validation: "valid"}}, TrustStore: "test-roots.pem"})
	if p2 <= p1 {
		t.Fatal("probe ids did not increase")
	}

	interWatch := mustWatch(t, s, model.WatchEntry{Name: "Specific intermediate", MatchType: "cert_sha256", Value: intermediate.Fingerprint, Status: "under investigation", Severity: "high"})
	rootWatch := mustWatch(t, s, model.WatchEntry{Name: "Test root", MatchType: "cert_sha256", Value: root.Fingerprint, Status: "monitored", Severity: "info"})
	keyWatch := mustWatch(t, s, model.WatchEntry{Name: "Intermediate key", MatchType: "spki_sha256", Value: rotated.SPKIFingerprint, Status: "monitored", Severity: "medium"})
	nameWatch := mustWatch(t, s, model.WatchEntry{Name: "Name search", MatchType: "name", Value: "Test Root", Status: "monitored"})
	findings, err := s.ListFindings(FindingFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 7 {
		t.Fatalf("expected 7 historical findings, got %d: %+v", len(findings), findings)
	}
	counts := map[int64]map[string]int{}
	for _, f := range findings {
		if counts[f.WatchID] == nil {
			counts[f.WatchID] = map[string]int{}
		}
		counts[f.WatchID][f.Evidence]++
	}
	if counts[interWatch]["direct"] != 1 || counts[rootWatch]["candidate"] != 2 || counts[keyWatch]["direct"] != 2 || counts[nameWatch]["name_only"] != 2 {
		t.Fatalf("incorrect evidence split: %+v", counts)
	}
	alerts, err := s.ListAlerts(FindingFilter{WatchID: keyWatch})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].ObservationCount != 2 {
		t.Fatalf("recurring alert not grouped: %+v", alerts)
	}
	probes, err := s.ProbesForDestination(destID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 2 || probes[0].Presented[1].Fingerprint != rotated.Fingerprint || probes[1].Presented[1].Fingerprint != intermediate.Fingerprint {
		t.Fatalf("rotation history lost: %+v", probes)
	}
	cas, err := s.CAInventory()
	if err != nil {
		t.Fatal(err)
	}
	var rootRecord *CARecord
	for i := range cas {
		if cas[i].Certificate.Fingerprint == root.Fingerprint {
			rootRecord = &cas[i]
		}
	}
	if rootRecord == nil || rootRecord.PresentedObservations != 0 || rootRecord.CandidateObservations != 2 {
		t.Fatalf("root presentation provenance wrong: %+v", rootRecord)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.DestinationEvents != 1 || st.Probes != 2 || st.SuccessfulProbes != 2 || st.ObservedCACertificates != 2 || st.AffectedDestinations != 1 {
		t.Fatalf("wrong stats: %+v", st)
	}

	// A changed watch must replace its old historical findings, including after reopen.
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.AddWatch(model.WatchEntry{ID: interWatch, Name: "Specific intermediate", MatchType: "cert_sha256", Value: rotated.Fingerprint, Status: "distrusted"})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.ListFindings(FindingFilter{WatchID: interWatch})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated) != 1 || updated[0].ProbeID != p2 {
		t.Fatalf("historical reevaluation failed: %+v", updated)
	}

	if err = s.DeleteBefore(t2); err != nil {
		t.Fatal(err)
	}
	remaining, err := s.ListProbes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].ID != p2 {
		t.Fatalf("retention did not preserve latest observation: %+v", remaining)
	}
}

func TestValidationAndFailedProbe(t *testing.T) {
	s, _ := mustOpen(t)
	if _, err := s.AddDestination(model.DestinationEvent{Port: 443}); err == nil {
		t.Fatal("accepted destination without host or IP")
	}
	destID := mustDestination(t, s, model.DestinationEvent{Hostname: "service.test", Port: 443, Collector: "jsonl", Workload: "uncertain"})
	d, err := s.GetDestination(destID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Workload != "" {
		t.Fatalf("unreliable attribution persisted: %+v", d)
	}
	if _, err = s.AddProbe(model.ProbeObservation{DestinationID: 9999, Port: 443}); err == nil {
		t.Fatal("orphan probe accepted")
	}
	pID := mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Port: 443, Failure: "dial timeout"})
	if _, err = s.GetProbe(pID); err != nil {
		t.Fatal(err)
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.FailedProbes != 1 || st.SuccessfulProbes != 0 {
		t.Fatalf("failure stats wrong: %+v", st)
	}
	if _, err = s.AddWatch(model.WatchEntry{MatchType: "cert_sha256", Value: "CN=Fake CA"}); err == nil {
		t.Fatal("accepted non-fingerprint identity")
	}
	findings, err := s.ListFindings(FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("failed probe produced exposure: %+v", findings)
	}
	if err := s.DeleteDestination(destID); err != nil {
		t.Fatal(err)
	}
	st, err = s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.DestinationEvents != 0 || st.Probes != 0 {
		t.Fatalf("destination deletion did not cascade: %+v", st)
	}
}

func TestRepeatedEventsShareDestinationIdentityAndTimeFilters(t *testing.T) {
	s, _ := mustOpen(t)
	base := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	later := base.Add(250 * time.Millisecond)
	ca := model.Certificate{Fingerprint: strings.Repeat("9", 64), SPKIFingerprint: strings.Repeat("8", 64), Subject: "CN=Lab Intermediate", IsCA: true, Source: "presented"}
	watch := mustWatch(t, s, model.WatchEntry{Name: "Lab", MatchType: "cert_sha256", Value: ca.Fingerprint})
	for _, when := range []time.Time{base, later} {
		destID := mustDestination(t, s, model.DestinationEvent{Time: when, Collector: "gateway", Vantage: "office", Hostname: "service.test", IP: "192.0.2.7", Port: 443})
		mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: when, Vantage: "office", Hostname: "service.test", TargetIP: "192.0.2.7", Port: 443, Presented: []model.Certificate{ca}})
	}
	st, err := s.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.DestinationEvents != 2 || st.UniqueDestinations != 1 || st.ProbedDestinations != 1 || st.AffectedDestinations != 1 {
		t.Fatalf("identity counts wrong: %+v", st)
	}
	if st.LatestProbe == nil || !st.LatestProbe.Equal(later) {
		t.Fatalf("latest probe time wrong: %+v", st.LatestProbe)
	}
	alerts, err := s.ListAlerts(FindingFilter{WatchID: watch})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].ObservationCount != 2 || !alerts[0].LastSeen.Equal(later) {
		t.Fatalf("recurring events not grouped: %+v", alerts)
	}
	newer, err := s.ListAlerts(FindingFilter{WatchID: watch, From: &later})
	if err != nil {
		t.Fatal(err)
	}
	if len(newer) != 1 || newer[0].ObservationCount != 1 || !newer[0].LastSeen.Equal(later) {
		t.Fatalf("from filter wrong: %+v", newer)
	}
	older, err := s.ListAlerts(FindingFilter{WatchID: watch, To: &later})
	if err != nil {
		t.Fatal(err)
	}
	if len(older) != 1 || older[0].ObservationCount != 1 || !older[0].LastSeen.Equal(base) {
		t.Fatalf("exclusive to filter wrong: %+v", older)
	}
}

func TestAlertDestinationKeyUsesStableGroupedIdentity(t *testing.T) {
	s, _ := mustOpen(t)
	when := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	ca := model.Certificate{Fingerprint: strings.Repeat("9", 64), SPKIFingerprint: strings.Repeat("8", 64), Subject: "CN=Lab Intermediate", IsCA: true, Source: "presented"}
	watch := mustWatch(t, s, model.WatchEntry{Name: "Lab", MatchType: "cert_sha256", Value: ca.Fingerprint})
	add := func(hostname, ip string, port int, vantage string) int64 {
		t.Helper()
		id := mustDestination(t, s, model.DestinationEvent{Time: when, Collector: "gateway", Vantage: vantage, Hostname: hostname, IP: ip, Port: port})
		mustProbe(t, s, model.ProbeObservation{DestinationID: id, Time: when, Vantage: vantage, Hostname: hostname, TargetIP: ip, Port: port, Presented: []model.Certificate{ca}})
		return id
	}
	firstID := add("Service.Test", "192.0.2.7", 443, "office")
	alerts, err := s.ListAlerts(FindingFilter{WatchID: watch})
	if err != nil || len(alerts) != 1 {
		t.Fatalf("first alert: %+v, %v", alerts, err)
	}
	key := alerts[0].DestinationKey
	var parts []any
	if err := json.Unmarshal([]byte(key), &parts); err != nil {
		t.Fatal(err)
	}
	if len(parts) != 4 || parts[0] != "service.test" || parts[1] != "192.0.2.7" || parts[2] != float64(443) || parts[3] != "office" {
		t.Fatalf("destination key does not reflect grouping fields: %q", key)
	}
	secondID := add("SERVICE.TEST", "192.0.2.7", 443, "office")
	alerts, err = s.ListAlerts(FindingFilter{WatchID: watch})
	if err != nil || len(alerts) != 1 {
		t.Fatalf("repeated destination alert: %+v, %v", alerts, err)
	}
	if alerts[0].DestinationKey != key || alerts[0].ObservationCount != 2 || alerts[0].DestinationID != secondID || firstID == secondID {
		t.Fatalf("group key changed with representative destination event: %+v", alerts[0])
	}
	// All observations share a timestamp, so a timestamp-only key would merge
	// these distinct groups. Each GROUP BY field must contribute to identity.
	add("other.test", "192.0.2.7", 443, "office")
	add("service.test", "192.0.2.8", 443, "office")
	add("service.test", "192.0.2.7", 8443, "office")
	add("service.test", "192.0.2.7", 443, "remote")
	alerts, err = s.ListAlerts(FindingFilter{WatchID: watch})
	if err != nil || len(alerts) != 5 {
		t.Fatalf("distinct destinations: %+v, %v", alerts, err)
	}
	keys := map[string]bool{}
	for _, alert := range alerts {
		if keys[alert.DestinationKey] {
			t.Fatalf("distinct grouped destinations share key %q", alert.DestinationKey)
		}
		keys[alert.DestinationKey] = true
	}
}

func TestWatchEffectiveDatesAndManualStatus(t *testing.T) {
	s, _ := mustOpen(t)
	base := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	from, to := base.Add(time.Hour), base.Add(2*time.Hour)
	ca := model.Certificate{Fingerprint: strings.Repeat("7", 64), SPKIFingerprint: strings.Repeat("6", 64), Subject: "CN=Dated CA", IsCA: true, Source: "presented"}
	destID := mustDestination(t, s, model.DestinationEvent{Time: base, Hostname: "dated.test", Port: 443})
	probeIDs := make([]int64, 0, 5)
	for _, when := range []time.Time{base, from, from.Add(30 * time.Minute), to} {
		probeIDs = append(probeIDs, mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: when, Port: 443, Presented: []model.Certificate{ca}}))
	}
	watchID := mustWatch(t, s, model.WatchEntry{Name: "Dated CA", MatchType: "cert_sha256", Value: ca.Fingerprint, Status: "under investigation", Severity: "critical", EffectiveFrom: &from, EffectiveTo: &to})
	watches, err := s.ListWatches()
	if err != nil {
		t.Fatal(err)
	}
	if len(watches) != 1 || watches[0].Source != "manual" || watches[0].Status != "under investigation" || watches[0].Severity != "critical" {
		t.Fatalf("watch metadata wrong: %+v", watches)
	}
	findings, err := s.ListFindings(FindingFilter{WatchID: watchID})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].ProbeID != probeIDs[2] || findings[1].ProbeID != probeIDs[1] {
		t.Fatalf("historical date bounds wrong: %+v", findings)
	}
	mustProbe(t, s, model.ProbeObservation{DestinationID: destID, Time: to.Add(time.Hour), Port: 443, Presented: []model.Certificate{ca}})
	findings, err = s.ListFindings(FindingFilter{WatchID: watchID})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("live probe outside effective period matched: %+v", findings)
	}
	cas, err := s.CAInventory()
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 || len(cas[0].WatchMatches) != 1 || cas[0].WatchMatches[0].Evidence != "direct" {
		t.Fatalf("CA inventory lost dated watch: %+v", cas)
	}
	// Changing the bounds reevaluates history and removes formerly valid findings.
	_, err = s.AddWatch(model.WatchEntry{ID: watchID, Name: "Dated CA", MatchType: "cert_sha256", Value: ca.Fingerprint, EffectiveTo: &from})
	if err != nil {
		t.Fatal(err)
	}
	findings, err = s.ListFindings(FindingFilter{WatchID: watchID})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ProbeID != probeIDs[0] {
		t.Fatalf("updated effective bounds not reevaluated: %+v", findings)
	}
	if _, err = s.AddWatch(model.WatchEntry{Name: "Bad", MatchType: "name", Value: "CA", Status: "trusted"}); err == nil {
		t.Fatal("accepted unsupported status")
	}
	if _, err = s.AddWatch(model.WatchEntry{Name: "Bad", MatchType: "name", Value: "CA", Severity: "urgent"}); err == nil {
		t.Fatal("accepted unsupported severity")
	}
	if _, err = s.AddWatch(model.WatchEntry{Name: "Bad", MatchType: "name", Value: "CA", EffectiveFrom: &to, EffectiveTo: &from}); err == nil {
		t.Fatal("accepted reversed effective interval")
	}
}

func TestRetentionPreservesOldDestinationProvenanceForFreshRefresh(t *testing.T) {
	s, _ := mustOpen(t)
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	fresh := old.Add(30 * 24 * time.Hour)
	cutoff := old.Add(15 * 24 * time.Hour)
	destinationID := mustDestination(t, s, model.DestinationEvent{Time: old, Collector: "gateway", Vantage: "office", Hostname: "refresh.test", Port: 443})
	ca := model.Certificate{Fingerprint: strings.Repeat("5", 64), SPKIFingerprint: strings.Repeat("4", 64), Subject: "CN=Refresh Intermediate", IsCA: true, Source: "presented"}
	watchID := mustWatch(t, s, model.WatchEntry{Name: "Refresh CA", MatchType: "cert_sha256", Value: ca.Fingerprint})
	mustProbe(t, s, model.ProbeObservation{DestinationID: destinationID, Time: old, Vantage: "office", Hostname: "refresh.test", Port: 443, Presented: []model.Certificate{ca}})
	freshProbeID := mustProbe(t, s, model.ProbeObservation{DestinationID: destinationID, Time: fresh, Vantage: "office", Hostname: "refresh.test", Port: 443, Presented: []model.Certificate{ca}})
	if err := s.DeleteBefore(cutoff); err != nil {
		t.Fatal(err)
	}
	destination, err := s.GetDestination(destinationID)
	if err != nil || !destination.Time.Equal(old) {
		t.Fatalf("old source event for retained refresh was lost: %+v, %v", destination, err)
	}
	probes, err := s.ProbesForDestination(destinationID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0].ID != freshProbeID {
		t.Fatalf("retention did not keep fresh refresh probe: %+v", probes)
	}
	findings, err := s.ListFindings(FindingFilter{WatchID: watchID})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].ProbeID != freshProbeID {
		t.Fatalf("retention did not keep fresh finding: %+v", findings)
	}
	if err := s.DeleteBefore(fresh.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDestination(destinationID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unreferenced old event should be pruned, got %v", err)
	}
}

func TestDestinationKeysetPagination(t *testing.T) {
	s, _ := mustOpen(t)
	ids := make([]int64, 0, 6)
	for i := 0; i < 5; i++ {
		ids = append(ids, mustDestination(t, s, model.DestinationEvent{Collector: "fixture", Hostname: "page.test", Port: 443}))
	}
	first, err := s.ListDestinationsBefore(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].ID != ids[4] || first[1].ID != ids[3] {
		t.Fatalf("first page wrong: %+v", first)
	}
	newID := mustDestination(t, s, model.DestinationEvent{Collector: "fixture", Hostname: "new.page.test", Port: 443})
	second, err := s.ListDestinationsBefore(first[len(first)-1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 2 || second[0].ID != ids[2] || second[1].ID != ids[1] {
		t.Fatalf("second page skipped or repeated events: %+v", second)
	}
	third, err := s.ListDestinationsBefore(second[len(second)-1].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(third) != 1 || third[0].ID != ids[0] {
		t.Fatalf("last page wrong: %+v", third)
	}
	empty, err := s.ListDestinationsBefore(third[0].ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected no older events, got %+v", empty)
	}
	latest, err := s.ListDestinations(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 2 || latest[0].ID != newID || latest[1].ID != ids[4] {
		t.Fatalf("latest listing wrong: %+v", latest)
	}
	if _, err = s.ListDestinationsBefore(-1, 2); err == nil {
		t.Fatal("accepted negative cursor")
	}
}
