package observe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

type fakeInventory struct {
	mu    sync.Mutex
	next  int64
	added chan struct{}
}

type pagedInventory struct {
	fakeInventory
	probedOldest chan struct{}
}

func (f *pagedInventory) ListDestinationsBefore(beforeID int64, limit int) ([]model.DestinationEvent, error) {
	var page []model.DestinationEvent
	for id := int64(1001); id >= 1 && len(page) < limit; id-- {
		if beforeID != 0 && id >= beforeID {
			continue
		}
		page = append(page, model.DestinationEvent{ID: id, Hostname: fmt.Sprintf("test-%d.example", id), IP: "127.0.0.1", Port: 443, Vantage: "lab"})
	}
	return page, nil
}

func (f *pagedInventory) AddProbe(p model.ProbeObservation) (int64, error) {
	if p.DestinationID == 1 {
		select {
		case f.probedOldest <- struct{}{}:
		default:
		}
	}
	return 1, nil
}

func (f *fakeInventory) AddDestination(e model.DestinationEvent) (int64, error) {
	f.mu.Lock()
	f.next++
	id := f.next
	f.mu.Unlock()
	select {
	case f.added <- struct{}{}:
	default:
	}
	return id, nil
}
func (f *fakeInventory) AddProbe(model.ProbeObservation) (int64, error) { return 1, nil }
func (f *fakeInventory) ListDestinationsBefore(int64, int) ([]model.DestinationEvent, error) {
	return nil, nil
}

func TestQueueLimitAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	db := &fakeInventory{added: make(chan struct{}, 1)}
	o := New(ctx, db, Config{Scope: Scope{}, Workers: 1, QueueSize: 1, MinProbeInterval: time.Hour, RefreshInterval: 0})
	e := model.DestinationEvent{IP: "127.0.0.1", Port: 443}
	if err := o.Submit(e); err != nil {
		t.Fatal(err)
	}
	select {
	case <-db.added:
	case <-time.After(time.Second):
		t.Fatal("worker did not take first event")
	}
	if err := o.Submit(e); err != nil {
		t.Fatal(err)
	}
	if err := o.Submit(e); err == nil || !strings.Contains(err.Error(), "queue full") {
		t.Fatalf("expected queue limit, got %v", err)
	}
	done := make(chan struct{})
	go func() { cancel(); o.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled observer did not stop")
	}
	if err := o.Submit(e); err == nil {
		t.Fatal("closed observer accepted event")
	}
}

func TestScopeRequiresExplicitPrivateAuthorization(t *testing.T) {
	e := model.DestinationEvent{IP: "127.0.0.1", Port: 443}
	if _, err := (Scope{}).Resolve(context.Background(), e); err == nil {
		t.Fatal("loopback accepted by default")
	}
	scope := Scope{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	if _, err := scope.Resolve(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	private := Scope{AllowPrivate: true}
	if !private.AllowedIP(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("authorized RFC1918 address denied")
	}
	for _, text := range []string{"100.64.0.1", "198.18.0.1", "192.0.2.1"} {
		if private.AllowedIP(netip.MustParseAddr(text)) {
			t.Fatalf("broad private flag accepted reserved address %s", text)
		}
	}
	all := Scope{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	for _, text := range []string{"0.0.0.0", "224.0.0.1"} {
		if all.AllowedIP(netip.MustParseAddr(text)) {
			t.Fatalf("wide CIDR accepted unroutable address %s", text)
		}
	}
}

func TestRefreshReachesOlderDestinationsBeyondFirstPage(t *testing.T) {
	db := &pagedInventory{probedOldest: make(chan struct{}, 1)}
	o := New(context.Background(), db, Config{Scope: Scope{}, Workers: 1, QueueSize: 1, MinProbeInterval: time.Microsecond, RefreshInterval: time.Second / 100})
	defer o.Close()
	select {
	case <-db.probedOldest:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not reach the oldest destination after paging and queue backpressure")
	}
}

func TestRecentProbeCacheHasEntryLimit(t *testing.T) {
	db := &fakeInventory{added: make(chan struct{}, 3)}
	o := New(context.Background(), db, Config{Scope: Scope{}, Workers: 1, QueueSize: 3, MinProbeInterval: time.Microsecond, MaxCacheEntries: 2})
	defer o.Close()
	for i := 0; i < 3; i++ {
		if err := o.Submit(model.DestinationEvent{Hostname: fmt.Sprintf("test-%d.example", i), IP: "127.0.0.1", Port: 443}); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Wait(); err != nil {
		t.Fatal(err)
	}
	if len(o.last) != 2 {
		t.Fatalf("recent probe cache has %d entries, want 2", len(o.last))
	}
}
