package observe

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jasvir/certainted/internal/model"
	"github.com/jasvir/certainted/internal/probe"
)

type Inventory interface {
	AddDestination(model.DestinationEvent) (int64, error)
	AddProbe(model.ProbeObservation) (int64, error)
	ListDestinationsBefore(int64, int) ([]model.DestinationEvent, error)
}

type Config struct {
	Scope            Scope
	Probe            probe.Config
	Workers          int
	QueueSize        int
	MinProbeInterval time.Duration
	CacheTTL         time.Duration
	MaxCacheEntries  int
	RefreshInterval  time.Duration
	OnStorageError   func()
}

type task struct {
	event   model.DestinationEvent
	refresh bool
}

type cacheEntry struct {
	key  string
	last time.Time
}

type Observer struct {
	cfg      Config
	db       Inventory
	tasks    chan task
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	workers  sync.WaitGroup
	sendMu   sync.Mutex
	mu       sync.Mutex
	closed   bool
	last     map[string]*list.Element
	order    *list.List
	firstErr error
	rate     <-chan time.Time
	ticker   *time.Ticker
}

func New(ctx context.Context, db Inventory, cfg Config) *Observer {
	if cfg.Workers < 1 {
		cfg.Workers = 4
	}
	if cfg.Workers > 64 {
		cfg.Workers = 64
	}
	if cfg.QueueSize < 1 {
		cfg.QueueSize = 256
	}
	if cfg.QueueSize > 100000 {
		cfg.QueueSize = 100000
	}
	if cfg.MinProbeInterval <= 0 {
		cfg.MinProbeInterval = 200 * time.Millisecond
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 15 * time.Minute
	}
	if cfg.MaxCacheEntries < 1 {
		cfg.MaxCacheEntries = 10000
	}
	if cfg.MaxCacheEntries > 1000000 {
		cfg.MaxCacheEntries = 1000000
	}
	child, cancel := context.WithCancel(ctx)
	ticker := time.NewTicker(cfg.MinProbeInterval)
	o := &Observer{cfg: cfg, db: db, tasks: make(chan task, cfg.QueueSize), ctx: child, cancel: cancel, last: map[string]*list.Element{}, order: list.New(), rate: ticker.C, ticker: ticker}
	for i := 0; i < cfg.Workers; i++ {
		o.workers.Add(1)
		go o.worker()
	}
	if cfg.RefreshInterval > 0 {
		go o.refreshLoop()
	}
	return o
}

// Submit never waits for a probe or a database write. A full queue is reported
// to metadata callers; CONNECT forwarding can ignore this inspection failure.
func (o *Observer) Submit(e model.DestinationEvent) error {
	normalized, err := Normalize(e)
	if err != nil {
		return err
	}
	o.sendMu.Lock()
	defer o.sendMu.Unlock()
	if o.closed {
		return fmt.Errorf("observer closed")
	}
	o.wg.Add(1)
	select {
	case o.tasks <- task{event: normalized}:
		return nil
	default:
		o.wg.Done()
		return fmt.Errorf("observation queue full")
	}
}

func (o *Observer) enqueueRefresh(e model.DestinationEvent) {
	o.sendMu.Lock()
	defer o.sendMu.Unlock()
	if o.closed {
		return
	}
	o.wg.Add(1)
	select {
	case o.tasks <- task{event: e, refresh: true}:
	case <-o.ctx.Done():
		o.wg.Done()
	}
}

func (o *Observer) worker() {
	defer o.workers.Done()
	for t := range o.tasks {
		func() { defer o.wg.Done(); o.process(t) }()
	}
}

func (o *Observer) process(t task) {
	e := t.event
	if !t.refresh {
		id, err := o.db.AddDestination(e)
		if err != nil {
			o.recordError(err)
			return
		}
		e.ID = id
	}
	scoped, err := o.cfg.Scope.Resolve(o.ctx, e)
	key := fmt.Sprintf("%s|%s|%d|%s|%s", e.Hostname, scoped.IP, e.Port, e.Vantage, o.cfg.Probe.TrustStoreName)
	o.mu.Lock()
	entry := o.last[key]
	if err == nil && !t.refresh && entry != nil && time.Since(entry.Value.(*cacheEntry).last) < o.cfg.CacheTTL {
		o.mu.Unlock()
		return
	}
	if entry == nil {
		entry = o.order.PushBack(&cacheEntry{key: key, last: time.Now()})
		o.last[key] = entry
		if len(o.last) > o.cfg.MaxCacheEntries {
			oldest := o.order.Front()
			delete(o.last, oldest.Value.(*cacheEntry).key)
			o.order.Remove(oldest)
		}
	} else {
		entry.Value.(*cacheEntry).last = time.Now()
		o.order.MoveToBack(entry)
	}
	o.mu.Unlock()
	select {
	case <-o.ctx.Done():
		return
	case <-o.rate:
	}
	var result model.ProbeObservation
	if err != nil {
		result = model.ProbeObservation{DestinationID: e.ID, Time: time.Now().UTC(), Vantage: e.Vantage, Hostname: e.Hostname, TargetIP: e.IP, Port: e.Port, SNI: e.Hostname, Failure: err.Error()}
	} else {
		result = probe.Probe(o.ctx, scoped, o.cfg.Probe)
		result.DestinationID = e.ID
	}
	if _, err := o.db.AddProbe(result); err != nil {
		o.recordError(err)
	}
}

func (o *Observer) recordError(err error) {
	o.mu.Lock()
	if o.firstErr == nil {
		o.firstErr = err
	}
	callback := o.cfg.OnStorageError
	o.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func (o *Observer) refreshLoop() {
	tick := time.NewTicker(o.cfg.RefreshInterval)
	defer tick.Stop()
	for {
		select {
		case <-o.ctx.Done():
			return
		case <-tick.C:
			seen := map[string]bool{}
			var beforeID int64
			for {
				if o.ctx.Err() != nil {
					return
				}
				events, err := o.db.ListDestinationsBefore(beforeID, 1000)
				if err != nil {
					o.recordError(err)
					break
				}
				for _, e := range events {
					key := fmt.Sprintf("%s|%s|%d|%s", e.Hostname, e.IP, e.Port, e.Vantage)
					if seen[key] {
						continue
					}
					seen[key] = true
					o.enqueueRefresh(e)
				}
				if len(events) < 1000 {
					break
				}
				beforeID = events[len(events)-1].ID
			}
		}
	}
}

func (o *Observer) Wait() error {
	o.wg.Wait()
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.firstErr
}
func (o *Observer) Close() {
	o.cancel()
	o.sendMu.Lock()
	if !o.closed {
		o.closed = true
		close(o.tasks)
	}
	o.sendMu.Unlock()
	o.workers.Wait()
	o.ticker.Stop()
}
