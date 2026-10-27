// Package collector accepts authorized destination metadata. It does not
// receive or forward application traffic.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

// DestinationSink is the collector-to-observer interface. Other metadata
// sources can implement collection without changing probing or storage.
type DestinationSink interface {
	Submit(model.DestinationEvent) error
}

type JSONL struct {
	Reader       io.Reader
	MaxLineBytes int
}

// Collect reads one destination event per line and emits only metadata.
func (j JSONL) Collect(ctx context.Context, sink DestinationSink) (int, error) {
	if j.Reader == nil {
		return 0, errors.New("JSONL reader is required")
	}
	max := j.MaxLineBytes
	if max <= 0 {
		max = 16 << 10
	}
	sc := bufio.NewScanner(j.Reader)
	sc.Buffer(make([]byte, 4096), max)
	count, lineNo := 0, 0
	for sc.Scan() {
		lineNo++
		if err := ctx.Err(); err != nil {
			return count, err
		}
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		e, err := DecodeEvent(line)
		if err != nil {
			return count, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if err := sink.Submit(e); err != nil {
			return count, fmt.Errorf("line %d: %w", lineNo, err)
		}
		count++
	}
	return count, sc.Err()
}

type eventLine struct {
	Time                *time.Time `json:"time"`
	Timestamp           *time.Time `json:"timestamp"`
	Collector           string     `json:"collector"`
	Vantage             string     `json:"vantage"`
	NetworkVantage      string     `json:"network_vantage"`
	Hostname            string     `json:"hostname"`
	IP                  string     `json:"ip"`
	Port                int        `json:"port"`
	Workload            string     `json:"workload"`
	AttributionReliable bool       `json:"attribution_reliable"`
}

func DecodeEvent(line []byte) (model.DestinationEvent, error) {
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	var raw eventLine
	if err := dec.Decode(&raw); err != nil {
		return model.DestinationEvent{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return model.DestinationEvent{}, errors.New("trailing JSON")
	}
	if raw.Time != nil && raw.Timestamp != nil {
		return model.DestinationEvent{}, errors.New("use time or timestamp, not both")
	}
	var when time.Time
	if raw.Time != nil {
		when = *raw.Time
	}
	if raw.Timestamp != nil {
		when = *raw.Timestamp
	}
	vantage := raw.Vantage
	if vantage == "" {
		vantage = raw.NetworkVantage
	}
	return model.DestinationEvent{Time: when, Collector: raw.Collector, Vantage: vantage, Hostname: raw.Hostname, IP: raw.IP, Port: raw.Port, Workload: raw.Workload, AttributionReliable: raw.AttributionReliable}, nil
}
