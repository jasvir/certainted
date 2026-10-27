package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/jasvir/certainted/internal/model"
)

type captureSink struct{ events []model.DestinationEvent }

func (s *captureSink) Submit(e model.DestinationEvent) error {
	s.events = append(s.events, e)
	return nil
}

func TestJSONLPreservesUnknownHostnameAndReliableAttribution(t *testing.T) {
	source := `{"timestamp":"2026-10-25T12:00:00Z","collector":"flow","network_vantage":"office","ip":"203.0.113.7","port":443}
{"collector":"gateway","hostname":"service.example","port":8443,"workload":"payments","attribution_reliable":true}`
	var sink captureSink
	count, err := (JSONL{Reader: strings.NewReader(source)}).Collect(context.Background(), &sink)
	if err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if sink.events[0].Hostname != "" || sink.events[0].IP != "203.0.113.7" || sink.events[0].Vantage != "office" {
		t.Fatalf("changed IP-only evidence: %+v", sink.events[0])
	}
	if sink.events[1].Workload != "payments" || !sink.events[1].AttributionReliable {
		t.Fatalf("lost reliable attribution: %+v", sink.events[1])
	}
}

func TestJSONLRejectsUnknownFieldsAndOverlongLines(t *testing.T) {
	for _, input := range []string{`{"hostname":"a.example","secret":"should not persist"}`, strings.Repeat("x", 200)} {
		_, err := (JSONL{Reader: strings.NewReader(input), MaxLineBytes: 100}).Collect(context.Background(), &captureSink{})
		if err == nil {
			t.Fatalf("accepted invalid input %q", input)
		}
	}
}
