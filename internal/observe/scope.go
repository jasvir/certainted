package observe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jasvir/certainted/internal/model"
)

// Scope is applied to both independent probes and CONNECT forwarding. DNS
// answers are checked before dialing, then the selected IP is pinned.
type Scope struct {
	AllowPrivate bool
	AllowCIDRs   []netip.Prefix
	Ports        map[int]bool
	Resolver     *net.Resolver
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("2001:db8::/32"),
}

func (s Scope) AllowedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, p := range s.AllowCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() {
		return false
	}
	if s.AllowPrivate && ip.IsPrivate() {
		return true
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (s Scope) AllowedPort(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	if len(s.Ports) == 0 {
		return port == 443 || port == 8443
	}
	return s.Ports[port]
}

func (s Scope) Resolve(ctx context.Context, e model.DestinationEvent) (model.DestinationEvent, error) {
	if !s.AllowedPort(e.Port) {
		return e, fmt.Errorf("destination port %d is outside policy", e.Port)
	}
	if e.IP != "" {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil || !s.AllowedIP(ip) {
			return e, errors.New("destination IP is outside policy")
		}
		e.IP = ip.Unmap().String()
		return e, nil
	}
	if e.Hostname == "" {
		return e, errors.New("destination requires hostname or IP")
	}
	resolver := s.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", e.Hostname)
	if err != nil {
		return e, fmt.Errorf("resolve destination: %w", err)
	}
	// Reject the entire answer set if any result is outside scope. This fails
	// closed for mixed public/private DNS responses and DNS rebinding attempts.
	if len(addrs) == 0 {
		return e, errors.New("destination has no IP address")
	}
	for _, ip := range addrs {
		if !s.AllowedIP(ip) {
			return e, errors.New("DNS answer contains IP outside policy")
		}
	}
	e.IP = addrs[0].Unmap().String()
	return e, nil
}

func Normalize(e model.DestinationEvent) (model.DestinationEvent, error) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	} else {
		e.Time = e.Time.UTC()
	}
	if e.Port == 0 {
		e.Port = 443
	}
	if e.Port < 1 || e.Port > 65535 {
		return e, errors.New("invalid destination port")
	}
	e.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(e.Hostname), "."))
	e.IP = strings.TrimSpace(e.IP)
	if e.Hostname == "" && e.IP == "" {
		return e, errors.New("hostname or IP required")
	}
	if ip, err := netip.ParseAddr(e.Hostname); err == nil {
		if e.IP != "" && e.IP != ip.String() {
			return e, errors.New("conflicting destination addresses")
		}
		e.IP, e.Hostname = ip.String(), ""
	}
	if e.IP != "" {
		ip, err := netip.ParseAddr(e.IP)
		if err != nil {
			return e, errors.New("invalid IP address")
		}
		e.IP = ip.Unmap().String()
	}
	if e.Hostname != "" {
		if len(e.Hostname) > 253 || strings.ContainsAny(e.Hostname, ":/@\\?# \t\r\n") {
			return e, errors.New("invalid hostname")
		}
		for _, part := range strings.Split(e.Hostname, ".") {
			if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return e, errors.New("invalid hostname label")
			}
			for _, c := range part {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
					return e, errors.New("invalid hostname character")
				}
			}
		}
	}
	if e.Collector == "" {
		e.Collector = "jsonl"
	}
	if e.Vantage == "" {
		e.Vantage = "local"
	}
	for _, x := range []string{e.Collector, e.Vantage, e.Workload} {
		if len(x) > 256 || strings.ContainsAny(x, "\x00\r\n") {
			return e, errors.New("invalid metadata field")
		}
	}
	if !e.AttributionReliable {
		e.Workload = ""
	}
	return e, nil
}

func ParsePorts(csv string) (map[int]bool, error) {
	out := map[int]bool{}
	for _, piece := range strings.Split(csv, ",") {
		if strings.TrimSpace(piece) == "" {
			continue
		}
		p, err := strconv.Atoi(strings.TrimSpace(piece))
		if err != nil || p < 1 || p > 65535 {
			return nil, errors.New("invalid port policy")
		}
		out[p] = true
	}
	return out, nil
}
