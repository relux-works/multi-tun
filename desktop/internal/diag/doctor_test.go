package diag

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode"

	"multi-tun/desktop/internal/core/failclosed"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/singbox"
)

const scutilFixture = `DNS configuration
resolver #1
  search domain[0] : example.test
  nameserver[0] : 1.1.1.1
  nameserver[1] : 8.8.8.8
  flags : Request A records, Request AAAA records
  reach : 0x00000002 (Reachable)
resolver #2
  domain : mts.ru
  nameserver[0] : 10.0.0.53
  if_index : 27 (utun4)
  flags : Supplemental, Request A records
  reach : 0x00000002 (Reachable)
  order : 102000
resolver #3
  domain : login.mts.ru
  nameserver[0] : 10.0.0.54
  order : 101000
DNS configuration (for scoped queries)
resolver #1
  nameserver[0] : 192.0.2.53
  if_index : 14 (en0)
  flags : Scoped, Request A records
  reach : 0x00000002 (Reachable)
resolver #2
  domain : services.mts.ru
  nameserver[0] : 10.1.0.53
  if_index : 27 (utun4)
  flags : Scoped
`

func TestScutilDNS(t *testing.T) {
	snap := ParseScutilDNS(scutilFixture)
	if len(snap.Resolvers) != 5 {
		t.Fatalf("resolver count: %d", len(snap.Resolvers))
	}
	r := snap.Resolvers[1]
	if r.ID != 2 || r.Scoped || r.Interface != "utun4" || r.IfIndex != "27" || r.Order != 102000 || !strings.Contains(r.Flags, "Supplemental") || r.Reach == "" {
		t.Fatalf("supplemental: %+v", r)
	}
	if !snap.Resolvers[3].Scoped || snap.Resolvers[3].Interface != "en0" || len(snap.Resolvers[0].Search) != 1 {
		t.Fatal("lost scoped resolver or search domains")
	}
	for _, tc := range []struct {
		host   string
		id     int
		domain string
	}{{"gitlab.services.mts.ru", 2, "mts.ru"}, {"LOGIN.MTS.RU.", 3, "login.mts.ru"}, {"mts.ru", 2, "mts.ru"}, {"nodedata.io", 1, ""}, {"fakemts.ru", 1, ""}, {"foo.login.mts.ru", 3, "login.mts.ru"}} {
		t.Run(tc.host, func(t *testing.T) {
			m := MatchResolverForHost(snap, tc.host)
			if m == nil || m.ResolverID != tc.id || m.MatchedDomain != tc.domain || m.Scoped || len(m.Nameservers) == 0 || m.MatchReason == "" {
				t.Fatalf("match: %+v", m)
			}
		})
	}
	if MatchResolverForHost(ScutilDNSSnapshot{}, "example.test") != nil {
		t.Fatal("invented resolver")
	}
	tie := ScutilDNSSnapshot{Resolvers: []ScutilResolver{{ID: 4, Domain: "mts.ru", Order: 200}, {ID: 3, Domain: "mts.ru", Order: 100}, {ID: 2, Domain: "mts.ru", Order: 100}}}
	if m := MatchResolverForHost(tie, "mts.ru"); m.ResolverID != 2 {
		t.Fatalf("tie: %+v", m)
	}
}
func TestRouteGet(t *testing.T) {
	for _, tc := range []struct{ ip, iface, gateway string }{{"10.0.0.2", "utun4", "10.0.0.1"}, {"172.19.0.2", "utun233", "172.19.0.1"}, {"203.0.113.1", "en0", "192.0.2.1"}, {"2001:db8::2", "utun4", "fe80::1%utun4"}} {
		t.Run(tc.ip, func(t *testing.T) {
			out := "   route to: " + tc.ip + "\ndestination: default\n       mask: default\n    gateway: " + tc.gateway + "\n  interface: " + tc.iface + "\n      flags: <UP,GATEWAY,DONE,STATIC>\n"
			r := ParseRouteGet(tc.ip, out)
			if r.TargetIP != tc.ip || r.RouteTo != tc.ip || r.Destination != "default" || r.Mask != "default" || r.Gateway != tc.gateway || r.Interface != tc.iface || r.Flags != "<UP,GATEWAY,DONE,STATIC>" || r.Error != "" {
				t.Fatalf("route: %+v", r)
			}
		})
	}
	for _, out := range []string{"route: writing to routing socket: not in table", "", "route: permission denied\x1b\n"} {
		r := ParseRouteGet("203.0.113.1", out)
		if r.Error == "" || strings.ContainsAny(r.Error, "\x1b\n") {
			t.Fatalf("route error: %+v", r)
		}
	}
}
func renderedConfig(t *testing.T) []byte {
	t.Helper()
	cfg := config.Default()
	cfg.Network.Mode = config.RenderModeTun
	cfg.Routing.BypassSuffixes = []string{".ru"}
	cfg.Routing.BypassExcludes = []string{"t.me"}
	data, err := singbox.RenderWithOptions(cfg, model.Profile{ID: "fixture", Name: "fixture", Protocol: "vless", UUID: "00000000-0000-0000-0000-000000000001", Host: "203.0.113.10", Port: 443, Network: "tcp", Security: "tls"}, singbox.RenderOptions{OverlayDNS: &singbox.OverlayDNS{Domains: []string{"mts.ru"}, Nameservers: []string{"10.0.0.53"}, RouteExcludes: []string{"10.0.0.0/8"}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestEvaluateRenderedSingBox(t *testing.T) {
	data := renderedConfig(t)
	for _, tc := range []struct {
		host, ip, dns, outbound string
		excluded                bool
		dnsIndex, routeIndex    int
		matcher                 string
	}{
		{"gitlab.services.mts.ru", "10.20.30.40", "dns-overlay", "direct", true, 1, 3, "ip_is_private"},
		{"gitlab.services.mts.ru", "198.51.100.1", "dns-overlay", "direct", false, 1, 6, "rule_set:overlay-direct"},
		{"gosuslugi.ru", "198.51.100.1", "dns-direct", "direct", false, 2, 7, "rule_set:ru-direct"},
		{"www.gosuslugi.ru", "198.51.100.1", "dns-direct", "direct", false, 2, 7, "rule_set:ru-direct"},
		{"t.me", "198.51.100.1", "dns-proxy", "proxy", false, 0, 5, "rule_set:proxy-exceptions"},
		{"nodedata.io", "198.51.100.1", "dns-proxy", "proxy", false, 3, -1, "final"},
		{"fakemts.ru", "198.51.100.1", "dns-direct", "direct", false, 2, 7, "rule_set:ru-direct"},
		{"private.example", "192.168.1.1", "dns-proxy", "direct", false, 3, 3, "ip_is_private"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			m, err := EvaluateSingBoxConfig(data, "rendered.json", tc.host, []netip.Addr{netip.MustParseAddr(tc.ip)})
			if err != nil {
				t.Fatal(err)
			}
			if m.Outbound != tc.outbound || m.DNSServerTag != tc.dns || m.TUNExcluded != tc.excluded || m.TUNInterface == "" || len(m.TUNAddresses) == 0 {
				t.Fatalf("match: %+v", m)
			}
			if m.DNSRuleIndex != tc.dnsIndex || m.RouteRuleIndex != tc.routeIndex || m.RouteMatcher != tc.matcher {
				t.Fatalf("wrong rule precedence: %+v", m)
			}
			if tc.excluded && m.TUNExcludeCIDR != "10.0.0.0/8" {
				t.Fatalf("exclude: %+v", m)
			}
			if tc.host == "nodedata.io" && (m.RouteRuleIndex != -1 || m.RouteMatcher != "final") {
				t.Fatalf("expected final: %+v", m)
			}
			if tc.dns == "dns-overlay" && (m.DNSServerAddress != "10.0.0.53" || m.DNSDetour != "direct") {
				t.Fatalf("overlay: %+v", m)
			}
		})
	}
	for _, suffix := range []string{".ru", "ru", "mts.ru", ".mts.ru"} {
		for _, host := range []string{"mts.ru", "gitlab.services.mts.ru"} {
			if !suffixMatch(host, suffix) {
				t.Fatalf("%s should match %s", suffix, host)
			}
		}
	}
	if suffixMatch("fakemts.ru", "mts.ru") {
		t.Fatal("matched partial label")
	}
}
func TestSingBoxPredicatesAndRefusals(t *testing.T) {
	raw := []byte(`{"dns":{"servers":[{"tag":"d","address":"local","detour":"direct"}],"rules":[{"domain":["exact.test"],"server":"d"},{"domain_keyword":["key"],"server":"d"}],"final":"fallback"},"route":{"rule_set":[{"type":"inline","tag":"nets","rules":[{"ip_cidr":["198.51.100.0/24"]}]}],"rules":[{"process_name":["openconnect"],"outbound":"direct"},{"rule_set":["nets"],"outbound":"direct"}],"final":"proxy"}}`)
	for _, host := range []string{"exact.test", "keyword.test"} {
		m, err := EvaluateSingBoxConfig(raw, "x", host, []netip.Addr{netip.MustParseAddr("198.51.100.9")})
		if err != nil || m.DNSServerTag != "d" || m.Outbound != "direct" || m.RouteRuleIndex != 1 || m.RouteMatcher != "rule_set:nets" || len(m.Notes) == 0 {
			t.Fatalf("%+v %v", m, err)
		}
	}
	m, err := EvaluateSingBoxConfig(raw, "x", "none.test", nil)
	if err != nil || m.DNSRuleIndex != -1 || m.DNSServerTag != "fallback" || m.Outbound != "proxy" {
		t.Fatalf("final: %+v %v", m, err)
	}
	for _, raw := range []string{"{", `{}`, `{"route":{"rules":[{"rule_set":["remote"],"outbound":"direct"}],"final":"proxy"}}`, `{"route":{"rules":[{"port":443,"outbound":"direct"}],"final":"proxy"}}`} {
		if _, err := EvaluateSingBoxConfig([]byte(raw), "x", "host.test", nil); err == nil {
			t.Fatalf("accepted unknown config/predicate: %s", raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "169.254.1.1", "fe80::1", "::1", "fd00::1"} {
		m, err := EvaluateSingBoxConfig([]byte(`{"route":{"rules":[{"ip_is_private":true,"outbound":"direct"}],"final":"proxy"}}`), "x", "host.test", []netip.Addr{netip.MustParseAddr(ip)})
		if err != nil || m.Outbound != "direct" {
			t.Fatalf("private %s: %+v %v", ip, m, err)
		}
	}
}
func healthyDeps() Deps {
	return Deps{
		Now: func() time.Time { return time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC) },
		Configuration: func(context.Context) Configuration {
			return Configuration{Present: true, HelperRequired: true, Policy: failclosed.Policy{Enabled: true, TunnelInterface: "utun233", Services: []failclosed.Service{{Name: "service", Domains: []string{"mts.ru"}}}}, ConfigPath: "fallback.json"}
		},
		VPNCore: func(context.Context) VPNCoreHealth { return VPNCoreHealth{Reachable: true, DaemonPID: 42} },
		Interfaces: func(context.Context) ([]TUNInterfaceInfo, error) {
			return []TUNInterfaceInfo{{Name: "utun233", Up: true, MTU: 1500, Addresses: []string{"172.19.0.1/30"}}}, nil
		},
		Guard: func(context.Context) GuardHealth {
			return GuardHealth{HelperEnabled: true, PFEnabled: true, AnchorLoaded: true, Enforcing: true, TableMatches: true, TableEntries: 3, LiveTableEntries: 3}
		},
		Sessions: func(context.Context) ([]SessionHealth, error) {
			return []SessionHealth{{Name: "fixture", Kind: "sing-box", State: "active", PID: 7, Interface: "utun233", ConfigPath: "active.json"}}, nil
		},
		ScutilDNS:     func(context.Context) (string, error) { return scutilFixture, nil },
		ResolverFiles: func(context.Context) ([]string, error) { return []string{"/etc/resolver/mts.ru"}, nil },
	}
}
func TestDoctorVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		edit    func(*Deps)
		healthy bool
	}{
		{"healthy", func(*Deps) {}, true},
		{"unreachable", func(d *Deps) {
			d.VPNCore = func(context.Context) VPNCoreHealth { return VPNCoreHealth{Error: "unreachable"} }
		}, false},
		{"guard-not-enforcing", func(d *Deps) { d.Guard = func(context.Context) GuardHealth { return GuardHealth{HelperEnabled: true} } }, false},
		{"stale-session", func(d *Deps) {
			d.Sessions = func(context.Context) ([]SessionHealth, error) {
				return []SessionHealth{{Name: "stale", State: "stale"}}, nil
			}
		}, false},
		{"unknown-session", func(d *Deps) {
			d.Sessions = func(context.Context) ([]SessionHealth, error) {
				return []SessionHealth{{Name: "unknown", State: "unknown"}}, nil
			}
		}, false},
		{"session-scan-error", func(d *Deps) {
			d.Sessions = func(context.Context) ([]SessionHealth, error) { return nil, errors.New("read error") }
		}, false},
		{"plaintext-warning", func(d *Deps) {
			base := d.Configuration
			d.Configuration = func(ctx context.Context) Configuration {
				c := base(ctx)
				c.Auth = []AuthHealth{{Server: "fixture", Storage: "plaintext_url", Status: "warn", Detail: "migrate authentication"}}
				return c
			}
		}, true},
		{"tool-drift-warning", func(d *Deps) {
			d.VPNCore = func(context.Context) VPNCoreHealth {
				return VPNCoreHealth{Reachable: true, ToolDrift: []string{"tool differs"}}
			}
		}, true},
		{"missing-config", func(d *Deps) { d.Configuration = func(context.Context) Configuration { return Configuration{} } }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := healthyDeps()
			tc.edit(&d)
			r := Doctor(context.Background(), d)
			if r.Healthy != tc.healthy || (r.Verdict == "ok") != tc.healthy {
				t.Fatalf("report: %+v", r)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var decoded DoctorReport
			if err = json.Unmarshal(b, &decoded); err != nil || decoded.Healthy != r.Healthy {
				t.Fatalf("round trip: %v", err)
			}
			if r.Timestamp != "2026-11-28T12:00:00Z" || len(r.DNS.ScopedResolvers) != 2 {
				t.Fatalf("collectors lost: %+v", r)
			}
			if tc.name == "healthy" && (r.Interfaces[0].Role != "tun-wave" || !r.Guard.TunnelUp) {
				t.Fatalf("interface attribution: %+v", r)
			}
		})
	}
}
func TestTextSanitizesExternalData(t *testing.T) {
	r := Doctor(context.Background(), healthyDeps())
	r.Interfaces[0].Name = "utun233\x1b[2J\nforged"
	r.Checks = append(r.Checks, DoctorCheck{Name: "external\r\n", Status: "warn", Detail: "escape\x1b\x00\u202e"})
	for _, out := range []string{FormatDoctorText(r), FormatTraceText(TraceReport{Host: "example.test\x1b\r\n", HTTPProbe: &HTTPProbeResult{BodyPreview: "hello\x1b\n"}})} {
		for _, r := range out {
			if r != '\n' && (unicode.IsControl(r) || !unicode.IsPrint(r)) {
				t.Fatalf("unsafe output: %q", out)
			}
		}
	}
}

func TestSingBoxDestinationPredicatesAreAlternatives(t *testing.T) {
	data := []byte(`{"route":{"rules":[{"domain":["exact.test"],"domain_suffix":["suffix.test"],"domain_keyword":["keyword"],"ip_cidr":["198.51.100.0/24"],"outbound":"direct"}],"final":"proxy"}}`)
	for _, tc := range []struct{ host, ip, want string }{{"exact.test", "203.0.113.1", "direct"}, {"sub.suffix.test", "203.0.113.1", "direct"}, {"keyword.test", "203.0.113.1", "direct"}, {"other.test", "198.51.100.1", "direct"}, {"nonsuffix.test", "203.0.113.1", "proxy"}} {
		m, err := EvaluateSingBoxConfig(data, "x", tc.host, []netip.Addr{netip.MustParseAddr(tc.ip)})
		if err != nil || m.Outbound != tc.want {
			t.Fatalf("%s: %+v %v", tc.host, m, err)
		}
	}
}
