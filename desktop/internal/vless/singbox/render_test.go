package singbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/subscription"
)

// The matcher reads only domain predicates from the rendered config. It checks
// first-match precedence offline; it does not prove live DNS or OS routing.
func renderedDomainTarget(root map[string]any, section, domain string) string {
	sets := map[string][]any{}
	for _, raw := range root["route"].(map[string]any)["rule_set"].([]any) {
		set := raw.(map[string]any)
		sets[set["tag"].(string)] = set["rules"].([]any)
	}
	matches := func(rule map[string]any) bool {
		for _, raw := range rule["domain_suffix"].([]any) {
			suffix := strings.TrimPrefix(raw.(string), ".")
			if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
				return true
			}
		}
		return false
	}
	for _, raw := range root[section].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		matched := false
		if _, ok := rule["domain_suffix"]; ok {
			matched = matches(rule)
		} else if names, ok := rule["rule_set"].([]any); ok {
			for _, name := range names {
				for _, raw := range sets[name.(string)] {
					predicate := raw.(map[string]any)
					if _, ok := predicate["domain_suffix"]; ok && matches(predicate) {
						matched = true
					}
				}
			}
		} else if section == "dns" {
			matched = true // DNS's unconditional final rule.
		}
		if matched {
			if section == "dns" {
				return rule["server"].(string)
			}
			return rule["outbound"].(string)
		}
	}
	return root[section].(map[string]any)["final"].(string)
}

func TestRenderComposedDNSAndRoutePrecedenceAcrossBackends(t *testing.T) {
	t.Parallel()
	for _, backend := range []struct {
		name      string
		render    func(config.ProjectConfig, model.Profile, RenderOptions) ([]byte, error)
		processes []any
	}{
		{"VLESS", RenderWithOptions, []any{"openconnect"}},
		{"Xray", RenderXrayFrontendWithOptions, []any{"xray", "openconnect"}},
		{"AWG", RenderAWGFrontendWithOptions, []any{"tun-wave", "vless-tun", "openconnect"}},
	} {
		for _, overlay := range []bool{false, true} {
			for _, bypass := range []bool{false, true} {
				name := fmt.Sprintf("%s/overlay=%t/bypass=%t", backend.name, overlay, bypass)
				t.Run(name, func(t *testing.T) {
					cfg := config.Default()
					cfg.Routing.BypassSuffixes = nil
					cfg.Routing.BypassExcludes = nil
					if bypass {
						cfg.Routing.BypassSuffixes = []string{"ru", "рф", "gosuslugi.ru"}
						cfg.Routing.BypassExcludes = []string{"proxy.example.ru", "proxy.mts.ru"}
					}
					options := RenderOptions{}
					if overlay {
						options.OverlayDNS = &OverlayDNS{
							Domains:       []string{"mts.ru", "mtsit.local"},
							BypassDomains: []string{"vpn-ra2.mts.ru", "login.mts.ru", "outside.example"},
							Nameservers:   []string{"10.73.16.4"},
						}
					}
					data, err := backend.render(cfg, model.Profile{UUID: "00000000-0000-0000-0000-000000000000", Host: "203.0.113.10", Port: 443}, options)
					if err != nil {
						t.Fatal(err)
					}
					if err := vpncore.ValidateSingBoxConfig(data); err != nil {
						t.Fatalf("config refused: %v", err)
					}
					var root map[string]any
					if err := json.Unmarshal(data, &root); err != nil {
						t.Fatal(err)
					}
					route := root["route"].(map[string]any)
					wantResolver := "dns-direct"
					if overlay {
						wantResolver = "dns-proxy"
					}
					if got := root["outbounds"].([]any)[1].(map[string]any)["domain_resolver"]; got != wantResolver {
						t.Fatalf("direct.domain_resolver = %v, want %s", got, wantResolver)
					}
					first := route["rules"].([]any)[0].(map[string]any)
					if !slices.Equal(first["process_name"].([]any), backend.processes) || first["action"] != "route" || first["outbound"] != "direct" {
						t.Fatalf("process bypass = %v", first)
					}
					if hasRuleSet(route["rule_set"].([]any), "overlay-direct") != overlay {
						t.Fatal("overlay route set presence does not match overlay state")
					}
					for _, domain := range []string{"gitlab.services.mts.ru", "mybonus.mts.ru", "host.mtsit.local", "vpn-ra2.mts.ru", "login.mts.ru", "outside.example", "gosuslugi.ru", "host.xn--p1ai", "nodedata.io", "notmts.ru", "mts.ru.example"} {
						wantDNS, wantRoute := "dns-proxy", "proxy"
						if bypass && (strings.HasSuffix(domain, ".ru") || strings.HasSuffix(domain, ".xn--p1ai")) {
							wantDNS, wantRoute = "dns-direct", "direct"
						}
						if overlay {
							switch domain {
							case "gitlab.services.mts.ru", "mybonus.mts.ru", "host.mtsit.local":
								wantDNS, wantRoute = "dns-overlay", "direct"
							case "vpn-ra2.mts.ru", "login.mts.ru", "outside.example":
								wantDNS, wantRoute = "dns-direct", "direct"
							}
						}
						if got := renderedDomainTarget(root, "dns", domain); got != wantDNS {
							t.Fatalf("DNS %s = %s, want %s", domain, got, wantDNS)
						}
						if got := renderedDomainTarget(root, "route", domain); got != wantRoute {
							t.Fatalf("route %s = %s, want %s", domain, got, wantRoute)
						}
					}
					if bypass {
						for _, domain := range []string{"proxy.example.ru", "proxy.mts.ru"} {
							if renderedDomainTarget(root, "dns", domain) != "dns-proxy" || renderedDomainTarget(root, "route", domain) != "proxy" {
								t.Fatalf("proxy exception lost for %s", domain)
							}
						}
					}
					if overlay && bypass {
						rules := root["dns"].(map[string]any)["rules"].([]any)
						if len(rules) != 5 {
							t.Fatalf("DNS rules = %v", rules)
						}
						for i, want := range []string{"dns-proxy", "dns-direct", "dns-overlay", "dns-direct", "dns-proxy"} {
							if rules[i].(map[string]any)["server"] != want {
								t.Fatalf("DNS rule %d = %v, want %s", i, rules[i], want)
							}
						}
					}
				})
			}
		}
	}
}

func TestNormalizeOverlayDNSBypassDomains(t *testing.T) {
	t.Parallel()
	input := &OverlayDNS{Domains: []string{" MTS.RU ", "mts.ru", ""}, BypassDomains: []string{" VPN-RA2.MTS.RU ", "vpn-ra2.mts.ru", "", ".Login.Mts.Ru."}, Nameservers: []string{" 10.73.16.4 ", "10.73.16.4"}}
	got := normalizeOverlayDNS(input)
	if !slices.Equal(got.Domains, []string{"mts.ru"}) || !slices.Equal(got.BypassDomains, []string{"vpn-ra2.mts.ru", "login.mts.ru"}) || !slices.Equal(got.Nameservers, []string{"10.73.16.4"}) {
		t.Fatalf("normalized = %+v", got)
	}
	if input.BypassDomains[0] != " VPN-RA2.MTS.RU " {
		t.Fatal("normalization mutated input")
	}
	for _, invalid := range []*OverlayDNS{nil, {}, {Domains: []string{"mts.ru"}}, {Nameservers: []string{"10.73.16.4"}}, {Domains: []string{" "}, Nameservers: []string{"10.73.16.4"}, BypassDomains: []string{"login.mts.ru"}}} {
		if normalizeOverlayDNS(invalid) != nil {
			t.Fatalf("incomplete overlay accepted: %+v", invalid)
		}
	}
}

func TestRenderTUNProcessBypassDeduplicatesOpenconnect(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	data, err := renderWithProxyOutbound(cfg, model.Profile{}, RenderOptions{}, proxyRenderBackend{Outbound: map[string]any{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 20808, "version": "5"}, DirectProcessNames: []string{"xray", "openconnect", " xray "}})
	if err != nil {
		t.Fatal(err)
	}
	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	rule := root["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if !slices.Equal(rule["process_name"].([]any), []any{"xray", "openconnect"}) {
		t.Fatalf("process rule = %v", rule)
	}
}

// This proves the Xray client-only UDP/443 spelling becomes the equivalent
// flow accepted by sing-box without mutating the parsed profile.
func TestBuildVLESSOutboundNormalizesXrayUDP443FlowForSingbox(t *testing.T) {
	t.Parallel()

	profile := model.Profile{
		UUID: "00000000-0000-0000-0000-000000000000",
		Host: "example.com",
		Port: 443,
		Flow: "xtls-rprx-vision-udp443",
	}
	outbound, err := buildVLESSOutbound(config.Default(), profile)
	if err != nil {
		t.Fatalf("buildVLESSOutbound() error = %v", err)
	}
	if got, want := outbound["flow"], "xtls-rprx-vision"; got != want {
		t.Fatalf("outbound flow = %#v, want %#v", got, want)
	}
	if got, want := profile.Flow, "xtls-rprx-vision-udp443"; got != want {
		t.Fatalf("profile flow = %#v, want unchanged %#v", got, want)
	}
}

// This negative control proves the compatibility mapping does not silently
// rewrite unrelated flow values that sing-box should validate itself.
func TestBuildVLESSOutboundPreservesUnknownFlow(t *testing.T) {
	t.Parallel()

	profile := model.Profile{
		UUID: "00000000-0000-0000-0000-000000000000",
		Host: "example.com",
		Port: 443,
		Flow: "unknown-flow",
	}
	outbound, err := buildVLESSOutbound(config.Default(), profile)
	if err != nil {
		t.Fatalf("buildVLESSOutbound() error = %v", err)
	}
	if got, want := outbound["flow"], "unknown-flow"; got != want {
		t.Fatalf("outbound flow = %#v, want %#v", got, want)
	}
}

func TestRender(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) != 3 {
		t.Fatalf("outbounds = %#v, want 3 entries", root["outbounds"])
	}

	proxy, ok := outbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("proxy outbound shape = %#v", outbounds[0])
	}
	if got, want := proxy["server"], "203.0.113.77"; got != want {
		t.Fatalf("proxy.server = %#v, want %q", got, want)
	}

	direct, ok := outbounds[1].(map[string]any)
	if !ok {
		t.Fatalf("direct outbound shape = %#v", outbounds[1])
	}
	if got, want := direct["domain_resolver"], "dns-direct"; got != want {
		t.Fatalf("direct.domain_resolver = %#v, want %q", got, want)
	}

	route, ok := root["route"].(map[string]any)
	if !ok {
		t.Fatalf("route shape = %#v", root["route"])
	}
	if got, want := route["final"], "proxy"; got != want {
		t.Fatalf("route.final = %#v, want %q", got, want)
	}
	if _, ok := route["default_domain_resolver"]; !ok {
		t.Fatalf("route.default_domain_resolver missing from %#v", route)
	}
	ruleSet := route["rule_set"].([]any)
	if !hasRuleSet(ruleSet, "upstream-direct") {
		t.Fatalf("route.rule_set = %#v, want upstream-direct", ruleSet)
	}
	routeRules := route["rules"].([]any)
	if !hasRouteRule(routeRules, "upstream-direct", "direct") {
		t.Fatalf("route.rules = %#v, want upstream-direct direct rule", routeRules)
	}

	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) != 1 {
		t.Fatalf("inbounds = %#v, want 1 entry", root["inbounds"])
	}

	tunInbound, ok := inbounds[0].(map[string]any)
	if !ok {
		t.Fatalf("tun inbound shape = %#v", inbounds[0])
	}
	if got, want := tunInbound["type"], "tun"; got != want {
		t.Fatalf("tun inbound type = %#v, want %q", got, want)
	}
	routeExcludes, ok := tunInbound["route_exclude_address"].([]any)
	if !ok {
		t.Fatalf("tun.route_exclude_address = %#v, want []any", tunInbound["route_exclude_address"])
	}
	if !containsAnyString(routeExcludes, "203.0.113.77/32") {
		t.Fatalf("tun.route_exclude_address = %#v, want upstream endpoint", routeExcludes)
	}
}

func TestRenderXrayFrontendUsesLocalSocksAndDirectProcessRule(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Engine = &config.EngineConfig{
		Type: config.EngineXray,
		Xray: &config.XrayEngineConfig{
			SocksListen:  "127.0.0.1",
			SocksPort:    21808,
			ProcessNames: []string{"xray", "xray"},
		},
	}
	data, err := RenderXrayFrontendWithOptions(cfg, profiles[0], RenderOptions{})
	if err != nil {
		t.Fatalf("RenderXrayFrontendWithOptions returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	outbounds := root["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	if got, want := proxy["type"], "socks"; got != want {
		t.Fatalf("proxy.type = %#v, want %q", got, want)
	}
	if got, want := proxy["server"], "127.0.0.1"; got != want {
		t.Fatalf("proxy.server = %#v, want %q", got, want)
	}
	if got, want := proxy["server_port"], float64(21808); got != want {
		t.Fatalf("proxy.server_port = %#v, want %#v", got, want)
	}
	if got := proxy["uuid"]; got != nil {
		t.Fatalf("proxy.uuid = %#v, want nil for frontend socks outbound", got)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	if hasRuleSet(ruleSet, "upstream-direct") {
		t.Fatalf("route.rule_set = %#v, want no upstream-direct for xray frontend", ruleSet)
	}
	routeRules := route["rules"].([]any)
	firstRule := routeRules[0].(map[string]any)
	if got, want := firstRule["outbound"], "direct"; got != want {
		t.Fatalf("first route outbound = %#v, want %#v", got, want)
	}
	processNames := firstRule["process_name"].([]any)
	if len(processNames) != 2 || processNames[0] != "xray" || processNames[1] != "openconnect" {
		t.Fatalf("first route process_name = %#v, want [xray openconnect]", processNames)
	}

	inbounds := root["inbounds"].([]any)
	tunInbound := inbounds[0].(map[string]any)
	if got := tunInbound["route_exclude_address"]; got != nil {
		t.Fatalf("tun.route_exclude_address = %#v, want nil for xray frontend", got)
	}
}

func TestRenderWithOverlayDNSPrecedesPublicSuffixBypasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Network.Mode = config.RenderModeTun
	data, err := RenderWithOptions(cfg, profiles[0], RenderOptions{
		OverlayDNS: &OverlayDNS{
			Domains:       []string{"corp.example", "inside.corp.example"},
			Nameservers:   []string{"10.23.16.4", "10.23.0.23"},
			RouteExcludes: []string{"10.23.16.4/32", "10.23.0.23/32", "10.0.0.0/8"},
		},
	})
	if err != nil {
		t.Fatalf("RenderWithOptions returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	dns := root["dns"].(map[string]any)
	dnsServers := dns["servers"].([]any)
	if len(dnsServers) != 3 {
		t.Fatalf("expected direct + proxy + overlay dns servers, got %#v", dnsServers)
	}
	firstServer := dnsServers[0].(map[string]any)
	if got, want := firstServer["tag"], "dns-direct"; got != want {
		t.Fatalf("first dns tag = %#v, want %q", got, want)
	}
	secondServer := dnsServers[1].(map[string]any)
	if got, want := secondServer["tag"], "dns-proxy"; got != want {
		t.Fatalf("second dns tag = %#v, want %q", got, want)
	}
	overlayServer := dnsServers[2].(map[string]any)
	if got, want := overlayServer["tag"], "dns-overlay"; got != want {
		t.Fatalf("overlay dns tag = %#v, want %q", got, want)
	}
	if got, want := overlayServer["type"], "udp"; got != want {
		t.Fatalf("overlay dns type = %#v, want %q", got, want)
	}
	if got, want := overlayServer["server"], "10.23.16.4"; got != want {
		t.Fatalf("overlay dns server = %#v, want %q", got, want)
	}

	dnsRules := dns["rules"].([]any)
	if len(dnsRules) != 4 {
		t.Fatalf("dns rules = %#v, want 4 entries", dnsRules)
	}
	firstRule := dnsRules[0].(map[string]any)
	if got, want := firstRule["server"], "dns-proxy"; got != want {
		t.Fatalf("first dns rule server = %#v, want %q", got, want)
	}
	if got := firstRule["rule_set"]; !containsAnyString(got.([]any), "proxy-exceptions") {
		t.Fatalf("first dns rule_set = %#v, want proxy-exceptions", got)
	}

	secondRule := dnsRules[2].(map[string]any)
	if got, want := secondRule["server"], "dns-direct"; got != want {
		t.Fatalf("public suffix dns rule server = %#v, want %q", got, want)
	}
	if got := secondRule["rule_set"]; !containsAnyString(got.([]any), "ru-direct") {
		t.Fatalf("public suffix dns rule_set = %#v, want ru-direct", got)
	}

	overlayRule := dnsRules[1].(map[string]any)
	if got, want := overlayRule["server"], "dns-overlay"; got != want {
		t.Fatalf("overlay dns rule server = %#v, want %q", got, want)
	}
	domainSuffixes := overlayRule["domain_suffix"].([]any)
	if len(domainSuffixes) != 2 {
		t.Fatalf("overlay domain_suffix = %#v, want two values", domainSuffixes)
	}

	outbounds := root["outbounds"].([]any)
	direct := outbounds[1].(map[string]any)
	if got, want := direct["domain_resolver"], "dns-proxy"; got != want {
		t.Fatalf("direct.domain_resolver = %#v, want %q", got, want)
	}

	inbounds := root["inbounds"].([]any)
	tunInbound := inbounds[0].(map[string]any)
	routeExcludes, ok := tunInbound["route_exclude_address"].([]any)
	if !ok {
		t.Fatalf("tun.route_exclude_address = %#v, want []any", tunInbound["route_exclude_address"])
	}
	if len(routeExcludes) != 4 {
		t.Fatalf("tun.route_exclude_address = %#v, want four entries", routeExcludes)
	}
	for _, want := range []string{"203.0.113.77/32", "10.23.16.4/32", "10.23.0.23/32", "10.0.0.0/8"} {
		if !containsAnyString(routeExcludes, want) {
			t.Fatalf("tun.route_exclude_address = %#v, want %q", routeExcludes, want)
		}
	}
}

func TestRenderNormalizesIPv4MappedUpstreamHost(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}
	profile := profiles[0]
	profile.Host = "::ffff:203.0.113.77"

	cfg := config.Default()
	data, err := Render(cfg, profile)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	inbounds := root["inbounds"].([]any)
	tunInbound := inbounds[0].(map[string]any)
	routeExcludes := tunInbound["route_exclude_address"].([]any)
	if !containsAnyString(routeExcludes, "203.0.113.77/32") {
		t.Fatalf("tun.route_exclude_address = %#v, want mapped upstream endpoint as IPv4 CIDR", routeExcludes)
	}
}

func TestRenderSkipsUpstreamExcludeForDomainHost(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}
	profile := profiles[0]
	profile.Host = "vpn.example.com"

	cfg := config.Default()
	data, err := Render(cfg, profile)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	inbounds := root["inbounds"].([]any)
	tunInbound := inbounds[0].(map[string]any)
	if got := tunInbound["route_exclude_address"]; got != nil {
		t.Fatalf("tun.route_exclude_address = %#v, want nil for domain upstream", got)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	if hasRuleSet(ruleSet, "upstream-direct") {
		t.Fatalf("route.rule_set = %#v, want no upstream-direct for domain upstream", ruleSet)
	}

	outbounds := root["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	if got, want := proxy["domain_resolver"], "dns-direct"; got != want {
		t.Fatalf("proxy.domain_resolver = %#v, want %q", got, want)
	}
}

func TestRenderKeepsDirectDNSForDomainUpstreamWithOverlayDNS(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}
	profile := profiles[0]
	profile.Host = "vpn.example.com"

	cfg := config.Default()
	cfg.Routing.BypassSuffixes = nil
	cfg.Routing.BypassExcludes = nil

	data, err := RenderWithOptions(cfg, profile, RenderOptions{
		OverlayDNS: &OverlayDNS{
			Domains:     []string{"corp.example"},
			Nameservers: []string{"10.23.16.4"},
		},
	})
	if err != nil {
		t.Fatalf("RenderWithOptions returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	dns := root["dns"].(map[string]any)
	dnsServers := dns["servers"].([]any)
	if !hasTaggedServer(dnsServers, "dns-direct") {
		t.Fatalf("dns.servers = %#v, want dns-direct for domain upstream", dnsServers)
	}

	outbounds := root["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	if got, want := proxy["domain_resolver"], "dns-direct"; got != want {
		t.Fatalf("proxy.domain_resolver = %#v, want %q", got, want)
	}
}

func TestRenderWithoutBypasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Routing.BypassSuffixes = nil

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	if len(ruleSet) != 2 {
		t.Fatalf("expected proxy-exceptions and upstream-direct rule sets without direct bypasses, got %#v", ruleSet)
	}

	if !hasRuleSet(ruleSet, "proxy-exceptions") {
		t.Fatalf("route.rule_set = %#v, want proxy-exceptions", ruleSet)
	}
	if !hasRuleSet(ruleSet, "upstream-direct") {
		t.Fatalf("route.rule_set = %#v, want upstream-direct", ruleSet)
	}
}

func TestRenderAddsDirectRouteCIDRs(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Routing.Routes = []string{"10.0.0.0/8", "172.16.0.0/12"}

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	var directRoutes map[string]any
	for _, item := range ruleSet {
		entry := item.(map[string]any)
		if entry["tag"] == "direct-routes" {
			directRoutes = entry
			break
		}
	}
	if directRoutes == nil {
		t.Fatalf("route.rule_set = %#v, want direct-routes entry", ruleSet)
	}
	rules := directRoutes["rules"].([]any)
	ipCIDRs := rules[0].(map[string]any)["ip_cidr"].([]any)
	for _, want := range []string{"10.0.0.0/8", "172.16.0.0/12"} {
		if !containsAnyString(ipCIDRs, want) {
			t.Fatalf("direct-routes ip_cidr = %#v, want %q", ipCIDRs, want)
		}
	}
}

func TestRenderOrdersProxyExclusionsThenBypassesThenDirectCIDRs(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Routing.BypassSuffixes = []string{"direct.example"}
	cfg.Routing.BypassExcludes = []string{"proxy.example"}
	cfg.Routing.Routes = []string{"198.51.100.7/32"}

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	indexes := map[string]int{}
	for index, rawRule := range root["route"].(map[string]any)["rules"].([]any) {
		rule := rawRule.(map[string]any)
		rawTags, ok := rule["rule_set"].([]any)
		if !ok {
			continue
		}
		for _, rawTag := range rawTags {
			if tag, ok := rawTag.(string); ok {
				indexes[tag] = index
			}
		}
	}
	proxyException, hasProxyException := indexes["proxy-exceptions"]
	bypass, hasBypass := indexes["ru-direct"]
	directCIDR, hasDirectCIDR := indexes["direct-routes"]
	if !hasProxyException || !hasBypass || !hasDirectCIDR {
		t.Fatalf("route rule indexes = %v, want proxy exceptions, bypasses, and direct CIDRs", indexes)
	}
	if !(proxyException < bypass && bypass < directCIDR) {
		t.Fatalf("route precedence = proxy-exceptions:%d ru-direct:%d direct-routes:%d, want proxy exceptions before bypasses before direct CIDRs", proxyException, bypass, directCIDR)
	}
}

func TestRenderAppliesConfiguredSniffAndTLSClientOptions(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Singbox = &config.SingboxConfig{
		Sniff: &config.SniffConfig{
			Enabled:  boolPtr(true),
			Sniffers: []string{"tls", "http"},
			Timeout:  "1s",
		},
		TLS: config.TLSClientConfig{
			Fragment:              boolPtr(true),
			FragmentFallbackDelay: "250ms",
			RecordFragment:        boolPtr(true),
			CurvePreferences:      []string{"X25519MLKEM768", "X25519"},
		},
	}

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	outbounds := root["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	tlsConfig := proxy["tls"].(map[string]any)
	if got, want := tlsConfig["fragment"], true; got != want {
		t.Fatalf("tls.fragment = %#v, want %#v", got, want)
	}
	if got, want := tlsConfig["fragment_fallback_delay"], "250ms"; got != want {
		t.Fatalf("tls.fragment_fallback_delay = %#v, want %#v", got, want)
	}
	if got, want := tlsConfig["record_fragment"], true; got != want {
		t.Fatalf("tls.record_fragment = %#v, want %#v", got, want)
	}
	curvePreferences := tlsConfig["curve_preferences"].([]any)
	for _, want := range []string{"X25519MLKEM768", "X25519"} {
		if !containsAnyString(curvePreferences, want) {
			t.Fatalf("tls.curve_preferences = %#v, want %q", curvePreferences, want)
		}
	}

	route := root["route"].(map[string]any)
	routeRules := route["rules"].([]any)
	sniff := routeRules[2].(map[string]any)
	if got, want := sniff["action"], "sniff"; got != want {
		t.Fatalf("sniff.action = %#v, want %#v", got, want)
	}
	if got, want := sniff["timeout"], "1s"; got != want {
		t.Fatalf("sniff.timeout = %#v, want %#v", got, want)
	}
	sniffers := sniff["sniffer"].([]any)
	for _, want := range []string{"tls", "http"} {
		if !containsAnyString(sniffers, want) {
			t.Fatalf("sniff.sniffer = %#v, want %q", sniffers, want)
		}
	}
}

func TestRenderCanDisableSniffRule(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Singbox = &config.SingboxConfig{
		Sniff: &config.SniffConfig{
			Enabled: boolPtr(false),
		},
	}

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if err := vpncore.ValidateSingBoxConfig(data); err != nil {
		t.Fatalf("rendered config refused: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	route := root["route"].(map[string]any)
	routeRules := route["rules"].([]any)
	for _, item := range routeRules {
		rule := item.(map[string]any)
		if got, ok := rule["action"].(string); ok && got == "sniff" {
			t.Fatalf("route.rules = %#v, want no sniff action", routeRules)
		}
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func containsAnyString(items []any, want string) bool {
	for _, item := range items {
		if got, ok := item.(string); ok && got == want {
			return true
		}
	}
	return false
}

func hasRuleSet(items []any, tag string) bool {
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, ok := entry["tag"].(string); ok && got == tag {
			return true
		}
	}
	return false
}

func hasTaggedServer(items []any, tag string) bool {
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, ok := entry["tag"].(string); ok && got == tag {
			return true
		}
	}
	return false
}

func hasRouteRule(items []any, ruleSetTag, outbound string) bool {
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if got, ok := entry["outbound"].(string); !ok || got != outbound {
			continue
		}
		ruleSets, ok := entry["rule_set"].([]any)
		if !ok {
			continue
		}
		if containsAnyString(ruleSets, ruleSetTag) {
			return true
		}
	}
	return false
}

// Claim: the TUN inbound carries "stack" exactly when network.tun.stack is set, and omits it
// otherwise so the sing-box default is unchanged for existing configs.
func TestBuildInboundsRendersTunStackOnlyWhenSet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		stack string
		want  any
	}{
		{"", nil},
		{"gvisor", "gvisor"},
		{"system", "system"},
		{"mixed", "mixed"},
	} {
		cfg := config.Default()
		cfg.Network.Mode = config.RenderModeTun
		cfg.Network.TUN.Stack = tc.stack
		inbounds, err := buildInbounds(cfg, nil, nil)
		if err != nil {
			t.Fatalf("stack %q: buildInbounds() error = %v", tc.stack, err)
		}
		inbound := inbounds[0].(map[string]any)
		got, present := inbound["stack"]
		if tc.want == nil {
			if present {
				t.Fatalf("empty stack rendered %#v, want no key", got)
			}
			continue
		}
		if got != tc.want {
			t.Fatalf("stack %q rendered %#v", tc.stack, got)
		}
	}
}

// These tests validate the closed frontend schema and all three loop protections.
// They do not start sing-box, an OS TUN, or an AWG peer.
func TestRenderAWGFrontendLoopProtection(t *testing.T) {
	for _, tc := range []struct{ name, host, cidr string }{{"IPv4", "192.0.2.42", "192.0.2.42/32"}, {"IPv6", "2001:db8::42", "2001:db8::42/128"}, {"domain", "peer.example", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Engine = &config.EngineConfig{Type: config.EngineAWG}
			profile := model.Profile{Host: tc.host, Port: 51820}
			options := RenderOptions{}
			if tc.cidr == "" {
				options.OverlayDNS = &OverlayDNS{Domains: []string{"local.test"}, Nameservers: []string{"192.0.2.53"}}
			}
			data, err := RenderAWGFrontendWithOptions(cfg, profile, options)
			if err != nil {
				t.Fatal(err)
			}
			if err := vpncore.ValidateSingBoxConfig(data); err != nil {
				t.Fatalf("closed schema refused AWG frontend: %v", err)
			}
			var root map[string]any
			if err := json.Unmarshal(data, &root); err != nil {
				t.Fatal(err)
			}
			proxy := root["outbounds"].([]any)[0].(map[string]any)
			if proxy["type"] != "socks" || proxy["tag"] != "proxy" || proxy["server"] != "127.0.0.1" || proxy["server_port"] != float64(20809) || proxy["version"] != "5" {
				t.Fatalf("unexpected SOCKS outbound: %v", proxy)
			}
			route := root["route"].(map[string]any)
			rules := route["rules"].([]any)
			first := rules[0].(map[string]any)
			names := first["process_name"].([]any)
			if first["outbound"] != "direct" || !slices.Contains(names, any("tun-wave")) || !slices.Contains(names, any("vless-tun")) || !slices.Contains(names, any("openconnect")) {
				t.Fatal("sidecar process bypass missing")
			}
			tun := root["inbounds"].([]any)[0].(map[string]any)
			if tc.cidr != "" {
				excludes, ok := tun["route_exclude_address"].([]any)
				if !ok || !slices.Contains(excludes, any(tc.cidr)) {
					t.Fatal("upstream route exclusion missing")
				}
				sets := route["rule_set"].([]any)
				found := false
				for _, item := range sets {
					set := item.(map[string]any)
					if set["tag"] == "upstream-direct" {
						found = true
						if set["type"] != "inline" {
							t.Fatal("upstream set is not inline")
						}
						cidrs := set["rules"].([]any)[0].(map[string]any)["ip_cidr"].([]any)
						if !slices.Contains(cidrs, any(tc.cidr)) {
							t.Fatal("upstream rule set excludes wrong endpoint")
						}
					}
				}
				if !found {
					t.Fatal("upstream-direct rule set missing")
				}
				direct := false
				for _, item := range rules {
					r := item.(map[string]any)
					sets, ok := r["rule_set"].([]any)
					if ok && slices.Contains(sets, any("upstream-direct")) && r["outbound"] == "direct" {
						direct = true
					}
				}
				if !direct {
					t.Fatal("upstream direct routing missing")
				}
			} else {
				dns := root["dns"].(map[string]any)
				direct := false
				for _, item := range dns["servers"].([]any) {
					server := item.(map[string]any)
					if server["tag"] == "dns-direct" && server["type"] == "local" && server["detour"] == "direct" {
						direct = true
					}
				}
				if !direct {
					t.Fatal("endpoint hostname must resolve directly")
				}
			}
		})
	}
}
