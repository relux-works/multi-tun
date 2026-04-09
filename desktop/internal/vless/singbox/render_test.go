package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/subscription"
)

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
	if got, want := proxy["server"], "144.31.90.46"; got != want {
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
}

func TestRenderWithOverlayDNSMakesBypassesWinBeforeOverlayDNS(t *testing.T) {
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

	secondRule := dnsRules[1].(map[string]any)
	if got, want := secondRule["server"], "dns-direct"; got != want {
		t.Fatalf("second dns rule server = %#v, want %q", got, want)
	}
	if got := secondRule["rule_set"]; !containsAnyString(got.([]any), "ru-direct") {
		t.Fatalf("second dns rule_set = %#v, want ru-direct", got)
	}

	overlayRule := dnsRules[2].(map[string]any)
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
	if len(routeExcludes) != 3 {
		t.Fatalf("tun.route_exclude_address = %#v, want three entries", routeExcludes)
	}
	for _, want := range []string{"10.23.16.4/32", "10.23.0.23/32", "10.0.0.0/8"} {
		if !containsAnyString(routeExcludes, want) {
			t.Fatalf("tun.route_exclude_address = %#v, want %q", routeExcludes, want)
		}
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

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	if len(ruleSet) != 1 {
		t.Fatalf("expected only proxy-exceptions rule_set without direct bypasses, got %#v", ruleSet)
	}

	inlineRuleSet := ruleSet[0].(map[string]any)
	if got, want := inlineRuleSet["tag"], "proxy-exceptions"; got != want {
		t.Fatalf("rule_set.tag = %#v, want %q", got, want)
	}
}

func containsAnyString(items []any, want string) bool {
	for _, item := range items {
		if got, ok := item.(string); ok && got == want {
			return true
		}
	}
	return false
}
