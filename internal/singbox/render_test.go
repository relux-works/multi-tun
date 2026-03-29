package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"multi-tun/internal/config"
	"multi-tun/internal/subscription"
)

func TestRender(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
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
}

func TestRenderWithOverlayDNSUsesProxyForGenericBypasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Render.Mode = config.RenderModeTun
	data, err := RenderWithOptions(cfg, profiles[0], RenderOptions{
		OverlayDNS: &OverlayDNS{
			Domains:     []string{"corp.example", "inside.corp.example"},
			Nameservers: []string{"10.23.16.4", "10.23.0.23"},
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
	if len(dnsServers) != 2 {
		t.Fatalf("expected proxy + overlay dns servers, got %#v", dnsServers)
	}
	firstServer := dnsServers[0].(map[string]any)
	if got, want := firstServer["tag"], "dns-proxy"; got != want {
		t.Fatalf("proxy dns tag = %#v, want %q", got, want)
	}
	overlayServer := dnsServers[1].(map[string]any)
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
	firstRule := dnsRules[0].(map[string]any)
	if got, want := firstRule["server"], "dns-overlay"; got != want {
		t.Fatalf("first dns rule server = %#v, want %q", got, want)
	}
	domainSuffixes := firstRule["domain_suffix"].([]any)
	if len(domainSuffixes) != 2 {
		t.Fatalf("overlay domain_suffix = %#v, want two values", domainSuffixes)
	}
	for _, rawRule := range dnsRules {
		rule := rawRule.(map[string]any)
		if got, ok := rule["server"]; ok && got == "dns-direct" {
			t.Fatalf("unexpected dns-direct rule under overlay: %#v", rule)
		}
	}
	for _, rawServer := range dnsServers {
		server := rawServer.(map[string]any)
		if got, ok := server["tag"]; ok && got == "dns-direct" {
			t.Fatalf("unexpected dns-direct server under overlay: %#v", server)
		}
	}

	outbounds := root["outbounds"].([]any)
	direct := outbounds[1].(map[string]any)
	if got, want := direct["domain_resolver"], "dns-proxy"; got != want {
		t.Fatalf("direct.domain_resolver = %#v, want %q", got, want)
	}
}

func TestRenderWithoutBypasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Render.BypassSuffixes = nil

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

func TestRenderSystemProxyMode(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Render.Mode = config.RenderModeSystemProxy
	cfg.Render.BypassSuffixes = nil

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	inbounds := root["inbounds"].([]any)
	inbound := inbounds[0].(map[string]any)
	if got, want := inbound["type"], "mixed"; got != want {
		t.Fatalf("inbound.type = %#v, want %q", got, want)
	}
	if got, want := inbound["set_system_proxy"], true; got != want {
		t.Fatalf("inbound.set_system_proxy = %#v, want %v", got, want)
	}

	route := root["route"].(map[string]any)
	rules := route["rules"].([]any)
	for _, rawRule := range rules {
		rule := rawRule.(map[string]any)
		if _, ok := rule["protocol"]; ok {
			t.Fatalf("unexpected protocol rule in system proxy mode: %#v", rule)
		}
	}
}

func TestRenderSystemProxyModeWithBypasses(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	cfg := config.Default()
	cfg.Render.Mode = config.RenderModeSystemProxy
	cfg.Render.BypassSuffixes = []string{".ru", ".xn--p1ai"}

	data, err := Render(cfg, profiles[0])
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	dns := root["dns"].(map[string]any)
	dnsRules := dns["rules"].([]any)
	if len(dnsRules) != 1 {
		t.Fatalf("expected only proxy dns rule in system proxy mode, got %#v", dnsRules)
	}

	dnsServers := dns["servers"].([]any)
	if len(dnsServers) != 2 {
		t.Fatalf("expected local + proxy dns servers in system proxy mode, got %#v", dnsServers)
	}

	route := root["route"].(map[string]any)
	ruleSet := route["rule_set"].([]any)
	if len(ruleSet) != 2 {
		t.Fatalf("expected proxy-exceptions + direct bypass rule_set, got %#v", ruleSet)
	}

	firstRuleSet := ruleSet[0].(map[string]any)
	if got, want := firstRuleSet["tag"], "proxy-exceptions"; got != want {
		t.Fatalf("rule_set[0].tag = %#v, want %q", got, want)
	}

	secondRuleSet := ruleSet[1].(map[string]any)
	if got, want := secondRuleSet["tag"], "ru-direct"; got != want {
		t.Fatalf("rule_set[1].tag = %#v, want %q", got, want)
	}
}
