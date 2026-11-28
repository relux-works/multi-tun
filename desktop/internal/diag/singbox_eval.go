package diag

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

type SingBoxMatch struct {
	ConfigPath       string   `json:"config_path"`
	TUNInterface     string   `json:"tun_interface,omitempty"`
	TUNAddresses     []string `json:"tun_addresses,omitempty"`
	TUNExcluded      bool     `json:"tun_excluded"`
	TUNExcludeCIDR   string   `json:"tun_exclude_cidr,omitempty"`
	DNSRuleIndex     int      `json:"dns_rule_index"`
	DNSMatcher       string   `json:"dns_matcher"`
	DNSServerTag     string   `json:"dns_server_tag"`
	DNSServerAddress string   `json:"dns_server_address,omitempty"`
	DNSDetour        string   `json:"dns_detour,omitempty"`
	DNSStrategy      string   `json:"dns_strategy,omitempty"`
	RouteRuleIndex   int      `json:"route_rule_index"`
	RouteMatcher     string   `json:"route_matcher"`
	Outbound         string   `json:"outbound"`
	Notes            []string `json:"notes,omitempty"`
}
type sbRule map[string]json.RawMessage

func sbString(r sbRule, key string) string { var s string; _ = json.Unmarshal(r[key], &s); return s }
func sbStrings(r sbRule, key string) []string {
	var s []string
	if json.Unmarshal(r[key], &s) == nil {
		return s
	}
	v := sbString(r, key)
	if v != "" {
		return []string{v}
	}
	return nil
}
func containsIP(ips []netip.Addr, cidr string) bool {
	p, e := netip.ParsePrefix(cidr)
	if e != nil {
		return false
	}
	for _, ip := range ips {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// ruleMatch refuses unsupported predicates rather than claiming a routing match
// that needs process, protocol, port or runtime rule-set information.
func ruleMatch(r sbRule, sets map[string][]sbRule, host string, ips []netip.Addr, depth int) (bool, string, error) {
	if depth > 12 {
		return false, "", fmt.Errorf("recursive rule_set")
	}
	for k := range r {
		switch k {
		case "domain", "domain_suffix", "domain_keyword", "ip_cidr", "ip_is_private", "rule_set", "action", "outbound", "server", "invert":
		default:
			return false, "", fmt.Errorf("unsupported predicate %s", k)
		}
	}
	// sing-box ORs its supported destination predicates (domain/IP). A
	// single default inline rule is merged into that destination group; other
	// inline sets are an additional group. Unsupported context is refused above.
	destinationSet, destinationMatch := false, false
	reasons := []string{}
	for _, key := range []string{"domain", "domain_suffix", "domain_keyword", "ip_cidr", "ip_is_private"} {
		raw, exists := r[key]
		if !exists {
			continue
		}
		matched := false
		if key == "ip_is_private" {
			var enabled bool
			if err := json.Unmarshal(raw, &enabled); err != nil {
				return false, "", err
			}
			if !enabled {
				continue
			}
			for _, ip := range ips {
				matched = matched || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
			}
		} else {
			values := sbStrings(r, key)
			if len(values) == 0 {
				continue
			}
			for _, v := range values {
				switch key {
				case "domain":
					matched = matched || host == normalizeHost(v)
				case "domain_suffix":
					matched = matched || suffixMatch(host, v)
				case "domain_keyword":
					matched = matched || strings.Contains(host, strings.ToLower(v))
				case "ip_cidr":
					matched = matched || containsIP(ips, v)
				}
			}
		}
		destinationSet = true
		destinationMatch = destinationMatch || matched
		if matched {
			reasons = append(reasons, key)
		}
	}
	setRequired, setMatch := false, false
	simpleSet, complexSet := false, false
	for _, tag := range sbStrings(r, "rule_set") {
		rules, ok := sets[tag]
		if !ok {
			return false, "", fmt.Errorf("rule_set %q is not inline", tag)
		}
		// The renderer emits a single headless destination rule per inline set.
		// Multi-rule sets remain independent predicates, ORed across their tags.
		merge := len(rules) == 1
		if merge {
			for k := range rules[0] {
				switch k {
				case "domain", "domain_suffix", "domain_keyword", "ip_cidr", "ip_is_private":
				default:
					merge = false
				}
			}
		}
		matched := false
		for _, sub := range rules {
			yes, _, err := ruleMatch(sub, sets, host, ips, depth+1)
			if err != nil {
				return false, "", err
			}
			matched = matched || yes
		}
		if merge {
			simpleSet = true
			destinationSet = true
			destinationMatch = destinationMatch || matched
		} else {
			complexSet = true
			setRequired = true
			setMatch = setMatch || matched
		}
		if matched {
			reasons = append(reasons, "rule_set:"+tag)
		}
	}
	if simpleSet && complexSet {
		return false, "", fmt.Errorf("mixed merged and complex inline rule_sets require runtime evaluation")
	}
	matched := (!destinationSet || destinationMatch) && (!setRequired || setMatch)
	var invert bool
	if raw, ok := r["invert"]; ok {
		if err := json.Unmarshal(raw, &invert); err != nil {
			return false, "", err
		}
	}
	if invert {
		matched = !matched
	}
	reason := strings.Join(reasons, " | ")
	if reason == "" {
		reason = "all"
	}
	if invert {
		reason = "invert(" + reason + ")"
	}
	return matched, reason, nil
}
func EvaluateSingBoxConfig(data []byte, configPath, host string, ips []netip.Addr) (*SingBoxMatch, error) {
	var cfg struct {
		Inbounds []struct {
			Type      string   `json:"type"`
			Interface string   `json:"interface_name"`
			Address   []string `json:"address"`
			Excludes  []string `json:"route_exclude_address"`
		} `json:"inbounds"`
		DNS struct {
			Servers  []sbRule `json:"servers"`
			Rules    []sbRule `json:"rules"`
			Final    string   `json:"final"`
			Strategy string   `json:"strategy"`
		} `json:"dns"`
		Route struct {
			Sets []struct {
				Type  string   `json:"type"`
				Tag   string   `json:"tag"`
				Rules []sbRule `json:"rules"`
			} `json:"rule_set"`
			Rules []sbRule `json:"rules"`
			Final string   `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if len(cfg.Inbounds) == 0 && cfg.Route.Final == "" {
		return nil, fmt.Errorf("missing sing-box inbounds and route")
	}
	m := &SingBoxMatch{ConfigPath: configPath, DNSRuleIndex: -1, RouteRuleIndex: -1, DNSMatcher: "final", RouteMatcher: "final", DNSServerTag: cfg.DNS.Final, Outbound: cfg.Route.Final, DNSStrategy: cfg.DNS.Strategy}
	for _, in := range cfg.Inbounds {
		if in.Type != "tun" {
			continue
		}
		m.TUNInterface = in.Interface
		m.TUNAddresses = in.Address
		for _, cidr := range in.Excludes {
			if containsIP(ips, cidr) {
				m.TUNExcluded = true
				m.TUNExcludeCIDR = cidr
				break
			}
		}
		break
	}
	sets := map[string][]sbRule{}
	for _, s := range cfg.Route.Sets {
		if s.Type == "inline" {
			sets[s.Tag] = s.Rules
		}
	}
	host = normalizeHost(host)
	for i, r := range cfg.DNS.Rules {
		if sbString(r, "action") != "" && sbString(r, "action") != "route" {
			continue
		}
		yes, why, err := ruleMatch(r, sets, host, nil, 0)
		if err != nil {
			m.Outbound = "unknown"
			m.DNSMatcher = "unknown"
			return m, fmt.Errorf("dns rule %d: %w", i, err)
		}
		if yes {
			m.DNSRuleIndex = i
			m.DNSMatcher = why
			m.DNSServerTag = sbString(r, "server")
			break
		}
	}
	for _, s := range cfg.DNS.Servers {
		if sbString(s, "tag") == m.DNSServerTag {
			m.DNSServerAddress = sbString(s, "address")
			if m.DNSServerAddress == "" {
				m.DNSServerAddress = sbString(s, "server")
			}
			if m.DNSServerAddress == "" {
				m.DNSServerAddress = sbString(s, "type")
			}
			m.DNSDetour = sbString(s, "detour")
		}
	}
	for i, r := range cfg.Route.Rules {
		action := sbString(r, "action")
		if action != "" && action != "route" {
			m.Notes = append(m.Notes, fmt.Sprintf("rule %d: %s", i, action))
			continue
		}
		if _, ok := r["process_name"]; ok {
			m.Notes = append(m.Notes, fmt.Sprintf("rule %d requires process context", i))
			continue
		}
		if action == "" && sbString(r, "outbound") == "" {
			continue
		}
		yes, why, err := ruleMatch(r, sets, host, ips, 0)
		if err != nil {
			m.Outbound = "unknown"
			m.RouteMatcher = "unknown"
			return m, fmt.Errorf("route rule %d: %w", i, err)
		}
		if yes {
			m.RouteRuleIndex = i
			m.RouteMatcher = why
			m.Outbound = sbString(r, "outbound")
			break
		}
	}
	return m, nil
}
