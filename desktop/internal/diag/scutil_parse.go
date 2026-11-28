package diag

import (
	"strconv"
	"strings"
)

type ScutilResolver struct {
	ID          int      `json:"id"`
	Scoped      bool     `json:"scoped"`
	Domain      string   `json:"domain,omitempty"`
	Search      []string `json:"search_domains,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	IfIndex     string   `json:"if_index,omitempty"`
	Flags       string   `json:"flags,omitempty"`
	Reach       string   `json:"reach,omitempty"`
	Order       int      `json:"order,omitempty"`
}
type ScutilDNSSnapshot struct {
	Resolvers []ScutilResolver `json:"resolvers"`
}
type ResolverMatch struct {
	ResolverID    int      `json:"resolver_id"`
	MatchedDomain string   `json:"matched_domain,omitempty"`
	Scoped        bool     `json:"scoped"`
	Nameservers   []string `json:"nameservers"`
	Interface     string   `json:"interface,omitempty"`
	Flags         string   `json:"flags,omitempty"`
	Reach         string   `json:"reach,omitempty"`
	MatchReason   string   `json:"match_reason"`
}

func ParseScutilDNS(output string) ScutilDNSSnapshot {
	var snap ScutilDNSSnapshot
	scoped := false
	var r *ScutilResolver
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "DNS configuration") {
			scoped = strings.Contains(line, "scoped queries")
			r = nil
			continue
		}
		if strings.HasPrefix(line, "resolver #") {
			id, _ := strconv.Atoi(strings.TrimPrefix(line, "resolver #"))
			snap.Resolvers = append(snap.Resolvers, ScutilResolver{ID: id, Scoped: scoped})
			r = &snap.Resolvers[len(snap.Resolvers)-1]
			continue
		}
		if r == nil {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch {
		case key == "domain":
			r.Domain = val
		case strings.HasPrefix(key, "search domain["):
			r.Search = append(r.Search, val)
		case strings.HasPrefix(key, "nameserver["):
			r.Nameservers = append(r.Nameservers, val)
		case key == "if_index":
			if fields := strings.Fields(val); len(fields) > 0 {
				r.IfIndex = fields[0]
			}
			if start := strings.Index(val, "("); start >= 0 {
				r.Interface = strings.TrimSuffix(val[start+1:], ")")
			}
		case key == "flags":
			r.Flags = val
		case key == "reach":
			r.Reach = val
		case key == "order":
			r.Order, _ = strconv.Atoi(val)
		}
	}
	return snap
}
func normalizeHost(host string) string { return strings.ToLower(strings.TrimSuffix(host, ".")) }
func normalizeDomain(domain string) string {
	return strings.TrimPrefix(normalizeHost(domain), ".")
}
func suffixMatch(host, domain string) bool {
	domain = normalizeDomain(domain)
	return domain != "" && (host == domain || strings.HasSuffix(host, "."+domain))
}
func MatchResolverForHost(snap ScutilDNSSnapshot, host string) *ResolverMatch {
	host = normalizeHost(host)
	var best *ScutilResolver
	for i := range snap.Resolvers {
		r := &snap.Resolvers[i]
		if r.Scoped || (r.Domain != "" && !suffixMatch(host, r.Domain)) {
			continue
		}
		rLen := len(normalizeDomain(r.Domain))
		bestLen := -1
		if best != nil {
			bestLen = len(normalizeDomain(best.Domain))
		}
		if best == nil || rLen > bestLen || (rLen == bestLen && (r.Order < best.Order || (r.Order == best.Order && r.ID < best.ID))) {
			best = r
		}
	}
	if best == nil {
		return nil
	}
	reason := "default resolver"
	if best.Domain != "" {
		reason = "longest domain suffix"
	}
	return &ResolverMatch{ResolverID: best.ID, MatchedDomain: best.Domain, Scoped: best.Scoped, Nameservers: best.Nameservers, Interface: best.Interface, Flags: best.Flags, Reach: best.Reach, MatchReason: reason}
}
