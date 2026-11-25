// Package failclosed resolves the fail-closed service list and renders the pf
// anchor that refuses listed services on physical interfaces while the
// personal tunnel is down. It is pure: no pfctl, no network, no privileges.
package failclosed

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// AnchorName is the pf anchor owned by the vpn-core helper. macOS evaluates
// only anchors the main ruleset references; /etc/pf.conf references
// "com.apple/*", so the anchor lives there and pf.conf is never edited.
const AnchorName = "com.apple/works.relux.vpn-core.failclosed"

// TableName is the pf table inside the anchor.
const TableName = "failclosed"

// MaxEntries bounds the address table.
const MaxEntries = 4096

// AddressTTL is how long a resolved address stays in the table after it was
// last seen while the tunnel was up.
const AddressTTL = 24 * time.Hour

// Service is one fail-closed service: domain suffixes and fixed ranges.
type Service struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
}

// Catalog is the built-in service catalog. Only DefaultEnabled is enabled
// when the configuration names nothing.
var Catalog = map[string]Service{
	"codex": {
		Name:    "codex",
		Domains: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
	},
	"claude": {
		Name:    "claude",
		Domains: []string{"anthropic.com", "claude.ai", "claude.com"},
		CIDRs:   []string{"160.79.104.0/23"},
	},
	"antigravity": {
		Name:    "antigravity",
		Domains: []string{"cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com"},
	},
}

// DefaultEnabled is the enabled list when fail_closed is absent or freshly
// installed (owner decision: Codex only until it has run without breakage).
var DefaultEnabled = []string{"codex"}

// Policy is the resolved, validated fail-closed policy.
type Policy struct {
	Enabled         bool
	TunnelInterface string
	Services        []Service
}

// Entry is one configured service reference: a catalog name or a full object.
type Entry struct {
	Name    string
	Service *Service
}

var (
	serviceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	domainLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	utunRE        = regexp.MustCompile(`^utun[0-9]{1,4}$`)
)

// Resolve turns the configured fields into a Policy. A nil enabled means true;
// nil entries mean DefaultEnabled.
func Resolve(enabled *bool, tunnelInterface string, entries []Entry) (Policy, error) {
	p := Policy{Enabled: enabled == nil || *enabled, TunnelInterface: strings.TrimSpace(tunnelInterface)}
	if p.TunnelInterface != "" && !utunRE.MatchString(p.TunnelInterface) {
		return Policy{}, fmt.Errorf("fail_closed.tunnel_interface %q must be a utun interface name such as utun233", p.TunnelInterface)
	}
	if entries == nil {
		for _, name := range DefaultEnabled {
			entries = append(entries, Entry{Name: name})
		}
	}
	seen := map[string]bool{}
	for i, e := range entries {
		var svc Service
		switch {
		case e.Service != nil:
			svc = *e.Service
		default:
			c, ok := Catalog[strings.TrimSpace(e.Name)]
			if !ok {
				return Policy{}, fmt.Errorf("fail_closed.services[%d]: %q is not a catalog service (%s); give a full object with domains or cidrs instead", i, e.Name, strings.Join(catalogNames(), ", "))
			}
			svc = c
		}
		norm, err := normalizeService(svc)
		if err != nil {
			return Policy{}, fmt.Errorf("fail_closed.services[%d]: %w", i, err)
		}
		if seen[norm.Name] {
			return Policy{}, fmt.Errorf("fail_closed.services[%d]: duplicate service %q", i, norm.Name)
		}
		seen[norm.Name] = true
		p.Services = append(p.Services, norm)
	}
	return p, nil
}

func catalogNames() []string {
	names := make([]string, 0, len(Catalog))
	for n := range Catalog {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func normalizeService(s Service) (Service, error) {
	out := Service{Name: strings.TrimSpace(s.Name)}
	if !serviceNameRE.MatchString(out.Name) {
		return Service{}, fmt.Errorf("service name %q must be 1-32 lowercase letters, digits or hyphens", s.Name)
	}
	for _, d := range s.Domains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if err := validDomain(d); err != nil {
			return Service{}, fmt.Errorf("service %q: %w", out.Name, err)
		}
		if !slices.Contains(out.Domains, d) {
			out.Domains = append(out.Domains, d)
		}
	}
	for _, c := range s.CIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return Service{}, fmt.Errorf("service %q: cidr %q: %v", out.Name, c, err)
		}
		if err := admissiblePrefix(prefix); err != nil {
			return Service{}, fmt.Errorf("service %q: cidr %q: %w", out.Name, c, err)
		}
		norm := prefix.Masked().String()
		if !slices.Contains(out.CIDRs, norm) {
			out.CIDRs = append(out.CIDRs, norm)
		}
	}
	if len(out.Domains) == 0 && len(out.CIDRs) == 0 {
		return Service{}, fmt.Errorf("service %q needs at least one domain or cidr", out.Name)
	}
	return out, nil
}

func validDomain(d string) error {
	if d == "" || len(d) > 253 {
		return fmt.Errorf("domain %q is empty or too long", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("domain %q must have at least two labels", d)
	}
	for _, l := range labels {
		if !domainLabelRE.MatchString(l) {
			return fmt.Errorf("domain %q has an invalid label %q", d, l)
		}
	}
	return nil
}

// admissiblePrefix refuses ranges that would block local or private traffic,
// and ranges broader than /8 (IPv4) or /32 (IPv6).
func admissiblePrefix(p netip.Prefix) error {
	a := p.Addr()
	switch {
	case a.Is4() && p.Bits() < 8, a.Is6() && !a.Is4In6() && p.Bits() < 32:
		return errors.New("range is broader than /8 (IPv4) or /32 (IPv6)")
	case a.IsLoopback(), a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsMulticast(), a.IsUnspecified(), a.IsLinkLocalMulticast():
		return errors.New("range is local, private, link-local or multicast")
	case a.Is4() && netip.MustParsePrefix("100.64.0.0/10").Overlaps(p):
		return errors.New("range overlaps carrier-grade NAT space 100.64.0.0/10")
	}
	return nil
}

// MatchesDomain reports whether host belongs to any service domain suffix.
func (p Policy) MatchesDomain(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, s := range p.Services {
		for _, d := range s.Domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}

// Table is the address table with last-seen times for resolved hosts.
type Table struct {
	Entries map[string]time.Time `json:"entries"`
}

// Merge records addresses observed for listed domains at now. Inadmissible
// addresses (private, loopback, ...) are dropped and returned.
func (t *Table) Merge(addrs []netip.Addr, now time.Time) (dropped []netip.Addr) {
	if t.Entries == nil {
		t.Entries = map[string]time.Time{}
	}
	for _, a := range addrs {
		a = a.Unmap()
		bits := 32
		if a.Is6() {
			bits = 128
		}
		pfx := netip.PrefixFrom(a, bits)
		if !a.IsValid() || admissiblePrefix(pfx) != nil {
			dropped = append(dropped, a)
			continue
		}
		t.Entries[pfx.String()] = now
	}
	return dropped
}

// Prune drops addresses not seen for AddressTTL. While the tunnel is down
// nothing is dropped, so an outage never empties the table.
func (t *Table) Prune(now time.Time, tunnelUp bool) {
	if !tunnelUp {
		return
	}
	for k, seen := range t.Entries {
		if now.Sub(seen) > AddressTTL {
			delete(t.Entries, k)
		}
	}
}

// Contents returns the sorted, de-duplicated table: policy CIDRs plus
// resolved addresses, bounded by MaxEntries.
func (p Policy) Contents(t Table) ([]string, error) {
	set := map[string]bool{}
	for _, s := range p.Services {
		for _, c := range s.CIDRs {
			set[c] = true
		}
	}
	for k := range t.Entries {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > MaxEntries {
		return nil, fmt.Errorf("fail-closed table has %d entries, more than %d", len(out), MaxEntries)
	}
	return out, nil
}

// ValidateTable checks table entries received over the helper RPC: each must
// be an admissible prefix; the result is sorted, de-duplicated and bounded.
func ValidateTable(entries []string) ([]string, error) {
	set := map[string]bool{}
	for _, e := range entries {
		p, err := netip.ParsePrefix(strings.TrimSpace(e))
		if err != nil {
			return nil, fmt.Errorf("table entry %q: %v", e, err)
		}
		if err := admissiblePrefix(p); err != nil {
			return nil, fmt.Errorf("table entry %q: %w", e, err)
		}
		set[p.Masked().String()] = true
	}
	if len(set) > MaxEntries {
		return nil, fmt.Errorf("table has %d entries, more than %d", len(set), MaxEntries)
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// physicalIfRE admits interface names the block rule may name.
var physicalIfRE = regexp.MustCompile(`^(en|bridge)[0-9]{1,3}$`)

// RenderAnchor renders the anchor rules for the given physical interfaces.
// The rules never name a utun interface, so tunnel and work VPN traffic is
// never matched.
func RenderAnchor(physical []string) (string, error) {
	if len(physical) == 0 {
		return "", errors.New("no physical interfaces to protect")
	}
	ifs := append([]string(nil), physical...)
	sort.Strings(ifs)
	ifs = slices.Compact(ifs)
	for _, i := range ifs {
		if !physicalIfRE.MatchString(i) {
			return "", fmt.Errorf("interface %q is not a physical interface name (en*, bridge*)", i)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s: refuse listed services outside the tunnel (managed by vpn-core)\n", AnchorName)
	fmt.Fprintf(&b, "table <%s> persist\n", TableName)
	fmt.Fprintf(&b, "block return out quick on { %s } to <%s>\n", strings.Join(ifs, " "), TableName)
	return b.String(), nil
}
