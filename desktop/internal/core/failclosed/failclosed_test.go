package failclosed

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func boolp(b bool) *bool { return &b }

// Claim: with no configured list the policy is enabled and holds Codex only (owner decision),
// even though the catalog contains three services.
func TestResolveDefaultIsCodexOnly(t *testing.T) {
	p, err := Resolve(nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || len(p.Services) != 1 || p.Services[0].Name != "codex" {
		t.Fatalf("default policy = %+v, want enabled codex only", p)
	}
	if len(Catalog) != 3 {
		t.Fatalf("catalog size %d, want 3", len(Catalog))
	}
}

// Claim: all three catalog services resolve by name, and an object with a catalog name replaces
// that catalog entry instead of merging with it.
func TestResolveCatalogAndOverride(t *testing.T) {
	p, err := Resolve(boolp(true), "utun233", []Entry{{Name: "codex"}, {Name: "claude"}, {Name: "antigravity"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Services) != 3 || p.TunnelInterface != "utun233" {
		t.Fatalf("policy = %+v", p)
	}
	p, err = Resolve(nil, "", []Entry{{Service: &Service{Name: "codex", Domains: []string{"Example.COM."}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Services[0].Domains; len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("override domains = %v, want [example.com]", got)
	}
}

// Claim: enabled=false resolves to a disabled policy while still validating the list.
func TestResolveDisabled(t *testing.T) {
	p, err := Resolve(boolp(false), "", nil)
	if err != nil || p.Enabled {
		t.Fatalf("disabled policy = %+v, err %v", p, err)
	}
}

// Claim: every refusal named in contract r3 §1 is refused with the offending field in the message;
// none of these configurations yields a policy.
func TestResolveRefusals(t *testing.T) {
	cases := map[string]struct {
		iface   string
		entries []Entry
		want    string
	}{
		"unknown catalog name":  {"", []Entry{{Name: "gemini"}}, "not a catalog service"},
		"duplicate":             {"", []Entry{{Name: "codex"}, {Name: "codex"}}, "duplicate service"},
		"empty service":         {"", []Entry{{Service: &Service{Name: "x"}}}, "at least one domain, host or cidr"},
		"bad name":              {"", []Entry{{Service: &Service{Name: "Bad Name", Domains: []string{"a.com"}}}}, "service name"},
		"single label domain":   {"", []Entry{{Service: &Service{Name: "x", Domains: []string{"localhost"}}}}, "two labels"},
		"bad label":             {"", []Entry{{Service: &Service{Name: "x", Domains: []string{"a_b.com"}}}}, "invalid label"},
		"malformed cidr":        {"", []Entry{{Service: &Service{Name: "x", CIDRs: []string{"1.2.3/24"}}}}, "cidr"},
		"too broad v4":          {"", []Entry{{Service: &Service{Name: "x", CIDRs: []string{"0.0.0.0/0"}}}}, "broader than"},
		"too broad v6":          {"", []Entry{{Service: &Service{Name: "x", CIDRs: []string{"2000::/3"}}}}, "broader than"},
		"private range":         {"", []Entry{{Service: &Service{Name: "x", CIDRs: []string{"10.0.0.0/8"}}}}, "private"},
		"cgnat range":           {"", []Entry{{Service: &Service{Name: "x", CIDRs: []string{"100.64.0.0/16"}}}}, "carrier-grade"},
		"non-utun tunnel iface": {"en0", nil, "utun interface"},
	}
	for name, tc := range cases {
		_, err := Resolve(nil, tc.iface, tc.entries)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", name, err, tc.want)
		}
	}
}

// Claim: domain matching is suffix-based on label boundaries; a look-alike that merely ends with
// the same characters does not match (negative control).
func TestMatchesDomain(t *testing.T) {
	p, _ := Resolve(nil, "", nil)
	for _, h := range []string{"chatgpt.com", "api.openai.com", "CDN.OAISTATIC.COM."} {
		if !p.MatchesDomain(h) {
			t.Errorf("%s should match", h)
		}
	}
	for _, h := range []string{"notchatgpt.com", "openai.com.evil.net", "anthropic.com"} {
		if p.MatchesDomain(h) {
			t.Errorf("%s must not match the codex-only policy", h)
		}
	}
}

// Claim: Merge keeps public addresses as host prefixes and drops local/private ones; Prune ages out
// entries older than AddressTTL only while the tunnel is up, never while it is down.
func TestTableMergeAndPrune(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	var tb Table
	dropped := tb.Merge([]netip.Addr{
		netip.MustParseAddr("104.18.32.47"), netip.MustParseAddr("2606:4700::6812:202f"),
		netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:172.19.0.2"),
	}, now)
	if len(dropped) != 3 || len(tb.Entries) != 2 {
		t.Fatalf("entries %v dropped %v", tb.Entries, dropped)
	}
	later := now.Add(AddressTTL + time.Minute)
	tb.Prune(later, false)
	if len(tb.Entries) != 2 {
		t.Fatalf("prune while tunnel down removed entries: %v", tb.Entries)
	}
	tb.Merge([]netip.Addr{netip.MustParseAddr("104.18.32.47")}, later)
	tb.Prune(later, true)
	if _, ok := tb.Entries["104.18.32.47/32"]; !ok || len(tb.Entries) != 1 {
		t.Fatalf("prune while up = %v, want only the refreshed v4 entry", tb.Entries)
	}
}

// Claim: Contents unions policy CIDRs and table entries, sorted and de-duplicated, and refuses a
// table above MaxEntries.
func TestContents(t *testing.T) {
	p, _ := Resolve(nil, "", []Entry{{Name: "claude"}})
	tb := Table{Entries: map[string]time.Time{"160.79.104.0/23": {}, "1.1.1.1/32": {}}}
	got, err := p.Contents(tb)
	if err != nil || strings.Join(got, ",") != "1.1.1.1/32,160.79.104.0/23" {
		t.Fatalf("contents = %v, %v", got, err)
	}
	big := Table{Entries: map[string]time.Time{}}
	for i := 0; i <= MaxEntries; i++ {
		big.Entries[netip.AddrFrom4([4]byte{8, byte(i >> 16), byte(i >> 8), byte(i)}).String()+"/32"] = time.Time{}
	}
	if _, err := p.Contents(big); err == nil {
		t.Fatal("oversized table accepted")
	}
}

// Claim: the rendered anchor matches the golden file for two physical interfaces and never names a
// utun interface; any non-physical interface name is refused (a rule naming utun233 would block the
// tunnel itself).
func TestRenderAnchorGoldenAndRefusals(t *testing.T) {
	got, err := RenderAnchor([]string{"en1", "en0", "en0"})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "anchor-en0-en1.golden")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		os.WriteFile(golden, []byte(got), 0o644)
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("anchor:\n%s\nwant:\n%s", got, want)
	}
	if strings.Contains(got, "utun") {
		t.Fatal("anchor names a utun interface")
	}
	for _, bad := range [][]string{nil, {"utun233"}, {"en0", "utun4"}, {"lo0"}, {"en0; pass all"}} {
		if _, err := RenderAnchor(bad); err == nil {
			t.Errorf("RenderAnchor(%q) accepted", bad)
		}
	}
}

// Claim: ValidateTable normalizes and de-duplicates admissible prefixes and refuses malformed,
// private and over-broad entries arriving over the RPC.
func TestValidateTable(t *testing.T) {
	got, err := ValidateTable([]string{"1.1.1.1/32", " 1.1.1.1/32", "160.79.105.7/23"})
	if err != nil || strings.Join(got, ",") != "1.1.1.1/32,160.79.104.0/23" {
		t.Fatalf("ValidateTable = %v, %v", got, err)
	}
	for _, bad := range []string{"1.1.1.1", "192.168.1.0/24", "0.0.0.0/0", "fe80::1/128", "x"} {
		if _, err := ValidateTable([]string{bad}); err == nil {
			t.Errorf("ValidateTable(%q) accepted", bad)
		}
	}
}

// Claim: ValidateTable, which bounds the table the helper accepts, admits exactly MaxEntries distinct
// entries and refuses one more; duplicates of an entry do not count toward the bound. Limit: only
// /32 entries from one public /8 are used.
func TestValidateTableEntryLimit(t *testing.T) {
	entries := make([]string, 0, MaxEntries+1)
	for i := 0; i <= MaxEntries; i++ {
		entries = append(entries, fmt.Sprintf("11.%d.%d.%d/32", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	got, err := ValidateTable(entries[:MaxEntries])
	if err != nil || len(got) != MaxEntries {
		t.Fatalf("MaxEntries entries: %d accepted, err %v", len(got), err)
	}
	withDuplicates := append(append([]string{}, entries[:MaxEntries]...), entries[0], " "+entries[1])
	if got, err := ValidateTable(withDuplicates); err != nil || len(got) != MaxEntries {
		t.Fatalf("MaxEntries entries plus duplicates: %d accepted, err %v", len(got), err)
	}
	if got, err := ValidateTable(entries); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("MaxEntries+1 entries: accepted %d, err %v", len(got), err)
	}
}

// Claim: the catalog's resolve set is pinned exactly to the endpoints observed in real sessions
// (review/ENDPOINTS-r1.md) plus apex/api/www of each suffix; a dropped or added endpoint fails here.
func TestCatalogResolveSetPinned(t *testing.T) {
	want := map[string]string{
		"codex":       "ab.chatgpt.com,api.chatgpt.com,api.oaistatic.com,api.oaiusercontent.com,api.openai.com,auth.openai.com,chatgpt.com,oaistatic.com,oaiusercontent.com,openai.com,persistent.oaistatic.com,www.chatgpt.com,www.oaistatic.com,www.oaiusercontent.com,www.openai.com",
		"claude":      "anthropic.com,api.anthropic.com,api.claude.ai,api.claude.com,claude.ai,claude.com,console.anthropic.com,downloads.claude.ai,mcp-proxy.anthropic.com,platform.claude.com,www.anthropic.com,www.claude.ai,www.claude.com",
		"antigravity": "aicode.googleapis.com,antigravity.google,api.antigravity.google,api.cloudcode-pa.googleapis.com,api.daily-cloudcode-pa.googleapis.com,cloudcode-pa.googleapis.com,daily-cloudcode-pa.googleapis.com,oauth2.googleapis.com,www.antigravity.google,www.cloudcode-pa.googleapis.com,www.daily-cloudcode-pa.googleapis.com",
	}
	for name, names := range want {
		p, err := Resolve(nil, "", []Entry{{Name: name}})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(p.ResolveNames(), ","); got != names {
			t.Errorf("%s resolve set:\n got %s\nwant %s", name, got, names)
		}
	}
	if p, _ := Resolve(nil, "", []Entry{{Name: "claude"}}); strings.Join(p.Services[0].CIDRs, ",") != "160.79.104.0/23" {
		t.Errorf("claude cidrs = %v", p.Services[0].CIDRs)
	}
}
