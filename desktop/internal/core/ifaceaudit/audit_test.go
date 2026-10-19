package ifaceaudit

import (
	"os"
	"strings"
	"testing"
)

func liveVLESSInterface() Interface {
	return Interface{
		Name: "utun233",
		IPv4: []string{"172.19.0.1/30"},
		IPv6: []string{"fdfe:dcba:9876::1/126"},
		Up:   true,
	}
}

// This proves the private-address regression is resolved by exact live VLESS ownership, without destructive or zombie guidance.
func TestClassifyLiveVLESSPrivateAddressAsOwned(t *testing.T) {
	report := Classify(
		[]Interface{liveVLESSInterface()},
		[]Claim{{Engine: EngineVLESS, SessionID: "vless-live", Interface: "utun233", Liveness: LivenessAlive}},
		map[string]bool{"utun233": true},
	)

	got := report.Interfaces[0]
	if got.Class != ClassOwned || len(got.Claims) != 1 || got.Claims[0].Engine != EngineVLESS || got.Claims[0].SessionID != "vless-live" {
		t.Fatalf("classification = %#v, want owned VLESS session", got)
	}
	if len(got.Advice) != 0 {
		t.Fatalf("owned advice = %v, want none", got.Advice)
	}
	output := strings.ToLower(RenderText(report))
	for _, forbidden := range []string{"down", "zombie"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("owned output contains %q: %s", forbidden, output)
		}
	}
}

// This proves an indeterminate VLESS liveness check remains unverified and never receives cleanup advice.
func TestClassifyUnknownVLESSLivenessAsUnverified(t *testing.T) {
	report := Classify(
		[]Interface{liveVLESSInterface()},
		[]Claim{{Engine: EngineVLESS, SessionID: "vless-uncertain", Interface: "utun233", Liveness: LivenessUnknown}},
		nil,
	)

	got := report.Interfaces[0]
	if got.Class != ClassUnverified {
		t.Fatalf("class = %q, want %q", got.Class, ClassUnverified)
	}
	if len(got.Advice) != 1 || got.Advice[0] != "vless-tun status" {
		t.Fatalf("advice = %v, want status-only guidance", got.Advice)
	}
	if strings.Contains(strings.Join(got.Advice, " "), "stop") {
		t.Fatalf("unverified advice contains cleanup: %v", got.Advice)
	}
}

// This proves a dead VLESS claim on a still-up interface is stale and points only to the engine's stop command.
func TestClassifyDeadVLESSInterfaceAsStale(t *testing.T) {
	report := Classify(
		[]Interface{liveVLESSInterface()},
		[]Claim{{Engine: EngineVLESS, SessionID: "vless-dead", Interface: "utun233", Liveness: LivenessDead}},
		map[string]bool{"utun233": true},
	)

	got := report.Interfaces[0]
	if got.Class != ClassStale {
		t.Fatalf("class = %q, want %q", got.Class, ClassStale)
	}
	if len(got.Advice) != 1 || got.Advice[0] != "vless-tun stop" {
		t.Fatalf("advice = %v, want vless-tun stop", got.Advice)
	}
	if !strings.Contains(got.Warning, "default route") {
		t.Fatalf("warning = %q, want stale default-route warning", got.Warning)
	}
	if strings.Contains(strings.ToLower(RenderText(report)), "ifconfig") {
		t.Fatalf("stale output suggests direct interface mutation: %s", RenderText(report))
	}
}

// This proves an unclaimed IPv4 utun is labeled as another app or system and receives no advice.
func TestClassifyUnclaimedIPv4InterfaceAsUnknown(t *testing.T) {
	report := Classify([]Interface{{Name: "utun9", IPv4: []string{"10.8.0.2/24"}, Up: true}}, nil, nil)

	got := report.Interfaces[0]
	if got.Class != ClassUnknown || got.Label != "not ours (another app or system)" {
		t.Fatalf("classification = %#v, want unknown not-ours label", got)
	}
	if len(got.Advice) != 0 {
		t.Fatalf("unknown advice = %v, want none", got.Advice)
	}
}

// This proves an unclaimed IPv6-link-local-only utun is classified as a compact system interface.
func TestClassifyIPv6OnlyInterfaceAsSystem(t *testing.T) {
	report := Classify([]Interface{{Name: "utun0", IPv6: []string{"fe80::1%utun0/64"}, Up: true}}, nil, nil)

	got := report.Interfaces[0]
	if got.Class != ClassSystem || len(got.Advice) != 0 {
		t.Fatalf("classification = %#v, want system without advice", got)
	}
}

// This proves live and dead OpenConnect claims become owned and stale respectively, with only native OpenConnect cleanup guidance.
func TestClassifyOpenConnectClaims(t *testing.T) {
	tests := []struct {
		name   string
		live   Liveness
		want   Class
		advice string
	}{
		{name: "live", live: LivenessAlive, want: ClassOwned},
		{name: "dead", live: LivenessDead, want: ClassStale, advice: "openconnect-tun stop"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := Classify(
				[]Interface{{Name: "utun5", IPv4: []string{"10.0.0.2/32"}, Up: true}},
				[]Claim{{Engine: EngineOpenConnect, SessionID: "oc-session", Interface: "utun5", Liveness: tc.live}},
				nil,
			)
			got := report.Interfaces[0]
			if got.Class != tc.want || got.Claims[0].Engine != EngineOpenConnect {
				t.Fatalf("classification = %#v, want class %q owned by OpenConnect", got, tc.want)
			}
			if tc.advice == "" && len(got.Advice) != 0 {
				t.Fatalf("advice = %v, want none", got.Advice)
			}
			if tc.advice != "" && (len(got.Advice) != 1 || got.Advice[0] != tc.advice) {
				t.Fatalf("advice = %v, want %q", got.Advice, tc.advice)
			}
		})
	}
}

// This proves a live claim wins over another engine's dead claim, so a shared interface is never marked stale while owned.
func TestClassifyDoubleClaimAliveWins(t *testing.T) {
	report := Classify(
		[]Interface{liveVLESSInterface()},
		[]Claim{
			{Engine: EngineOpenConnect, SessionID: "oc-dead", Interface: "utun233", Liveness: LivenessDead},
			{Engine: EngineVLESS, SessionID: "vless-live", Interface: "utun233", Liveness: LivenessAlive},
		},
		nil,
	)

	got := report.Interfaces[0]
	if got.Class != ClassOwned || len(got.Advice) != 0 {
		t.Fatalf("classification = %#v, want owned without cleanup advice", got)
	}
	if len(got.Claims) != 2 {
		t.Fatalf("claims = %v, want both claims retained for inspection", got.Claims)
	}
}

// This proves the ifconfig parser handles multiple utuns, dual-stack addresses, flags, and hexadecimal IPv4 masks from macOS output.
func TestParseIfconfigFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/ifconfig.txt")
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := ParseIfconfig(raw)
	if err != nil {
		t.Fatalf("ParseIfconfig() error = %v", err)
	}
	if len(interfaces) != 4 {
		t.Fatalf("interface count = %d, want 4", len(interfaces))
	}
	if got := interfaces[0]; got.Name != "utun0" || len(got.IPv4) != 0 || got.IPv6[0] != "fe80::aede:48ff:fe00:1122%utun0/64" || !got.Up {
		t.Fatalf("utun0 = %#v, want up IPv6-only interface", got)
	}
	if got := interfaces[3]; got.Name != "utun233" || got.IPv4[0] != "172.19.0.1/30" || got.IPv6[0] != "fdfe:dcba:9876::1/126" {
		t.Fatalf("utun233 = %#v, want parsed dual-stack addresses", got)
	}
}

// This proves ordinary and paired split-default macOS routes identify their exact carrying interfaces.
func TestParseDefaultRoutesFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/routes.txt")
	if err != nil {
		t.Fatal(err)
	}
	routes, err := ParseDefaultRoutes(raw)
	if err != nil {
		t.Fatalf("ParseDefaultRoutes() error = %v", err)
	}
	for _, name := range []string{"en0", "utun5", "utun233"} {
		if !routes[name] {
			t.Fatalf("routes[%q] = false, want true", name)
		}
	}
	if routes["utun9"] {
		t.Fatal("non-default utun9 unexpectedly marked as carrying a default route")
	}
}

// This proves malformed address and default-route rows are rejected instead of silently producing ownership facts.
func TestParsersRejectMalformedInput(t *testing.T) {
	if _, err := ParseIfconfig([]byte("utun7: flags=8051<UP,RUNNING> mtu 1380\n\tinet not-an-ip netmask 0xffffff00\n")); err == nil {
		t.Fatal("ParseIfconfig() error = nil, want malformed-address error")
	}
	if _, err := ParseDefaultRoutes([]byte("default 192.0.2.1 UGSc\n")); err == nil {
		t.Fatal("ParseDefaultRoutes() error = nil, want missing-interface error")
	}
}

// This proves the rendered output of Classify, across every class, never pairs "ifconfig" with "down"
// and never says "zombie". It renders what Classify actually produces, not hand-built results.
func TestRendererNeverSuggestsIfconfigDown(t *testing.T) {
	interfaces := []Interface{
		{Name: "utun1", IPv4: []string{"172.19.0.1/30"}, Up: true},
		{Name: "utun2", IPv4: []string{"172.19.0.5/30"}, Up: true},
		{Name: "utun3", IPv4: []string{"10.1.0.2/24"}, Up: true},
		{Name: "utun4", IPv4: []string{"172.19.0.9/30"}, Up: true},
		{Name: "utun5", IPv6: []string{"fe80::1%utun5/64"}, Up: true},
	}
	claims := []Claim{
		{Engine: EngineVLESS, SessionID: "live", Interface: "utun1", Liveness: LivenessAlive},
		{Engine: EngineVLESS, SessionID: "dead", Interface: "utun2", Liveness: LivenessDead},
		{Engine: EngineOpenConnect, SessionID: "unknown", Interface: "utun3", Liveness: LivenessUnknown},
	}
	report := Classify(interfaces, claims, map[string]bool{"utun2": true, "utun4": true})
	classes := map[Class]bool{}
	for _, result := range report.Interfaces {
		classes[result.Class] = true
	}
	for _, want := range []Class{ClassOwned, ClassStale, ClassUnverified, ClassUnknown, ClassSystem} {
		if !classes[want] {
			t.Fatalf("fixture does not exercise class %s: %#v", want, report.Interfaces)
		}
	}

	output := strings.ToLower(RenderText(report))
	if strings.Contains(output, "ifconfig") && strings.Contains(output, "down") {
		t.Fatalf("renderer emitted forbidden cleanup combination: %s", output)
	}
	if strings.Contains(output, "zombie") {
		t.Fatalf("renderer emitted zombie wording: %s", output)
	}
}

// This proves the exact host state from the 2026-10-19 report stays safe even without a session claim:
// a live vless-tun started by an older binary records no interface name, so utun233 (172.19.0.1/30, a
// private address, no openconnect) is unclaimed. It must be "unknown" with no advice, and nothing may
// attribute it to openconnect, call it a zombie or suggest taking it down. Address ranges never decide.
func TestClassifyUnclaimedPrivateInterfaceIsNeverAZombie(t *testing.T) {
	report := Classify([]Interface{liveVLESSInterface()}, nil, nil)

	got := report.Interfaces[0]
	if got.Class != ClassUnknown || len(got.Advice) != 0 || got.Warning != "" {
		t.Fatalf("classification = %#v, want unknown with no advice or warning", got)
	}
	output := strings.ToLower(RenderText(report))
	for _, forbidden := range []string{"zombie", "openconnect", "down", "stale"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains %q: %s", forbidden, output)
		}
	}
}
