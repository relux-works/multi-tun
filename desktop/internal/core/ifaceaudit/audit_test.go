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
	if len(got.Advice) != 0 || got.Warning != "" {
		t.Fatalf("owned advice/warning = %v/%q, want none", got.Advice, got.Warning)
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

// This proves dead VLESS and OpenConnect claims are unverified regardless of interface state, preserve default-route facts, and give status-only advice.
func TestClassifyDeadClaimsAsUnverified(t *testing.T) {
	tests := []struct {
		name         string
		iface        Interface
		engine       string
		advice       string
		defaultRoute bool
	}{
		{name: "vless-interface-up", iface: liveVLESSInterface(), engine: EngineVLESS, advice: "vless-tun status", defaultRoute: true},
		{name: "openconnect-interface-down", iface: Interface{Name: "utun5", IPv4: []string{"10.0.0.2/32"}}, engine: EngineOpenConnect, advice: "openconnect-tun status"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			routes := map[string]bool{}
			if tc.defaultRoute {
				routes[tc.iface.Name] = true
			}
			report := Classify(
				[]Interface{tc.iface},
				[]Claim{{Engine: tc.engine, SessionID: "dead-session", Interface: tc.iface.Name, Liveness: LivenessDead}},
				routes,
			)

			got := report.Interfaces[0]
			if got.Class != ClassUnverified || got.Label != "claimed by a dead session record; the interface name may since have been reused" {
				t.Fatalf("classification = %#v, want dead-record unverified label", got)
			}
			if len(got.Advice) != 1 || got.Advice[0] != tc.advice {
				t.Fatalf("advice = %v, want %q", got.Advice, tc.advice)
			}
			if got.Warning != "" || got.DefaultRoute != tc.defaultRoute {
				t.Fatalf("warning/default route = %q/%t, want empty/%t", got.Warning, got.DefaultRoute, tc.defaultRoute)
			}
		})
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

// This proves a live OpenConnect exact-name claim is owned and receives no advice.
func TestClassifyLiveOpenConnectClaimAsOwned(t *testing.T) {
	report := Classify(
		[]Interface{{Name: "utun5", IPv4: []string{"10.0.0.2/32"}, Up: true}},
		[]Claim{{Engine: EngineOpenConnect, SessionID: "oc-session", Interface: "utun5", Liveness: LivenessAlive}},
		nil,
	)
	got := report.Interfaces[0]
	if got.Class != ClassOwned || got.Claims[0].Engine != EngineOpenConnect || len(got.Advice) != 0 {
		t.Fatalf("classification = %#v, want owned OpenConnect claim without advice", got)
	}
}

// This proves a live claim wins over another engine's dead claim, so a shared interface remains owned without advice.
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

// This proves an otherwise valid IPv4 inet row without netmask retains its bare address instead of failing the audit.
func TestParseIfconfigKeepsIPv4WithoutNetmask(t *testing.T) {
	interfaces, err := ParseIfconfig([]byte("utun7: flags=8051<UP,RUNNING> mtu 1380\n\tinet 192.0.2.7 --> 192.0.2.8\n"))
	if err != nil {
		t.Fatalf("ParseIfconfig() error = %v", err)
	}
	if len(interfaces) != 1 || len(interfaces[0].IPv4) != 1 || interfaces[0].IPv4[0] != "192.0.2.7" {
		t.Fatalf("interfaces = %#v, want bare IPv4 address", interfaces)
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

// This proves invalid IPv4 and IPv6 addresses plus malformed default-route rows still fail instead of producing audit facts.
func TestParsersRejectMalformedInput(t *testing.T) {
	if _, err := ParseIfconfig([]byte("utun7: flags=8051<UP,RUNNING> mtu 1380\n\tinet not-an-ip netmask 0xffffff00\n")); err == nil {
		t.Fatal("ParseIfconfig() error = nil, want invalid IPv4 error")
	}
	if _, err := ParseIfconfig([]byte("utun7: flags=8051<UP,RUNNING> mtu 1380\n\tinet6 not-an-ipv6 prefixlen 64\n")); err == nil {
		t.Fatal("ParseIfconfig() error = nil, want invalid IPv6 error")
	}
	if _, err := ParseDefaultRoutes([]byte("default 192.0.2.1 UGSc\n")); err == nil {
		t.Fatal("ParseDefaultRoutes() error = nil, want missing-interface error")
	}
}

// This proves rendering Classify output covers owned, dead-unverified, unknown-liveness-unverified, unknown, and system paths without mutating advice.
func TestRendererCoversEveryRemainingClassificationPathWithoutMutatingAdvice(t *testing.T) {
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
	report := Classify(interfaces, claims, map[string]bool{"utun1": true, "utun2": true, "utun3": true, "utun4": true, "utun5": true})
	classes := map[Class]bool{}
	resultsByName := map[string]Result{}
	for _, result := range report.Interfaces {
		classes[result.Class] = true
		resultsByName[result.Name] = result
	}
	for _, want := range []Class{ClassOwned, ClassUnverified, ClassUnknown, ClassSystem} {
		if !classes[want] {
			t.Fatalf("fixture does not exercise class %s: %#v", want, report.Interfaces)
		}
	}
	if resultsByName["utun2"].Class != ClassUnverified || resultsByName["utun2"].Claims[0].Liveness != LivenessDead {
		t.Fatalf("utun2 = %#v, want dead-claim unverified path", resultsByName["utun2"])
	}
	if resultsByName["utun3"].Class != ClassUnverified || resultsByName["utun3"].Claims[0].Liveness != LivenessUnknown {
		t.Fatalf("utun3 = %#v, want unknown-liveness unverified path", resultsByName["utun3"])
	}
	for _, result := range report.Interfaces {
		for _, advice := range result.Advice {
			lowerAdvice := strings.ToLower(advice)
			for _, forbidden := range []string{"stop", "down", "kill", "rm", "ifconfig"} {
				if strings.Contains(lowerAdvice, forbidden) {
					t.Fatalf("%s advice contains mutating term %q: %q", result.Name, forbidden, advice)
				}
			}
		}
		if result.Warning != "" {
			t.Fatalf("%s warning = %q, want no default-route warnings", result.Name, result.Warning)
		}
		if !result.DefaultRoute {
			t.Fatalf("%s default route = false, want the route retained as a fact", result.Name)
		}
	}

	output := strings.ToLower(RenderText(report))
	if got := strings.Count(output, "default_route: yes"); got != len(report.Interfaces) {
		t.Fatalf("rendered default-route fact count = %d, want %d: %s", got, len(report.Interfaces), output)
	}
	if strings.Contains(output, "zombie") {
		t.Fatalf("renderer emitted zombie wording: %s", output)
	}
}

// This proves the unclaimed 172.19 interface regression stays unknown with no advice, ownership attribution, zombie wording, or address-based inference.
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
