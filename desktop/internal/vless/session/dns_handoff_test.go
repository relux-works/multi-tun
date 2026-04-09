package session

import (
	"runtime"
	"strings"
	"testing"

	"multi-tun/desktop/internal/vless/config"
)

func TestNormalizeDNSServerList(t *testing.T) {
	t.Parallel()

	got := normalizeDNSServerList([]string{"1.1.1.1", "8.8.8.8", "1.1.1.1", "fdfe::1", "not-an-ip"})
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("normalizeDNSServerList() = %#v, want 1.1.1.1 and 8.8.8.8", got)
	}
}

func TestParseDefaultInterface(t *testing.T) {
	t.Parallel()

	out := `   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
`

	got, err := parseDefaultInterface(out)
	if err != nil {
		t.Fatalf("parseDefaultInterface() error = %v", err)
	}
	if got != "en0" {
		t.Fatalf("parseDefaultInterface() = %q, want %q", got, "en0")
	}
}

func TestParseNetworkServiceOrder(t *testing.T) {
	t.Parallel()

	out := `An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)
`

	got, err := parseNetworkServiceOrder(out, "en0")
	if err != nil {
		t.Fatalf("parseNetworkServiceOrder() error = %v", err)
	}
	if got != "Wi-Fi" {
		t.Fatalf("parseNetworkServiceOrder() = %q, want %q", got, "Wi-Fi")
	}
}

func TestParseDNSServersAutomatic(t *testing.T) {
	t.Parallel()

	got, automatic, err := parseDNSServers("There aren't any DNS Servers set on Wi-Fi.\n", "Wi-Fi")
	if err != nil {
		t.Fatalf("parseDNSServers() error = %v", err)
	}
	if !automatic {
		t.Fatal("parseDNSServers() automatic = false, want true")
	}
	if len(got) != 0 {
		t.Fatalf("parseDNSServers() servers = %#v, want none", got)
	}
}

func TestParseDNSServersExplicit(t *testing.T) {
	t.Parallel()

	got, automatic, err := parseDNSServers("10.23.16.4\n10.23.0.23\n", "Wi-Fi")
	if err != nil {
		t.Fatalf("parseDNSServers() error = %v", err)
	}
	if automatic {
		t.Fatal("parseDNSServers() automatic = true, want false")
	}
	if len(got) != 2 || got[0] != "10.23.16.4" || got[1] != "10.23.0.23" {
		t.Fatalf("parseDNSServers() servers = %#v, want explicit list", got)
	}
}

func TestApplyAndRestoreSystemDNSHandoff(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific DNS handoff")
	}

	prevRunScutil := runScutilPrivilegedSession
	t.Cleanup(func() {
		runScutilPrivilegedSession = prevRunScutil
	})

	type scutilCall struct {
		launchMode string
		stdin      string
	}
	var calls []scutilCall
	runScutilPrivilegedSession = func(launchMode, logPath, stdinData string) error {
		calls = append(calls, scutilCall{
			launchMode: launchMode,
			stdin:      stdinData,
		})
		return nil
	}

	current := CurrentSession{
		ID:         "20260329T120000Z",
		LogPath:    t.TempDir() + "/session.log",
		LaunchMode: config.LaunchModeHelper,
		Mode:       config.RenderModeTun,
	}
	options := StartOptions{
		Mode:              config.RenderModeTun,
		InterfaceName:     "utun233",
		TunAddresses:      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		OverlayDNSActive:  true,
		OverlayDNSDomains: []string{"corp.example", "inside.corp.example"},
		SystemDNSServers:  []string{"1.1.1.1", "8.8.8.8"},
	}

	if err := applySystemDNSHandoff(&current, options); err != nil {
		t.Fatalf("applySystemDNSHandoff() error = %v", err)
	}
	if current.DNSHandoffMode != dnsHandoffModeScutil {
		t.Fatalf("DNSHandoffMode = %q, want %q", current.DNSHandoffMode, dnsHandoffModeScutil)
	}
	if current.DNSHandoffServiceID == "" {
		t.Fatal("DNSHandoffServiceID = empty, want generated service id")
	}
	if current.DNSHandoffInterface != "utun233" {
		t.Fatalf("DNSHandoffInterface = %q, want %q", current.DNSHandoffInterface, "utun233")
	}
	if len(current.DNSHandoffServers) != 2 || current.DNSHandoffServers[0] != "1.1.1.1" || current.DNSHandoffServers[1] != "8.8.8.8" {
		t.Fatalf("DNSHandoffServers = %#v, want 1.1.1.1 and 8.8.8.8", current.DNSHandoffServers)
	}
	if current.DNSHandoffRestoreAuto {
		t.Fatal("DNSHandoffRestoreAuto = true, want false for scutil handoff")
	}
	if len(calls) != 1 {
		t.Fatalf("apply scutil calls = %#v, want one call", calls)
	}
	if calls[0].launchMode != config.LaunchModeHelper {
		t.Fatalf("apply launchMode = %q, want %q", calls[0].launchMode, config.LaunchModeHelper)
	}
	for _, needle := range []string{
		"d.add ConfirmedServiceID " + current.DNSHandoffServiceID,
		"d.add InterfaceName utun233",
		"d.add DomainName corp.example",
		"d.add SearchDomains * corp.example inside.corp.example",
		"d.add ServerAddresses * 1.1.1.1 8.8.8.8",
		"set State:/Network/Service/" + current.DNSHandoffServiceID + "/DNS",
		"d.add Addresses * 172.19.0.1",
		"set State:/Network/Service/" + current.DNSHandoffServiceID + "/IPv4",
	} {
		if !strings.Contains(calls[0].stdin, needle) {
			t.Fatalf("apply scutil stdin missing %q:\n%s", needle, calls[0].stdin)
		}
	}

	if err := restoreSystemDNSHandoff(current); err != nil {
		t.Fatalf("restoreSystemDNSHandoff() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("restore scutil calls = %#v, want second call", calls)
	}
	if calls[1].launchMode != config.LaunchModeHelper {
		t.Fatalf("restore launchMode = %q, want %q", calls[1].launchMode, config.LaunchModeHelper)
	}
	for _, needle := range []string{
		"remove State:/Network/Service/" + current.DNSHandoffServiceID + "/DNS",
		"remove State:/Network/Service/" + current.DNSHandoffServiceID + "/IPv4",
	} {
		if !strings.Contains(calls[1].stdin, needle) {
			t.Fatalf("restore scutil stdin missing %q:\n%s", needle, calls[1].stdin)
		}
	}
}

func TestShouldApplySystemDNSHandoffDefaultsOnAndRespectsDisableEnv(t *testing.T) {
	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "")
	want := runtime.GOOS == "darwin"
	if got := shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true, SystemDNSServers: []string{"1.1.1.1"}}); got != want {
		t.Fatalf("shouldApplySystemDNSHandoff() = %v, want %v", got, want)
	}

	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "0")
	if shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true, SystemDNSServers: []string{"1.1.1.1"}}) {
		t.Fatal("shouldApplySystemDNSHandoff() = true with explicit disable env")
	}
}
