package session

import (
	"runtime"
	"testing"

	"multi-tun/internal/config"
)

func TestTunnelDNSServer(t *testing.T) {
	t.Parallel()

	got, err := tunnelDNSServer([]string{
		"fdfe:dcba:9876::1/126",
		"172.19.0.1/30",
	})
	if err != nil {
		t.Fatalf("tunnelDNSServer() error = %v", err)
	}
	if got != "172.19.0.1" {
		t.Fatalf("tunnelDNSServer() = %q, want %q", got, "172.19.0.1")
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
	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "1")

	prevDefaultRouteGet := defaultRouteGetSession
	prevNetworkServiceOrder := networkServiceOrderSession
	prevNetworkDNSServers := networkDNSServersSession
	prevSetDNSServers := setDNSServersPrivilegedSession
	t.Cleanup(func() {
		defaultRouteGetSession = prevDefaultRouteGet
		networkServiceOrderSession = prevNetworkServiceOrder
		networkDNSServersSession = prevNetworkDNSServers
		setDNSServersPrivilegedSession = prevSetDNSServers
	})

	defaultRouteGetSession = func() ([]byte, error) {
		return []byte("interface: en0\n"), nil
	}
	networkServiceOrderSession = func() ([]byte, error) {
		return []byte("(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"), nil
	}
	networkDNSServersSession = func(service string) ([]byte, error) {
		if service != "Wi-Fi" {
			t.Fatalf("networkDNSServersSession service = %q, want %q", service, "Wi-Fi")
		}
		return []byte("There aren't any DNS Servers set on Wi-Fi.\n"), nil
	}

	var calls [][]string
	setDNSServersPrivilegedSession = func(launchMode, logPath, service string, servers []string) error {
		calls = append(calls, append([]string{launchMode, service}, servers...))
		return nil
	}

	current := CurrentSession{
		ID:         "20260329T120000Z",
		LogPath:    t.TempDir() + "/session.log",
		LaunchMode: config.LaunchModeHelper,
		Mode:       config.RenderModeTun,
	}
	options := StartOptions{
		Mode:             config.RenderModeTun,
		TunAddresses:     []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		OverlayDNSActive: true,
	}

	if err := applySystemDNSHandoff(&current, options); err != nil {
		t.Fatalf("applySystemDNSHandoff() error = %v", err)
	}
	if current.DNSHandoffService != "Wi-Fi" {
		t.Fatalf("DNSHandoffService = %q, want %q", current.DNSHandoffService, "Wi-Fi")
	}
	if current.DNSHandoffServer != "172.19.0.1" {
		t.Fatalf("DNSHandoffServer = %q, want %q", current.DNSHandoffServer, "172.19.0.1")
	}
	if !current.DNSHandoffRestoreAuto {
		t.Fatal("DNSHandoffRestoreAuto = false, want true")
	}
	if len(calls) != 1 || len(calls[0]) != 3 || calls[0][0] != config.LaunchModeHelper || calls[0][1] != "Wi-Fi" || calls[0][2] != "172.19.0.1" {
		t.Fatalf("apply setDNS calls = %#v, want helper/Wi-Fi/172.19.0.1", calls)
	}

	if err := restoreSystemDNSHandoff(current); err != nil {
		t.Fatalf("restoreSystemDNSHandoff() error = %v", err)
	}
	if len(calls) != 2 || len(calls[1]) != 2 || calls[1][0] != config.LaunchModeHelper || calls[1][1] != "Wi-Fi" {
		t.Fatalf("restore setDNS calls = %#v, want helper/Wi-Fi/automatic", calls)
	}
}

func TestShouldApplySystemDNSHandoffRequiresEnvOptIn(t *testing.T) {
	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "")
	if shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true}) {
		t.Fatal("shouldApplySystemDNSHandoff() = true without env opt-in")
	}

	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "1")
	want := runtime.GOOS == "darwin"
	if got := shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true}); got != want {
		t.Fatalf("shouldApplySystemDNSHandoff() = %v, want %v", got, want)
	}
}
