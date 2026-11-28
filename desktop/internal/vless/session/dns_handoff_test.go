package session

import (
	"errors"
	"fmt"
	"runtime"
	"slices"
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

// Every host operation is replaced, including those the selected path must not use.
// These tests prove the command and restore contract, not macOS resolver selection.
func stubDNSHandoffHost(t *testing.T) {
	t.Helper()
	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "")
	prevRoute, prevOrder, prevGet := defaultRouteGetSession, networkServiceOrderSession, networkDNSServersSession
	prevSet, prevScutil := setDNSServersPrivilegedSession, runScutilPrivilegedSession
	t.Cleanup(func() {
		defaultRouteGetSession, networkServiceOrderSession, networkDNSServersSession = prevRoute, prevOrder, prevGet
		setDNSServersPrivilegedSession, runScutilPrivilegedSession = prevSet, prevScutil
	})
	defaultRouteGetSession = func() ([]byte, error) { return []byte("  interface: en0\n"), nil }
	networkServiceOrderSession = func() ([]byte, error) {
		return []byte("(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n"), nil
	}
	networkDNSServersSession = func(service string) ([]byte, error) {
		if service != "Wi-Fi" {
			t.Fatalf("DNS read service = %q", service)
		}
		return []byte("There aren't any DNS Servers set on Wi-Fi.\n"), nil
	}
	setDNSServersPrivilegedSession = func(string, string, int, string, []string) error {
		t.Fatal("unexpected networksetup write")
		return errors.New("unexpected networksetup write")
	}
	runScutilPrivilegedSession = func(string, string, int, string) error {
		t.Fatal("unexpected scutil write")
		return errors.New("unexpected scutil write")
	}
}

func dnsHandoffFixture(t *testing.T, overlay bool) (CurrentSession, StartOptions) {
	t.Helper()
	return CurrentSession{ID: "test-dns", LogPath: t.TempDir() + "/session.log", LaunchMode: config.LaunchModeHelper, Mode: config.RenderModeTun},
		StartOptions{Mode: config.RenderModeTun, InterfaceName: "utun233", TunAddresses: []string{"172.19.0.1/30"},
			OverlayDNSActive: overlay, OverlayDNSDomains: []string{"corp.example"}, SystemDNSServers: []string{"1.1.1.1", "8.8.8.8"}}
}

func TestApplyAndRestoreSystemDNSHandoffPrefersNetworkService(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific DNS handoff")
	}
	for _, overlay := range []bool{false, true} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprintf("overlay=%t/explicit=%t", overlay, explicit), func(t *testing.T) {
				stubDNSHandoffHost(t)
				var restore []string
				if explicit {
					restore = []string{"9.9.9.9", "8.8.4.4"}
					networkDNSServersSession = func(string) ([]byte, error) { return []byte(strings.Join(restore, "\n")), nil }
				}
				var calls [][]string
				setDNSServersPrivilegedSession = func(mode, logPath string, maxLines int, service string, servers []string) error {
					if mode != config.LaunchModeHelper || service != "Wi-Fi" {
						t.Fatalf("unexpected target: %s %s", mode, service)
					}
					calls = append(calls, append([]string(nil), servers...))
					return nil
				}
				current, options := dnsHandoffFixture(t, overlay)
				if err := applySystemDNSHandoff(&current, options); err != nil {
					t.Fatal(err)
				}
				if current.DNSHandoffMode != dnsHandoffModeFallback || current.DNSHandoffService != "Wi-Fi" || current.DNSHandoffServiceID != "" || current.DNSHandoffRestoreAuto == explicit {
					t.Fatalf("unexpected handoff record: %+v", current)
				}
				if !slices.Equal(current.DNSHandoffRestoreServers, restore) {
					t.Fatalf("restore servers = %v", current.DNSHandoffRestoreServers)
				}
				if err := restoreSystemDNSHandoff(current); err != nil {
					t.Fatal(err)
				}
				if len(calls) != 2 || !slices.Equal(calls[0], options.SystemDNSServers) || !slices.Equal(calls[1], restore) {
					t.Fatalf("DNS apply/restore calls = %v", calls)
				}
			})
		}
	}
}

func TestApplyAndRestoreSystemDNSHandoffFallsBackToScutilWithoutSearchDomains(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific DNS handoff")
	}
	for _, overlay := range []bool{false, true} {
		for _, failure := range []string{"route", "service", "getdns", "setdns"} {
			t.Run(fmt.Sprintf("overlay=%t/failure=%s", overlay, failure), func(t *testing.T) {
				stubDNSHandoffHost(t)
				errUnavailable := errors.New("network service unavailable")
				switch failure {
				case "route":
					defaultRouteGetSession = func() ([]byte, error) { return nil, errUnavailable }
				case "service":
					networkServiceOrderSession = func() ([]byte, error) { return nil, errUnavailable }
				case "getdns":
					networkDNSServersSession = func(string) ([]byte, error) { return nil, errUnavailable }
				case "setdns":
					setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { return errUnavailable }
				}
				var calls []string
				runScutilPrivilegedSession = func(mode, logPath string, maxLines int, input string) error {
					if mode != config.LaunchModeHelper {
						t.Fatalf("mode = %s", mode)
					}
					calls = append(calls, input)
					return nil
				}
				current, options := dnsHandoffFixture(t, overlay)
				if err := applySystemDNSHandoff(&current, options); err != nil {
					t.Fatal(err)
				}
				if current.DNSHandoffMode != dnsHandoffModeScutil || current.DNSHandoffServiceID == "" || current.DNSHandoffService != "" || current.DNSHandoffInterface != "utun233" {
					t.Fatalf("unexpected scoped handoff: %+v", current)
				}
				if !slices.Equal(current.DNSHandoffServers, options.SystemDNSServers) {
					t.Fatalf("servers = %v", current.DNSHandoffServers)
				}
				if len(calls) != 1 {
					t.Fatalf("apply calls = %v", calls)
				}
				for _, want := range []string{"d.add InterfaceName utun233", "d.add ServerAddresses * 1.1.1.1 8.8.8.8", "d.add Addresses * 172.19.0.1", "set State:/Network/Service/" + current.DNSHandoffServiceID + "/DNS", "set State:/Network/Service/" + current.DNSHandoffServiceID + "/IPv4"} {
					if !strings.Contains(calls[0], want) {
						t.Fatalf("missing %q in %s", want, calls[0])
					}
				}
				if err := restoreSystemDNSHandoff(current); err != nil {
					t.Fatal(err)
				}
				if len(calls) != 2 {
					t.Fatalf("restore calls = %v", calls)
				}
				for _, suffix := range []string{"/DNS", "/IPv4"} {
					if !strings.Contains(calls[1], "remove State:/Network/Service/"+current.DNSHandoffServiceID+suffix) {
						t.Fatalf("missing remove %s: %s", suffix, calls[1])
					}
				}
				for _, call := range calls {
					for _, forbidden := range []string{"DomainName", "SearchDomains", "SupplementalMatchDomains", "corp.example"} {
						if strings.Contains(call, forbidden) {
							t.Fatalf("search-domain leakage %q: %s", forbidden, call)
						}
					}
				}
			})
		}
	}
}

func TestSystemDNSHandoffReportsApplyAndRestoreFailures(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific DNS handoff")
	}
	stubDNSHandoffHost(t)
	defaultRouteGetSession = func() ([]byte, error) { return nil, errors.New("route failed") }
	refused := errors.New("scutil refused")
	runScutilPrivilegedSession = func(string, string, int, string) error { return refused }
	current, options := dnsHandoffFixture(t, true)
	if err := applySystemDNSHandoff(&current, options); !errors.Is(err, refused) || !strings.Contains(err.Error(), "route failed") {
		t.Fatalf("apply error = %v", err)
	}
	if current.DNSHandoffMode != "" || len(current.DNSHandoffServers) != 0 {
		t.Fatalf("failed apply recorded success: %+v", current)
	}
	current.DNSHandoffMode, current.DNSHandoffServiceID, current.DNSHandoffServers = dnsHandoffModeScutil, "test-service", []string{"1.1.1.1"}
	if err := restoreSystemDNSHandoff(current); !errors.Is(err, refused) {
		t.Fatalf("scutil restore error = %v", err)
	}
	current.DNSHandoffMode, current.DNSHandoffServiceID, current.DNSHandoffService = dnsHandoffModeFallback, "", "Wi-Fi"
	setDNSServersPrivilegedSession = func(string, string, int, string, []string) error { return refused }
	if err := restoreSystemDNSHandoff(current); !errors.Is(err, refused) {
		t.Fatalf("networksetup restore error = %v", err)
	}
}

func TestShouldApplySystemDNSHandoffDefaultsOnAndRespectsDisableEnv(t *testing.T) {
	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "")
	want := runtime.GOOS == "darwin"
	if got := shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true, SystemDNSServers: []string{"1.1.1.1"}}); got != want {
		t.Fatalf("shouldApplySystemDNSHandoff(overlay) = %v, want %v", got, want)
	}
	if got := shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: false, SystemDNSServers: []string{"1.1.1.1"}}); got != want {
		t.Fatalf("shouldApplySystemDNSHandoff(standalone) = %v, want %v", got, want)
	}
	if shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: false}) {
		t.Fatal("shouldApplySystemDNSHandoff() = true without configured system DNS servers")
	}

	t.Setenv("VLESS_TUN_ENABLE_DNS_HANDOFF", "0")
	if shouldApplySystemDNSHandoff(config.RenderModeTun, StartOptions{OverlayDNSActive: true, SystemDNSServers: []string{"1.1.1.1"}}) {
		t.Fatal("shouldApplySystemDNSHandoff() = true with explicit disable env")
	}
}
