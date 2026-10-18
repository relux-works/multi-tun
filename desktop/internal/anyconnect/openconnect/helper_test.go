package openconnect

import (
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestRenderPrivilegedHelperPlist(t *testing.T) {
	// This proves the compatibility wrapper renders the hardened daemon digest arguments.
	t.Parallel()

	cfg := PrivilegedHelperConfig{
		Label:      "works.relux.test-helper",
		PlistPath:  "/Library/LaunchDaemons/works.relux.test-helper.plist",
		SocketPath: "/var/run/works.relux.test-helper.sock",
	}
	plist := string(renderPrivilegedHelperPlist(cfg, "/tmp/openconnect-tun", 501, 20, strings.Repeat("a", 64), strings.Repeat("b", 64)))
	for _, want := range []string{
		"<string>works.relux.test-helper</string>",
		"<string>/tmp/openconnect-tun</string>",
		"<string>_daemon</string>",
		"<string>/var/run/works.relux.test-helper.sock</string>",
		"<string>501</string>",
		"<string>20</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q", want)
		}
	}
}

func TestHelperSignalPreservesClientAPI(t *testing.T) {
	// This proves the OpenConnect compatibility wrapper forwards pid/signal without broadening group scope.
	previous := vpnCoreSignalOpenConnect
	defer func() { vpnCoreSignalOpenConnect = previous }()
	called := false
	vpnCoreSignalOpenConnect = func(_ vpncore.ServiceConfig, pid int, signal string, group bool) error {
		called = pid == 42 && signal == "-TERM" && !group
		return nil
	}
	if err := helperSignal(DefaultPrivilegedHelperConfig(), 42, "-TERM"); err != nil {
		t.Fatalf("helperSignal() error = %v", err)
	}
	if !called {
		t.Fatal("helperSignal() did not forward the expected request")
	}
}

func TestLegacyHelperEntrypointsFailClosed(t *testing.T) {
	// This proves compatibility commands cannot bypass the digest-checked vpn-core installer or verified daemon entrypoint.
	if err := InstallPrivilegedHelper("/tmp/vpn-core", 501, 20); err == nil {
		t.Fatal("InstallPrivilegedHelper() error = nil")
	}
	if err := RunPrivilegedHelperDaemon("/tmp/vpn-core.sock", 501, 20); err == nil {
		t.Fatal("RunPrivilegedHelperDaemon() error = nil")
	}
}
