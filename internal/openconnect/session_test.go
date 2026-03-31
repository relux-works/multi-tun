package openconnect

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWritePreStopSnapshotIncludesStatusFields(t *testing.T) {
	var buf bytes.Buffer

	writePreStopSnapshot(&buf, CurrentSession{
		ID:        "20260327T143405Z",
		Mode:      ConnectModeSplitInclude,
		Server:    "vpn-gw2.corp.example/outside",
		Interface: "utun8",
	}, stopSnapshot{
		VPNBinary:  "/opt/cisco/anyconnect/bin/vpn",
		CiscoState: StateDisconnected,
		Info: &ConnectionInfo{
			State:      StateConnected,
			ServerAddr: "198.51.100.241",
			ClientAddr: "172.18.194.4",
			TunnelMode: "Split Include",
			Duration:   "00:57",
		},
		Runtime: &RuntimeStatus{
			PID:       22497,
			Interface: "utun8",
			Uptime:    "00:57",
		},
		Routes:     []string{"10.23.16.4/32", "10.23.0.23/32"},
		ScutilDNS:  "DNS configuration\nresolver #1",
		RouteTable: "Routing tables\nInternet:",
	})

	got := buf.String()
	for _, needle := range []string{
		"=== pre-stop snapshot ===",
		"pre_stop_session_id: 20260327T143405Z",
		"pre_stop_session_mode: split-include",
		"pre_stop_session_server: vpn-gw2.corp.example/outside",
		"pre_stop_vpn_binary: /opt/cisco/anyconnect/bin/vpn",
		"pre_stop_cisco_state: disconnected",
		"pre_stop_state: connected",
		"pre_stop_server_addr: 198.51.100.241",
		"pre_stop_client_addr: 172.18.194.4",
		"pre_stop_tunnel_mode: Split Include",
		"pre_stop_openconnect_pid: 22497",
		"pre_stop_openconnect_interface: utun8",
		"pre_stop_live_routes: 10.23.16.4/32, 10.23.0.23/32",
		"pre_stop_scutil_dns_begin",
		"DNS configuration",
		"pre_stop_route_table_begin",
		"Routing tables",
		"=== end pre-stop snapshot ===",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("snapshot missing %q:\n%s", needle, got)
		}
	}

	if !strings.Contains(got, "captured_at: ") {
		t.Fatalf("snapshot missing captured_at:\n%s", got)
	}
	if _, err := time.Parse(time.RFC3339, extractLineValue(got, "captured_at: ")); err != nil {
		t.Fatalf("captured_at is not RFC3339: %v\n%s", err, got)
	}
}

func extractLineValue(body string, prefix string) string {
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, prefix))
		}
	}
	return ""
}

func TestActiveOverlayDNSReturnsExpandedDomainsForLiveSession(t *testing.T) {
	cacheDir := t.TempDir()
	current := CurrentSession{
		ID:             "20260328T194252Z",
		PID:            os.Getpid(),
		Mode:           ConnectModeSplitInclude,
		Server:         "vpn-gw2.corp.example/outside",
		VPNDomains:     []string{"corp.example"},
		VPNNameservers: []string{"10.23.16.4", "10.23.0.23"},
	}
	if err := SaveCurrent(cacheDir, current); err != nil {
		t.Fatalf("SaveCurrent() error = %v", err)
	}

	overlay, err := ActiveOverlayDNS(cacheDir)
	if err != nil {
		t.Fatalf("ActiveOverlayDNS() error = %v", err)
	}
	if overlay == nil {
		t.Fatal("ActiveOverlayDNS() = nil, want overlay data")
	}
	for _, domain := range []string{"corp.example", "inside.corp.example", "region.corp.example", "branch.example"} {
		if !containsString(overlay.Domains, domain) {
			t.Fatalf("overlay.Domains = %#v, want %q", overlay.Domains, domain)
		}
	}
	if !containsString(overlay.Nameservers, "10.23.16.4") || !containsString(overlay.Nameservers, "10.23.0.23") {
		t.Fatalf("overlay.Nameservers = %#v, want Corp nameservers", overlay.Nameservers)
	}
	if !containsString(overlay.RouteExcludes, "10.23.16.4/32") || !containsString(overlay.RouteExcludes, "10.23.0.23/32") {
		t.Fatalf("overlay.RouteExcludes = %#v, want Corp DNS host routes", overlay.RouteExcludes)
	}
}

func TestConnectConvergenceExpectationsForSplitIncludeSession(t *testing.T) {
	expect := connectConvergenceExpectationsForSession(CurrentSession{
		Mode:           ConnectModeSplitInclude,
		Server:         "vpn-gw2.corp.example/outside",
		IncludeRoutes:  []string{"10.0.0.0/8"},
		VPNDomains:     []string{"corp.example"},
		VPNNameservers: []string{"10.23.16.4", "10.23.0.23"},
	})
	if !expect.RouteOverrides || !expect.DNSShim {
		t.Fatalf("expect = %#v, want route and dns readiness checks enabled", expect)
	}
	if expect.ProbeSync {
		t.Fatalf("expect.ProbeSync = true, want false because probe warmup is no longer a hard connect gate: %#v", expect)
	}
}

func TestReadConnectConvergenceStateUsesConnectEventNotPreInit(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openconnect.log")
	logBody := strings.Join([]string{
		"vpnc_wrapper_reason: pre-init",
		"vpnc_wrapper_base_exit: 0",
		"vpnc_wrapper_reason: connect",
		"vpnc_wrapper_route_override: begin utun9",
		"vpnc_wrapper_dns_shim: apply split-include",
		"vpnc_wrapper_probe_route_sync_begin: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_probe_route_sync: apply gitlab.services.corp.example 203.0.113.27 -> utun9",
		"vpnc_wrapper_probe_route_sync_end: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_base_exit: 0",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := readConnectConvergenceState(logPath)
	if err != nil {
		t.Fatalf("readConnectConvergenceState() error = %v", err)
	}
	if !state.ConnectEventSeen || !state.ConnectExitSeen {
		t.Fatalf("state = %#v, want connect event and exit", state)
	}
	if !state.RouteOverrideSeen || !state.DNSShimSeen || !state.ProbeSyncSeen || !state.ProbeSyncSuccess {
		t.Fatalf("state = %#v, want route override, dns shim, and probe sync markers", state)
	}
	ready, err := state.ready(connectConvergenceExpectations{
		RouteOverrides: true,
		DNSShim:        true,
	})
	if err != nil {
		t.Fatalf("state.ready() error = %v", err)
	}
	if !ready {
		t.Fatalf("state.ready() = false, want true for converged connect event: %#v", state)
	}
}

func TestReadConnectConvergenceStateIgnoresPendingProbeSyncForConnectReadiness(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openconnect.log")
	logBody := strings.Join([]string{
		"vpnc_wrapper_reason: connect",
		"vpnc_wrapper_route_override: begin utun9",
		"vpnc_wrapper_dns_shim: apply split-include",
		"vpnc_wrapper_probe_route_sync_begin: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_base_exit: 0",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := readConnectConvergenceState(logPath)
	if err != nil {
		t.Fatalf("readConnectConvergenceState() error = %v", err)
	}
	ready, err := state.ready(connectConvergenceExpectations{
		RouteOverrides: true,
		DNSShim:        true,
	})
	if err != nil {
		t.Fatalf("state.ready() error = %v", err)
	}
	if !ready {
		t.Fatalf("state.ready() = false, want true because pending probe sync no longer blocks connect readiness: %#v", state)
	}
}

func TestReadConnectConvergenceStateStaysNotReadyAfterProbeResolveFailure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openconnect.log")
	logBody := strings.Join([]string{
		"vpnc_wrapper_reason: connect",
		"vpnc_wrapper_route_override: begin utun9",
		"vpnc_wrapper_dns_shim: apply split-include",
		"vpnc_wrapper_probe_route_sync_begin: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_probe_route_sync_resolve_failed: apply gitlab.services.corp.example",
		"vpnc_wrapper_probe_route_sync_end: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_base_exit: 0",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	state, err := readConnectConvergenceState(logPath)
	if err != nil {
		t.Fatalf("readConnectConvergenceState() error = %v", err)
	}
	ready, err := state.ready(connectConvergenceExpectations{
		RouteOverrides: true,
		DNSShim:        true,
	})
	if err != nil {
		t.Fatalf("state.ready() error = %v", err)
	}
	if !ready {
		t.Fatalf("state.ready() = false, want true because unresolved probe sync no longer blocks connect convergence: %#v", state)
	}
}

func TestProbeRouteWarmupReadyTracksApplySuccessPerHost(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openconnect.log")
	logBody := strings.Join([]string{
		"vpnc_wrapper_probe_route_sync_begin: apply gitlab.services.corp.example utun9",
		"vpnc_wrapper_probe_route_sync_retry: apply gitlab.services.corp.example remaining=5",
		"vpnc_wrapper_probe_route_sync: apply gitlab.services.corp.example 203.0.113.27 -> utun9",
		"vpnc_wrapper_probe_route_sync_end: apply gitlab.services.corp.example utun9",
	}, "\n")
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	ready, err := probeRouteWarmupReady(logPath, []string{"gitlab.services.corp.example"})
	if err != nil {
		t.Fatalf("probeRouteWarmupReady() error = %v", err)
	}
	if !ready {
		t.Fatalf("probeRouteWarmupReady() = false, want true")
	}
}
