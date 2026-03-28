package openconnect

import (
	"bytes"
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
