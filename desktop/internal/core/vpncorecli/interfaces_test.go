package vpncorecli

import (
	"bytes"
	"encoding/json"
	"testing"

	"multi-tun/desktop/internal/core/ifaceaudit"
)

// This proves vpn-core wires the read-only interfaces command through injected interface, route, and claim seams without executing a host command.
func TestInterfacesCommandUsesInjectedSeams(t *testing.T) {
	previousIfconfig := ifconfigOutputVPNCoreCLI
	previousRoutes := routeOutputVPNCoreCLI
	previousClaims := collectInterfaceClaimsVPNCoreCLI
	t.Cleanup(func() {
		ifconfigOutputVPNCoreCLI = previousIfconfig
		routeOutputVPNCoreCLI = previousRoutes
		collectInterfaceClaimsVPNCoreCLI = previousClaims
	})

	ifconfigCalls := 0
	routeCalls := 0
	claimCalls := 0
	ifconfigOutputVPNCoreCLI = func() ([]byte, error) {
		ifconfigCalls++
		return []byte("utun233: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000\n\tinet 172.19.0.1 --> 172.19.0.2 netmask 0xfffffffc\n"), nil
	}
	routeOutputVPNCoreCLI = func() ([]byte, error) {
		routeCalls++
		return []byte("Destination Gateway Flags Netif Expire\n0/1 172.19.0.2 UGSc utun233\n128.0/1 172.19.0.2 UGSc utun233\n"), nil
	}
	collectInterfaceClaimsVPNCoreCLI = func() ifaceaudit.ClaimCollection {
		claimCalls++
		return ifaceaudit.ClaimCollection{Claims: []ifaceaudit.Claim{{
			Engine:    ifaceaudit.EngineVLESS,
			SessionID: "live-session",
			Interface: "utun233",
			Liveness:  ifaceaudit.LivenessAlive,
		}}}
	}

	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"interfaces", "--json"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if ifconfigCalls != 1 || routeCalls != 1 || claimCalls != 1 {
		t.Fatalf("seam calls = ifconfig:%d routes:%d claims:%d, want one each", ifconfigCalls, routeCalls, claimCalls)
	}
	var report ifaceaudit.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("JSON output = %q: %v", stdout.String(), err)
	}
	if len(report.Interfaces) != 1 || report.Interfaces[0].Class != ifaceaudit.ClassOwned || !report.Interfaces[0].DefaultRoute {
		t.Fatalf("report = %#v, want owned default-route interface", report)
	}
}
