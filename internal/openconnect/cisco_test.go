package openconnect

import "testing"

func TestParseStateConnected(t *testing.T) {
	if got := parseState("  >> state: Connected"); got != StateConnected {
		t.Fatalf("parseState() = %q, want %q", got, StateConnected)
	}
}

func TestParseStateDisconnected(t *testing.T) {
	if got := parseState("  >> state: Disconnected"); got != StateDisconnected {
		t.Fatalf("parseState() = %q, want %q", got, StateDisconnected)
	}
}

func TestParseStats(t *testing.T) {
	output := `
[ Connection Information ]
    Connection State:            Connected
    Duration:                    01:23:45
    Tunnel Mode (IPv4):          Split Tunnel
[ Address Information ]
    Client Address (IPv4):       10.255.0.42
    Server Address:              vpn-gw2.corp.example
[ Bytes ]
    Bytes Sent:                  12345678
    Bytes Received:              87654321
`
	info := parseStats(output)
	if info.State != StateConnected {
		t.Fatalf("State = %q, want %q", info.State, StateConnected)
	}
	if info.ServerAddr != "vpn-gw2.corp.example" {
		t.Fatalf("ServerAddr = %q", info.ServerAddr)
	}
	if info.ClientAddr != "10.255.0.42" {
		t.Fatalf("ClientAddr = %q", info.ClientAddr)
	}
	if info.TunnelMode != "Split Tunnel" {
		t.Fatalf("TunnelMode = %q", info.TunnelMode)
	}
}

func TestParseHosts(t *testing.T) {
	output := `
[hosts]:
> 1. MSK Base
>> 2. Ural Base
`
	profiles := parseHosts(output)
	if len(profiles) != 2 {
		t.Fatalf("len(profiles) = %d, want 2", len(profiles))
	}
	if profiles[0].Name != "MSK Base" {
		t.Fatalf("profiles[0].Name = %q", profiles[0].Name)
	}
	if profiles[1].Name != "Ural Base" {
		t.Fatalf("profiles[1].Name = %q", profiles[1].Name)
	}
}

func TestParseAuthenticateOutput(t *testing.T) {
	output := "COOKIE='abc'\nHOST='vpn-gw2.corp.example'\nCONNECT_URL='https://vpn-gw2.corp.example/outside'\n"
	result, err := parseAuthenticateOutput(output)
	if err != nil {
		t.Fatalf("parseAuthenticateOutput() error = %v", err)
	}
	if result.Cookie != "abc" {
		t.Fatalf("Cookie = %q", result.Cookie)
	}
	if result.Host != "vpn-gw2.corp.example" {
		t.Fatalf("Host = %q", result.Host)
	}
}

func TestDestToCIDR(t *testing.T) {
	if got := destToCIDR("213.87"); got != "198.51.100.0/24" {
		t.Fatalf("destToCIDR = %q", got)
	}
	if got := destToCIDR("198.51.100.128"); got != "198.51.100.128/32" {
		t.Fatalf("destToCIDR = %q", got)
	}
}
