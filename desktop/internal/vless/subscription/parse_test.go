package subscription

import (
	"os"
	"path/filepath"
	"testing"

	"multi-tun/desktop/internal/vless/model"
)

func TestNormalizePayloadPlain(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	normalized, payloadFormat, err := NormalizePayload(raw)
	if err != nil {
		t.Fatalf("NormalizePayload returned error: %v", err)
	}
	if payloadFormat != "plain" {
		t.Fatalf("payloadFormat = %q, want plain", payloadFormat)
	}
	if normalized == "" {
		t.Fatal("normalized payload is empty")
	}
}

func TestNormalizePayloadBase64(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.base64.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	normalized, payloadFormat, err := NormalizePayload(raw)
	if err != nil {
		t.Fatalf("NormalizePayload returned error: %v", err)
	}
	if payloadFormat != "base64" {
		t.Fatalf("payloadFormat = %q, want base64", payloadFormat)
	}
	if normalized == "" {
		t.Fatal("normalized payload is empty")
	}
}

func TestParseProfiles(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}
	if got, want := len(profiles), 2; got != want {
		t.Fatalf("len(profiles) = %d, want %d", got, want)
	}

	first := profiles[0]
	if got, want := first.Host, "144.31.90.46"; got != want {
		t.Fatalf("first.Host = %q, want %q", got, want)
	}
	if got, want := first.Network, "grpc"; got != want {
		t.Fatalf("first.Network = %q, want %q", got, want)
	}
	if got, want := first.Security, "reality"; got != want {
		t.Fatalf("first.Security = %q, want %q", got, want)
	}
	if got, want := first.ServiceName, "grpcservice"; got != want {
		t.Fatalf("first.ServiceName = %q, want %q", got, want)
	}
}

func TestParseVLESSURIExtractsPostQuantumAndSpiderXParams(t *testing.T) {
	t.Parallel()

	profile, err := ParseVLESSURI("vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=reality&encryption=mlkem768x25519plus.native.0rtt.example&spx=%2Fabc123&flow=xtls-rprx-vision#pq")
	if err != nil {
		t.Fatalf("ParseVLESSURI returned error: %v", err)
	}
	if got, want := profile.Encryption, "mlkem768x25519plus.native.0rtt.example"; got != want {
		t.Fatalf("Encryption = %q, want %q", got, want)
	}
	if got, want := profile.SpiderX, "/abc123"; got != want {
		t.Fatalf("SpiderX = %q, want %q", got, want)
	}
	if got, want := profile.Flow, "xtls-rprx-vision"; got != want {
		t.Fatalf("Flow = %q, want %q", got, want)
	}
}

func TestSelectProfile(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	profile, err := SelectProfile(profiles, "backup")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.Port, 8444; got != want {
		t.Fatalf("profile.Port = %d, want %d", got, want)
	}
}

func TestSelectProfileEmptySelectorPrefersTCP(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "grpc",
			Name:    "provider grpc default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "tcp",
			Name:    "provider tcp backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	profile, err := SelectProfile(profiles, "")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.ID, "tcp"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

func TestSelectProfileWhitespaceSelectorPrefersTCP(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{ID: "grpc", Host: "example.com", Port: 8443, Network: "grpc"},
		{ID: "tcp", Host: "example.com", Port: 8444, Network: "tcp"},
	}

	profile, err := SelectProfile(profiles, " \t\n ")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.ID, "tcp"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

func TestSelectProfileExplicitSelectorCanChooseGRPC(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "grpc",
			Name:    "provider grpc default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "tcp",
			Name:    "provider tcp backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	profile, err := SelectProfile(profiles, "grpc")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.ID, "grpc"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}
