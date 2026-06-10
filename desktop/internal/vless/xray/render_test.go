package xray

import (
	"encoding/json"
	"testing"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

func TestRenderPreservesVLESSPQEncryptionAndRealityOptions(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Engine = &config.EngineConfig{
		Type: config.EngineXray,
		Xray: &config.XrayEngineConfig{
			SocksListen: "127.0.0.1",
			SocksPort:   21808,
		},
	}
	profile := model.Profile{
		UUID:        "00000000-0000-0000-0000-000000000000",
		Host:        "sneakypeaky.fyi",
		Port:        443,
		Network:     "tcp",
		Security:    "reality",
		SNI:         "www.apple.com",
		Fingerprint: "chrome",
		PublicKey:   "pubkey",
		ShortID:     "abcd",
		Encryption:  "mlkem768x25519plus.native.0rtt.example",
		SpiderX:     "/TK5",
		Flow:        "xtls-rprx-vision",
	}

	data, err := Render(cfg, profile)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	inbounds := root["inbounds"].([]any)
	socks := inbounds[0].(map[string]any)
	if got, want := socks["protocol"], "socks"; got != want {
		t.Fatalf("inbound.protocol = %#v, want %#v", got, want)
	}
	if got, want := socks["port"], float64(21808); got != want {
		t.Fatalf("inbound.port = %#v, want %#v", got, want)
	}

	outbounds := root["outbounds"].([]any)
	proxy := outbounds[0].(map[string]any)
	settings := proxy["settings"].(map[string]any)
	vnext := settings["vnext"].([]any)[0].(map[string]any)
	users := vnext["users"].([]any)
	user := users[0].(map[string]any)
	if got, want := user["encryption"], "mlkem768x25519plus.native.0rtt.example"; got != want {
		t.Fatalf("user.encryption = %#v, want %#v", got, want)
	}
	if got, want := user["flow"], "xtls-rprx-vision"; got != want {
		t.Fatalf("user.flow = %#v, want %#v", got, want)
	}

	stream := proxy["streamSettings"].(map[string]any)
	if got, want := stream["security"], "reality"; got != want {
		t.Fatalf("stream.security = %#v, want %#v", got, want)
	}
	reality := stream["realitySettings"].(map[string]any)
	if got, want := reality["serverName"], "www.apple.com"; got != want {
		t.Fatalf("reality.serverName = %#v, want %#v", got, want)
	}
	if got, want := reality["publicKey"], "pubkey"; got != want {
		t.Fatalf("reality.publicKey = %#v, want %#v", got, want)
	}
	if got, want := reality["shortId"], "abcd"; got != want {
		t.Fatalf("reality.shortId = %#v, want %#v", got, want)
	}
	if got, want := reality["spiderX"], "/TK5"; got != want {
		t.Fatalf("reality.spiderX = %#v, want %#v", got, want)
	}
}
