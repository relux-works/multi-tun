package amnezia

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/subscription"
)

const testUUID = "11111111-2222-3333-4444-555555555555"
const testPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const testPresharedKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="

const testAWGINI = `[Interface]
PrivateKey = ` + testPrivateKey + `
Address = 10.0.0.2/32, fd00::2/128
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1280
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 20
S3 = 25
S4 = 30
H1 = 100-200
H2 = 300
H3 = 400
H4 = 500
I1 = <b 0x01>
I2 = <b 0x02>
I3 = <b 0x03>
I4 = <b 0x04>
I5 = <b 0x05>
[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
PresharedKey = ` + testPresharedKey + `
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = [2001:db8::1]:51820
PersistentKeepalive = 25
`

func testJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testVPN(t *testing.T, value any) string {
	t.Helper()
	key, err := EncodeVPNURI(testJSON(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testXrayConfig() map[string]any {
	return map[string]any{"outbounds": []any{
		map[string]any{"protocol": "freedom"},
		map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "2001:db8::2", "port": 443,
				"users": []any{map[string]any{"id": testUUID, "flow": "xtls-rprx-vision", "encryption": "none"}},
			}}},
			"streamSettings": map[string]any{
				"network": "grpc", "security": "reality",
				"realitySettings": map[string]any{"serverName": "example.com", "fingerprint": "chrome", "publicKey": "public-example", "shortId": "aabb", "spiderX": "/test"},
				"grpcSettings":    map[string]any{"serviceName": "grpc-service", "authority": "grpc.example.com"},
			},
		},
	}}
}

func testXrayContainer(t *testing.T, asString bool) map[string]any {
	t.Helper()
	var config any = testXrayConfig()
	if asString {
		config = string(testJSON(t, config))
	}
	return map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": config}}
}

func testAWGContainer(t *testing.T, asString bool) map[string]any {
	t.Helper()
	var config any = map[string]any{"Config": testAWGINI, "MTU": "1420", "hostName": "relay.example.com", "port": 51821}
	if asString {
		config = string(testJSON(t, config))
	}
	return map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": config}}
}

// Check the framing with an independent zlib reader, rather than relying only
// on two implementations agreeing in an encoder/decoder round trip.
func TestEncodeVPNURIQtFraming(t *testing.T) {
	body := []byte(`{"description":"example"}`)
	key, err := EncodeVPNURI(body)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.TrimPrefix(key, "vpn://")
	if !strings.HasPrefix(key, "vpn://") || strings.Contains(encoded, "=") {
		t.Fatal("unexpected URI encoding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(raw[:4]) != uint32(len(body)) {
		t.Fatal("incorrect qCompress length header")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("incorrect compressed document")
	}
	for _, body := range [][]byte{nil, make([]byte, MaxDecompressedBytes+1)} {
		key, err := EncodeVPNURI(body)
		if err != nil {
			t.Fatalf("encoder must frame even documents the decoder refuses: %v", err)
		}
		if _, err := DecodeKey(key); !IsRefusalCode(err, CodeKeyInvalid) {
			t.Fatalf("decoder size refusal = %v", err)
		}
	}
}

func TestDecodeXrayExportForms(t *testing.T) {
	for _, asString := range []bool{false, true} {
		for _, multiServer := range []bool{false, true} {
			server := map[string]any{"description": "plain relay", "hostName": "example.com", "server_country_code": " us ", "defaultContainer": "amnezia-xray", "containers": []any{testXrayContainer(t, asString)}}
			var export any = server
			if multiServer {
				export = map[string]any{"servers": []any{server}}
			}
			key := testVPN(t, export)
			d, err := DecodeKey(" \n" + key + "\n ")
			if err != nil {
				t.Fatal(err)
			}
			if d.Format != "vpn" || d.Protocol != "vless" || len(d.Profiles) != 1 || d.ValidateRunnable("sing-box") != nil {
				t.Fatalf("unexpected decoded structure: %+v", d.Summary)
			}
			p := d.Profiles[0]
			if p.Name != "plain relay" || p.CountryCode != "US" || p.Host != "2001:db8::2" || p.Port != 443 || p.UUID != testUUID {
				t.Fatal("endpoint or metadata lost")
			}
			if p.Protocol != "vless" || p.Network != "grpc" || p.Security != "reality" || p.ServiceName != "grpc-service" || p.Authority != "grpc.example.com" || p.SNI != "example.com" || p.Fingerprint != "chrome" || p.PublicKey != "public-example" || p.ShortID != "aabb" || p.SpiderX != "/test" || p.Flow != "xtls-rprx-vision" || p.Encryption != "none" {
				t.Fatal("Xray transport settings lost")
			}
			if len(p.ID) != 12 || strings.Trim(p.ID, "0123456789abcdef") != "" {
				t.Fatal("invalid deterministic profile ID")
			}
			again, err := DecodeKey(key)
			if err != nil || !reflect.DeepEqual(again.Profiles, d.Profiles) {
				t.Fatal("decoding is not deterministic")
			}
			reparsed, err := subscription.ParseVLESSURI(p.URI)
			if err != nil || reparsed.UUID != p.UUID || reparsed.SNI != p.SNI || reparsed.ServiceName != p.ServiceName || reparsed.Host != p.Host {
				t.Fatal("canonical URI does not preserve settings")
			}
			if d.Summary.ContainerCount != 1 || d.Summary.ProfileCount != 1 || d.Summary.DefaultContainer != "amnezia-xray" || !reflect.DeepEqual(d.Summary.Countries, []string{"US"}) {
				t.Fatalf("summary = %+v", d.Summary)
			}
		}
	}
}

func TestDecodeVPNSupportsRawJSONAndPaddedBase64(t *testing.T) {
	body := testJSON(t, map[string]any{"containers": []any{testXrayContainer(t, false)}})
	compressed, err := EncodeVPNURI(body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(compressed, "vpn://"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"vpn://" + base64.URLEncoding.EncodeToString(raw),
		"vpn://" + base64.URLEncoding.EncodeToString(body),
		"vpn://" + base64.RawURLEncoding.EncodeToString(body),
	} {
		d, err := DecodeKey(key)
		if err != nil || len(d.Profiles) != 1 || d.Profiles[0].Name != "[2001:db8::2]:443" {
			t.Fatalf("decode form failed: %v", err)
		}
	}
}

func TestDecodeMultiServerCountriesAndTLS(t *testing.T) {
	xray := testXrayConfig()
	outbound := xray["outbounds"].([]any)[1].(map[string]any)
	outbound["streamSettings"] = map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "tls.example.com", "fingerprint": "firefox", "alpn": []string{"h2", "http/1.1"}}}
	container := map[string]any{"description": "Germany relay", "xray": map[string]any{"last_config": xray}}
	d, err := DecodeKey(testVPN(t, map[string]any{"servers": []any{
		map[string]any{"country": "de", "containers": []any{container}},
		map[string]any{"description": "USA relay", "containers": []any{testXrayContainer(t, false)}},
		map[string]any{"country_code": "JP", "containers": []any{testXrayContainer(t, true)}},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Profiles) != 3 || !reflect.DeepEqual(d.Summary.Countries, []string{"DE", "JP", "US"}) {
		t.Fatalf("summary = %+v", d.Summary)
	}
	p := d.Profiles[0]
	if p.CountryCode != "DE" || p.Name != "Germany relay" || p.SNI != "tls.example.com" || p.Fingerprint != "firefox" || p.Query["alpn"] != "h2,http/1.1" {
		t.Fatal("TLS metadata lost")
	}
}

func TestExportCountryPrecedenceAndUnsupportedCompanion(t *testing.T) {
	for _, tc := range []struct{ serverCode, code, country, name, want string }{
		{"us", "DE", "JP", "Germany", "US"},
		{"invalid", "de", "JP", "USA", "DE"},
		{"", "", "jp", "Germany", "JP"},
		{"", "", "", "🇺🇸 relay", "US"},
		{"ſg", "", "", "Germany", "DE"},
	} {
		d, err := DecodeKey(testVPN(t, map[string]any{
			"description": tc.name, "server_country_code": tc.serverCode, "country_code": tc.code, "country": tc.country,
			"containers": []any{map[string]any{"container": "amnezia-openvpn"}, testXrayContainer(t, false)},
		}))
		if err != nil || len(d.Profiles) != 1 || d.Profiles[0].CountryCode != tc.want || d.Summary.ContainerCount != 2 {
			t.Fatalf("country precedence, expected %s: %v", tc.want, err)
		}
	}
}

func TestMalformedStaticConfigRefusals(t *testing.T) {
	for _, rawConfig := range []any{
		nil, 42, []any{}, "not-json",
		map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "example.com", "port": 443, "users": []any{}}}}}}},
		map[string]any{"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "example.com", "port": 65536, "users": []any{map[string]any{"id": testUUID}}}}}}}},
	} {
		key := testVPN(t, map[string]any{"containers": []any{map[string]any{"xray": map[string]any{"last_config": rawConfig}}}})
		if _, err := DecodeKey(key); err == nil {
			t.Fatal("malformed Xray was accepted")
		}
	}
	for _, wrapper := range []any{
		nil, map[string]any{}, map[string]any{"last_config": map[string]any{"MTU": "invalid", "Config": testAWGINI}},
		map[string]any{"last_config": map[string]any{"port": 65536, "Config": testAWGINI}},
	} {
		if _, err := DecodeKey(testVPN(t, map[string]any{"containers": []any{map[string]any{"awg": wrapper}}})); !IsRefusalCode(err, CodeKeyInvalid) {
			t.Fatalf("malformed AWG refusal = %v", err)
		}
	}
}

func TestDecodeAWGAndMixedExport(t *testing.T) {
	for _, asString := range []bool{false, true} {
		for _, mixed := range []bool{false, true} {
			containers := []any{testAWGContainer(t, asString)}
			if mixed {
				containers = append(containers, testXrayContainer(t, asString))
			}
			d, err := DecodeKey(testVPN(t, map[string]any{"description": "plain relay", "country_code": "US", "containers": containers}))
			if err != nil {
				t.Fatal(err)
			}
			if d.AWG == nil || d.AWG.Name != "plain relay" || d.AWG.CountryCode != "US" || d.AWG.MTU != 1420 || d.AWG.EndpointHost != "relay.example.com" || d.AWG.EndpointPort != 51821 {
				t.Fatal("AWG export metadata lost")
			}
			if mixed {
				if d.Protocol != "vless" || len(d.Profiles) != 1 || d.ValidateRunnable("xray") != nil {
					t.Fatal("mixed export did not prefer VLESS")
				}
			} else if d.Protocol != "amnezia-awg" || !IsRefusalCode(d.ValidateRunnable("xray"), CodeEngineUnavailable) {
				t.Fatal("AWG was admitted as runnable")
			}
			marshaled := string(testJSON(t, d.AWG))
			if strings.Contains(marshaled, testPrivateKey) || strings.Contains(marshaled, testPresharedKey) || strings.Contains(marshaled, "PrivateKey") || strings.Contains(marshaled, "PresharedKey") {
				t.Fatal("AWG JSON disclosed secret fields")
			}
		}
	}
	// WireGuard uses the same static parser but retains the AWG engine refusal.
	container := testAWGContainer(t, false)
	container["container"] = "amnezia-wireguard"
	container["wireguard"] = container["awg"]
	delete(container, "awg")
	if d, err := DecodeKey(testVPN(t, map[string]any{"containers": []any{container}})); err != nil || d.Protocol != "amnezia-awg" {
		t.Fatalf("WireGuard export: %v", err)
	}
}

func TestParseAWGINIAllFields(t *testing.T) {
	d, err := DecodeKey(testAWGINI)
	if err != nil || d.Format != "awg_ini" || d.Protocol != "amnezia-awg" {
		t.Fatalf("INI decode: %v", err)
	}
	c := d.AWG
	if c.PrivateKey != testPrivateKey || c.PresharedKey != testPresharedKey || c.PublicKey == "" || c.EndpointHost != "2001:db8::1" || c.EndpointPort != 51820 || c.PersistentKeepalive != 25 || c.MTU != 1280 {
		t.Fatal("AWG keys or endpoint lost")
	}
	if !reflect.DeepEqual(c.Address, []string{"10.0.0.2/32", "fd00::2/128"}) || len(c.DNS) != 2 || !reflect.DeepEqual(c.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatal("AWG address lists lost")
	}
	if c.Jc != 4 || c.Jmin != 40 || c.Jmax != 70 || c.S1 != 15 || c.S2 != 20 || c.S3 != 25 || c.S4 != 30 || c.H1 != "100-200" || c.H2 != "300" || c.H3 != "400" || c.H4 != "500" || c.I1 != "<b 0x01>" || c.I2 != "<b 0x02>" || c.I3 != "<b 0x03>" || c.I4 != "<b 0x04>" || c.I5 != "<b 0x05>" {
		t.Fatal("AWG obfuscation parameters lost")
	}
	if d.ValidateRunnable("sing-box") != nil || d.ValidateRunnable("amnezia-awg") != nil || !IsRefusalCode(d.ValidateRunnable("xray"), CodeEngineUnavailable) {
		t.Fatal("incorrect AWG engine admission")
	}
	for _, raw := range []string{
		strings.Replace(testAWGINI, "Jc = 4", "Jc = invalid-secret", 1),
		strings.Replace(testAWGINI, "MTU = 1280", "MTU = -1", 1),
		strings.Replace(testAWGINI, "[2001:db8::1]:51820", "example.com:65536", 1),
		strings.Replace(testAWGINI, "[2001:db8::1]:51820", "bad-secret-endpoint", 1),
		strings.Replace(testAWGINI, "[Peer]", "[Other]", 1),
		strings.Replace(testAWGINI, "PrivateKey = "+testPrivateKey, "", 1),
		testAWGINI + "\n[Peer]\nPublicKey = other",
		testAWGINI + "\nPostUp = forbidden-command",
	} {
		if _, err := ParseAWGINI(raw); !IsRefusalCode(err, CodeKeyInvalid) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), testPrivateKey) {
			t.Fatalf("INI refusal: %v", err)
		}
	}
}

func TestDecodeDirectAndSubscriptionFormats(t *testing.T) {
	for _, scheme := range []string{"vless", "VLESS"} {
		d, err := DecodeKey(scheme + "://" + testUUID + "@example.com:443?type=tcp#USA")
		if err != nil || d.Format != "vless" || d.Protocol != "vless" || len(d.Profiles) != 1 || d.Profiles[0].CountryCode != "US" {
			t.Fatalf("direct VLESS: %v", err)
		}
	}
	for _, key := range []string{"https://example.com/sub?token=synthetic", "HTTPS://example.com/sub"} {
		d, err := DecodeKey(" \t" + key + "\n")
		if err != nil || d.Format != "subscription_url" || d.Protocol != "subscription" || d.SubscriptionURL != key || d.ValidateRunnable("sing-box") != nil {
			t.Fatalf("HTTPS: %v", err)
		}
	}
	if err := (DecodedPayload{Protocol: "amnezia-gateway"}).ValidateRunnable("xray"); !IsRefusalCode(err, CodeGatewayUnimplemented) {
		t.Fatalf("Gateway runtime refusal: %v", err)
	}
}

func TestDecodeRefusalsAreRedacted(t *testing.T) {
	for _, tc := range []struct{ raw, code string }{
		{" \n", CodeKeyEmpty}, {PlaceholderKey, CodeKeyPlaceholder},
		{"vpn://invalid!" + testUUID, CodeKeyInvalid},
		{"vless://" + testUUID + "@example.com:notaport", CodeKeyInvalid},
		{"http://example.com/" + testPrivateKey, CodeKeyInvalid},
		{"https:///missing-host", CodeKeyInvalid}, {"unknown " + testPresharedKey, CodeKeyInvalid},
		{testVPN(t, map[string]any{"api_endpoint": "https://example.com/", "api_key": testPrivateKey}), CodeGatewayUnimplemented},
		{testVPN(t, map[string]any{"api_config": map[string]any{"token": testUUID}, "containers": []any{}}), CodeGatewayUnimplemented},
		{testVPN(t, map[string]any{"api_key": testUUID, "containers": []any{map[string]any{"container": "amnezia-openvpn"}}}), CodeGatewayUnimplemented},
		{testVPN(t, map[string]any{"api_key": testUUID, "containers": []any{map[string]any{"container": "amnezia-xray"}}}), CodeGatewayUnimplemented},
		{testVPN(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-openvpn"}, map[string]any{"container": "amnezia-cloak"}, map[string]any{"container": "amnezia-shadowsocks"}}}), CodeProtocolUnsupported},
		{testVPN(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": testUUID}}}}), CodeKeyInvalid},
		{testVPN(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"Config": testPrivateKey}}}}}), CodeKeyInvalid},
		{"vpn://" + base64.RawURLEncoding.EncodeToString([]byte(`{"broken":"`+testUUID)), CodeKeyInvalid},
		{"vpn://" + base64.RawURLEncoding.EncodeToString([]byte(`{} {}`)), CodeKeyInvalid},
		{testVPN(t, []any{}), CodeKeyInvalid}, {testVPN(t, map[string]any{}), CodeKeyInvalid},
	} {
		d, err := DecodeKey(tc.raw)
		if !IsRefusalCode(err, tc.code) {
			t.Fatalf("expected code %s, got %v", tc.code, err)
		}
		for _, secret := range []string{"vpn://", testUUID, testPrivateKey, testPresharedKey} {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error disclosed a credential")
			}
		}
		if !reflect.DeepEqual(d, DecodedPayload{}) {
			t.Fatal("refusal returned partially decoded secrets")
		}
	}
}

func TestSummaryCannotEchoExportSecrets(t *testing.T) {
	key := testVPN(t, map[string]any{
		"description":      "vpn://" + testUUID + testPrivateKey + testPresharedKey,
		"defaultContainer": testUUID, "country": testPrivateKey,
		"api_key":    testPresharedKey,
		"containers": []any{testXrayContainer(t, true), testAWGContainer(t, false)},
	})
	d, err := DecodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	summary := string(testJSON(t, d.Summary))
	for _, secret := range []string{key, "vpn://", testUUID, testPrivateKey, testPresharedKey} {
		if strings.Contains(summary, secret) {
			t.Fatal("summary disclosed export secrets")
		}
	}
	if d.Protocol != "vless" || d.Summary.DefaultContainer != "" {
		t.Fatal("static export with API metadata was rejected or unsafe summary field retained")
	}
}

func TestDecodeDecompressionBoundaries(t *testing.T) {
	// Construct framing independently, including impossible/forged declarations.
	frame := func(body []byte, declared uint32) []byte {
		t.Helper()
		var buf bytes.Buffer
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], declared)
		buf.Write(header[:])
		zw := zlib.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	body := testJSON(t, map[string]any{"containers": []any{testXrayContainer(t, false)}})
	atLimit := append(append([]byte(nil), body...), bytes.Repeat([]byte(" "), MaxDecompressedBytes-len(body))...)
	key := "vpn://" + base64.RawURLEncoding.EncodeToString(frame(atLimit, MaxDecompressedBytes))
	if d, err := DecodeKey(key); err != nil || len(d.Profiles) != 1 {
		t.Fatalf("valid exact limit: %v", err)
	}
	// Real Amnezia Premium API v2 exports carry a 0x000000ff (255) qUncompress
	// hint header with >255-byte JSON (api_config + auth_data.api_key). Verify
	// it decodes cleanly into credentials with no secret in the summary or JSON.
	premiumV2Body := testJSON(t, map[string]any{
		"name":           "Amnezia Premium",
		"description":    "Amnezia Premium",
		"config_version": 2,
		"api_config": map[string]any{
			"service_type":      "amnezia-premium",
			"service_protocol":  "awg",
			"user_country_code": "US",
		},
		"auth_data": map[string]any{
			"api_key": testPrivateKey,
		},
	})
	premiumV2Key := "vpn://" + base64.RawURLEncoding.EncodeToString(frame(premiumV2Body, 255))
	if d, err := DecodeKey(premiumV2Key); err != nil || d.Format != "amnezia-premium-v2" || d.Protocol != "amnezia-gateway" || d.Gateway == nil || d.Gateway.APIKey != testPrivateKey {
		t.Fatalf("Amnezia Premium v2 decode failed: %v", err)
	} else if strings.Contains(string(testJSON(t, d)), testPrivateKey) || strings.Contains(string(testJSON(t, d.Summary)), "Amnezia Premium") || d.ValidateRunnable("sing-box") != nil || !IsRefusalCode(d.ValidateRunnable("xray"), CodeEngineUnavailable) {
		t.Fatal("gateway redaction or engine admission failed")
	}
	bad := [][]byte{
		frame(body, 0), frame(body, MaxDecompressedBytes+1),
		frame(bytes.Repeat([]byte("x"), MaxDecompressedBytes+1), 1),
		{0, 0, 0, 1, 0x78, 0x9c},
	}
	truncated := frame(body, uint32(len(body)))
	bad = append(bad, truncated[:len(truncated)-1])
	corrupt := frame(body, uint32(len(body)))
	corrupt[len(corrupt)-1] ^= 0xff
	bad = append(bad, corrupt)
	for _, raw := range bad {
		if _, err := DecodeKey("vpn://" + base64.RawURLEncoding.EncodeToString(raw)); !IsRefusalCode(err, CodeKeyInvalid) {
			t.Fatalf("framing refusal = %v", err)
		}
	}
}

func TestProfileCountryCodeJSONIsOptional(t *testing.T) {
	without := string(testJSON(t, model.Profile{}))
	with := string(testJSON(t, model.Profile{CountryCode: "US"}))
	if strings.Contains(without, "country_code") || !strings.Contains(with, `"country_code":"US"`) {
		t.Fatal("incorrect optional country JSON field")
	}
}

// Synthetic v3 material: no production key or endpoint is used.
func testAWGV3INI() string {
	raw := strings.Replace(testAWGINI, "PersistentKeepalive = 25", "PersistentKeepalive = 25-35", 1)
	return strings.Replace(raw, "[Peer]", `HeaderProtectionKey = synthetic-header-protection
ContentPaddingAddition = 0-64
RekeyAfterTime = 120-140
RekeyTimeout = 5-10
RejectAfterTime = 180-200
KeepaliveTimeout = 10-15
MaxHandshakeAttempts = 18-20
RandomTrailers = true
DisableCookies = false
[Peer]`, 1)
}

func TestDecodeAWGV3LowercaseConfig(t *testing.T) {
	for _, mtu := range []any{1420, "1420"} {
		for _, port := range []any{51821, "51821"} {
			key := testVPN(t, map[string]any{"containers": []any{map[string]any{
				"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{
					"config": testAWGV3INI(), "MTU": mtu, "port": port, "hostName": "relay.example.com",
				}},
			}}})
			d, err := DecodeKey(key)
			if err != nil {
				t.Fatal(err)
			}
			c := d.AWG
			if c == nil || c.PersistentKeepalive != 25 || c.PersistentKeepaliveRaw != "25-35" || c.HeaderProtectionKey != "synthetic-header-protection" || c.ContentPaddingAddition != "0-64" || c.RekeyAfterTime != "120-140" || c.RekeyTimeout != "5-10" || c.RejectAfterTime != "180-200" || c.KeepaliveTimeout != "10-15" || c.MaxHandshakeAttempts != "18-20" || c.RandomTrailers != "true" || c.DisableCookies != "false" || c.MTU != 1420 || c.EndpointPort != 51821 || c.EndpointHost != "relay.example.com" || c.Jc != 4 || c.Jmin != 40 || c.Jmax != 70 || c.S1 != 15 || c.S2 != 20 || c.S3 != 25 || c.S4 != 30 || c.H1 != "100-200" || c.H2 != "300" || c.H3 != "400" || c.H4 != "500" || c.I1 != "<b 0x01>" {
				t.Fatal("v3 configuration lost fields")
			}
			serialized := string(testJSON(t, c))
			for _, secret := range []string{testPrivateKey, testPresharedKey, "synthetic-header-protection", "HeaderProtectionKey"} {
				if strings.Contains(serialized, secret) {
					t.Fatal("secret serialized")
				}
			}
		}
	}
	c, err := ParseAWGINI(testAWGINI)
	if err != nil || c.PersistentKeepaliveRaw != "25" {
		t.Fatal("scalar keepalive compatibility failed")
	}
	for _, value := range []string{"0", "65535", "0-65535", "25-25"} {
		if _, err := ParseAWGINI(strings.Replace(testAWGINI, "PersistentKeepalive = 25", "PersistentKeepalive = "+value, 1)); err != nil {
			t.Fatalf("valid keepalive %q refused", value)
		}
	}
	for _, value := range []string{"35-25", "-1", "+25", "65536", "0-65536", "1-2-3", "25-", "-25", "25-secret", "1.5"} {
		if _, err := ParseAWGINI(strings.Replace(testAWGINI, "PersistentKeepalive = 25", "PersistentKeepalive = "+value, 1)); !IsRefusalCode(err, CodeKeyInvalid) {
			t.Fatalf("invalid keepalive accepted: %q", value)
		}
	}
	for _, directive := range []string{"PostUp = synthetic-secret", "PreDown = synthetic-secret", "HeaderProtectionKey = synthetic-secret", "Unknown = synthetic-secret"} {
		raw := strings.Replace(testAWGV3INI(), "[Peer]", directive+"\n[Peer]", 1)
		if _, err := ParseAWGINI(raw); !IsRefusalCode(err, CodeKeyInvalid) || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("unknown, hook or duplicate directive admitted or leaked")
		}
	}
}

func TestPremiumV2AdmissionAndLegacyRefusals(t *testing.T) {
	for _, tc := range []struct {
		version                         int
		service, protocol, apiKey, code string
	}{
		{2, "amnezia-premium", "awg", "synthetic-api-secret", ""},
		{2, "amnezia-premium", "", "synthetic-api-secret", ""},
		{2, "amnezia-premium", "vless", "synthetic-api-secret", ""},
		{2, "amnezia-premium", "awg", "  ", CodeKeyInvalid},
		{2, "amnezia-premium", "openvpn", "synthetic-api-secret", CodeProtocolUnsupported},
		{1, "amnezia-premium", "awg", "synthetic-api-secret", CodeGatewayUnimplemented},
		{0, "amnezia-premium", "awg", "synthetic-api-secret", CodeGatewayUnimplemented},
		{2, "unknown", "awg", "synthetic-api-secret", CodeGatewayUnimplemented},
	} {
		root := map[string]any{"name": "Premium", "description": "synthetic-description-secret", "config_version": tc.version, "api_config": map[string]string{"service_type": tc.service, "service_protocol": tc.protocol, "user_country_code": "US"}, "auth_data": map[string]string{"api_key": tc.apiKey}}
		d, err := DecodeKey(testVPN(t, root))
		if tc.code != "" {
			if !IsRefusalCode(err, tc.code) || strings.Contains(err.Error(), "synthetic") {
				t.Fatalf("incorrect redacted refusal: %v", err)
			}
			continue
		}
		if err != nil || d.Gateway == nil || d.Gateway.ConfigVersion != 2 || d.Gateway.Name != "Premium" || d.Gateway.UserCountryCode != "US" || d.Format != "amnezia-premium-v2" || d.Protocol != "amnezia-gateway" {
			t.Fatalf("invalid premium decode: %v", err)
		}
		if strings.Contains(string(testJSON(t, d.Gateway)), tc.apiKey) || strings.Contains(string(testJSON(t, d.Summary)), "synthetic-description-secret") {
			t.Fatal("gateway secret in serialization or summary")
		}
		for _, engine := range []string{"", "sing-box", " SINGBOX ", "amnezia-awg"} {
			if d.ValidateRunnable(engine) != nil {
				t.Fatalf("valid engine refused: %q", engine)
			}
		}
		if tc.protocol == "vless" {
			if d.ValidateRunnable("xray") != nil {
				t.Fatal("vless engine refused")
			}
		} else if !IsRefusalCode(d.ValidateRunnable("xray"), CodeEngineUnavailable) {
			t.Fatal("incompatible AWG engine admitted")
		}
	}
}
