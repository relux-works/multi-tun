package amnezia

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/model"
)

const gatewayTestAPIKey = "synthetic-gateway-api-secret"

// These fixture crypto routines deliberately do not call the implementation's
// CBC helpers. The NIST vector below supplies an independent encryption oracle.
func fixtureEncrypt(t *testing.T, plain, key, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("invalid fixture AES key")
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	data := append(bytes.Clone(plain), bytes.Repeat([]byte{byte(padding)}, padding)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(data, data)
	return data
}

func fixtureDecrypt(t *testing.T, ct, key, iv []byte) []byte {
	t.Helper()
	if len(ct) == 0 || len(ct)%16 != 0 {
		t.Fatal("invalid fixture ciphertext length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("invalid fixture AES key")
	}
	data := bytes.Clone(ct)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(data, data)
	padding := int(data[len(data)-1])
	if padding < 1 || padding > 16 || padding > len(data) {
		t.Fatal("invalid fixture padding")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			t.Fatal("invalid fixture padding bytes")
		}
	}
	return data[:len(data)-padding]
}

func fixtureRSA(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("cannot generate test RSA key")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal("cannot encode test RSA public key")
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Every client socket must be literal loopback, including accidental discovery
// defaults. Environment proxies and external DNS are disabled for all fixtures.
func offlineHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			t.Error("test attempted a non-loopback connection")
			return nil, errors.New("external networking forbidden")
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 2 * time.Second}
}

func offlineGateway(t *testing.T, pub string) *GatewayClient {
	return &GatewayClient{PublicKeyPEM: pub, HTTPClient: offlineHTTPClient(t), S3PrimaryEndpoints: []string{}, S3FallbackEndpoints: []string{}}
}

func gatewayTestCreds() GatewayCredentials {
	return GatewayCredentials{ConfigVersion: 2, ServiceType: "amnezia-premium", ServiceProtocol: "awg", UserCountryCode: "us", APIKey: gatewayTestAPIKey}
}

func readFixtureEnvelope(t *testing.T, r *http.Request, key *rsa.PrivateKey) (map[string]any, []byte, []byte) {
	t.Helper()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		t.Error("incorrect gateway request headers or method")
	}
	id := r.Header.Get("X-Client-Request-ID")
	if !validInstallationUUID(id) || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		t.Error("request ID is not UUIDv4")
	}
	var envelope map[string]string
	if json.NewDecoder(r.Body).Decode(&envelope) != nil || len(envelope) != 2 {
		t.Fatal("invalid envelope JSON")
	}
	encKeys, err := base64.StdEncoding.DecodeString(envelope["key_payload"])
	if err != nil {
		t.Fatal("invalid RSA ciphertext base64")
	}
	keysJSON, err := rsa.DecryptPKCS1v15(rand.Reader, key, encKeys)
	if err != nil {
		t.Fatal("invalid RSA key payload")
	}
	var keys map[string]string
	if json.Unmarshal(keysJSON, &keys) != nil || len(keys) != 3 {
		t.Fatal("invalid decrypted key payload")
	}
	aesKey, keyErr := base64.StdEncoding.DecodeString(keys["aes_key"])
	iv, ivErr := base64.StdEncoding.DecodeString(keys["aes_iv"])
	salt, saltErr := base64.StdEncoding.DecodeString(keys["aes_salt"])
	if keyErr != nil || ivErr != nil || saltErr != nil || len(aesKey) != 32 || len(iv) != 32 || len(salt) != 8 {
		t.Fatal("incorrect request key dimensions")
	}
	ct, err := base64.StdEncoding.DecodeString(envelope["api_payload"])
	if err != nil {
		t.Fatal("invalid API ciphertext base64")
	}
	var request map[string]any
	if json.Unmarshal(fixtureDecrypt(t, ct, aesKey, iv[:16]), &request) != nil {
		t.Fatal("invalid request plaintext")
	}
	return request, aesKey, iv[:16]
}

func fixtureGatewayServer(t *testing.T, key *rsa.PrivateKey, respond func(string, map[string]any) any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, aesKey, iv := readFixtureEnvelope(t, r, key)
		w.Write(fixtureEncrypt(t, testJSON(t, respond(r.URL.Path, request)), aesKey, iv))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func assertGatewayRedaction(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if !IsRefusalCode(err, CodeGatewayError) {
		t.Fatalf("expected gateway refusal, got %v", err)
	}
	for _, secret := range append(secrets, gatewayTestAPIKey, testPrivateKey, testPresharedKey, "synthetic-header-protection") {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatal("gateway error leaked a secret")
		}
	}
}

func TestGatewayCBCNISTVectorAndPadding(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key := decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := decode("000102030405060708090a0b0c0d0e0f")
	plain := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
	want := decode("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d")
	ct, err := encryptGatewayCBC(plain, key, iv)
	if err != nil || len(ct) != 48 || !bytes.Equal(ct[:32], want) {
		t.Fatal("AES-256 CBC disagrees with NIST SP 800-38A vector")
	}
	got, err := decryptGatewayCBC(ct, key, iv)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatal("CBC round-trip failed")
	}
	for size := 0; size <= 33; size++ {
		plain := bytes.Repeat([]byte{'x'}, size)
		ct, err := encryptGatewayCBC(plain, key, iv)
		if err != nil || !bytes.Equal(fixtureDecrypt(t, ct, key, iv), plain) {
			t.Fatal("padding encryption failed")
		}
		got, err := decryptGatewayCBC(fixtureEncrypt(t, plain, key, iv), key, iv)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("padding decryption failed")
		}
	}
	block, _ := aes.NewCipher(key)
	// Deterministically encrypted invalid padding, including mismatched bytes.
	for _, padding := range [][]byte{bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{17}, 16), append(bytes.Repeat([]byte{1}, 15), 2), append(bytes.Repeat([]byte{16}, 14), 15, 16)} {
		ct := bytes.Clone(padding)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, ct)
		_, err := decryptGatewayCBC(ct, key, iv)
		assertGatewayRedaction(t, err)
	}
	for _, ct := range [][]byte{nil, {1}, make([]byte, 15), make([]byte, 17)} {
		_, err := decryptGatewayCBC(ct, key, iv)
		assertGatewayRedaction(t, err)
	}
	for _, parts := range []struct{ key, iv []byte }{{key[:31], iv}, {key, iv[:15]}} {
		_, err := decryptGatewayCBC(make([]byte, 16), parts.key, parts.iv)
		assertGatewayRedaction(t, err)
		_, err = encryptGatewayCBC(nil, parts.key, parts.iv)
		assertGatewayRedaction(t, err)
	}
}

func TestGatewayEnvelopeAccountInfoAndCatalog(t *testing.T) {
	key, pub := fixtureRSA(t)
	var count atomic.Int32
	srv := fixtureGatewayServer(t, key, func(path string, request map[string]any) any {
		count.Add(1)
		if path != "/v1/account_info" {
			t.Error("incorrect account API path")
		}
		for k, want := range map[string]any{"os_version": "macos", "app_version": "5.1.1.10", "cli_name": "AmneziaVPN", "distribution": "github", "app_language": "en", "installation_uuid": testUUID, "user_country_code": "us", "service_type": "amnezia-premium", "subscription_status": "active", "cli_version": "5.1.1.10"} {
			if request[k] != want {
				t.Errorf("incorrect account metadata field %s", k)
			}
		}
		auth, ok := request["auth_data"].(map[string]any)
		if !ok || auth["api_key"] != gatewayTestAPIKey {
			t.Error("missing encrypted authentication")
		}
		return map[string]any{"http_status": 200, "active_device_count": 1, "max_device_count": 5, "service_type": "amnezia-premium", "subscription_end_date": "2030-01-01", "issued_configs": []any{map[string]any{"installation_uuid": testUUID, "os_version": "macos", "server_country_code": "us-west", "server_country_code_l10n": "us", "server_country_name": "US West", "source_type": "premium"}}, "available_countries": []any{
			map[string]any{"server_country_code": "us-west", "server_country_code_l10n": "us", "server_country_name": "US West", "available_protocols": []string{"awg", "vless"}},
			map[string]any{"server_country_code": "de", "server_country_name": "Germany", "available_protocols": []string{"awg"}},
			map[string]any{"server_country_code": "us-east", "server_country_code_l10n": "us", "server_country_name": "US East", "available_protocols": []string{"awg"}},
		}}
	})
	client := offlineGateway(t, pub)
	client.Endpoint = srv.URL
	info, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	if err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 || info.ActiveDeviceCount != 1 || info.MaxDeviceCount != 5 || info.ServiceType != "amnezia-premium" || info.SubscriptionEndDate != "2030-01-01" || len(info.IssuedConfigs) != 1 || info.IssuedConfigs[0].ServerCountryCodeL10n != "us" {
		t.Fatal("account fields lost")
	}
	profiles := info.CatalogProfiles("awg")
	if len(profiles) != 3 {
		t.Fatal("missing catalog countries")
	}
	for i, want := range []struct{ id, name, country, server string }{{"amnezia-de", "Germany", "DE", "de"}, {"amnezia-us-east", "US East", "US", "us-east"}, {"amnezia-us-west", "US West", "US", "us-west"}} {
		p := profiles[i]
		if p.ID != want.id || p.Name != want.name || p.CountryCode != want.country || p.Protocol != "amnezia-awg" || p.Network != "udp" || !IsGatewayCatalogProfile(p) || GatewayServerCountryCode(p) != want.server || GatewayServiceProtocol(p) != "awg" {
			t.Fatal("incorrect catalog mapping")
		}
	}
	if !reflect.DeepEqual(profiles, info.CatalogProfiles("")) {
		t.Fatal("default catalog protocol differs")
	}
	vless := info.CatalogProfiles("vless")
	if len(vless) != 1 || vless[0].Protocol != "vless" || vless[0].Network != "tcp" {
		t.Fatal("protocol filtering failed")
	}
	if len(info.CatalogProfiles("openvpn")) != 0 || IsGatewayCatalogProfile(model.Profile{}) {
		t.Fatal("unsupported protocol or ordinary profile admitted")
	}
	info.AvailableCountries[0], info.AvailableCountries[2] = info.AvailableCountries[2], info.AvailableCountries[0]
	if !reflect.DeepEqual(profiles, info.CatalogProfiles("awg")) {
		t.Fatal("catalog order depends on response order")
	}
}

func TestGatewayCountryCodeAndCatalogFallbacks(t *testing.T) {
	for _, tc := range []struct{ region, l10n, want string }{{"us-east", "us", "US"}, {"de", "", "DE"}, {"us-west", "invalid", "US"}, {"us-west", "DE", "DE"}, {"invalid", "", ""}, {"12", "12", ""}, {"ſg", "ſg", ""}} {
		if got := (AvailableCountry{ServerCountryCode: tc.region, ServerCountryCodeL10n: tc.l10n}).ISOCountryCode(); got != tc.want {
			t.Errorf("country code = %q, want %q", got, tc.want)
		}
	}
	info := AccountInfo{AvailableCountries: []AvailableCountry{{ServerCountryCode: "de", AvailableProtocols: []string{"vless", "awg"}}, {ServerCountryCode: "us", AvailableProtocols: []string{"unsupported"}}, {ServerCountryCode: "jp"}}}
	ps := info.CatalogProfiles("")
	if len(ps) != 1 || ps[0].Name != "DE" || ps[0].Protocol != "vless" {
		t.Fatal("catalog fallback invalid")
	}
}

func TestGatewayNegotiateAWGV3AndRevoke(t *testing.T) {
	key, pub := fixtureRSA(t)
	publicKeys := make(chan string, 1)
	var revoke atomic.Bool
	srv := fixtureGatewayServer(t, key, func(path string, request map[string]any) any {
		if request["installation_uuid"] != testUUID || request["server_country_code"] != "us-east" {
			t.Error("incorrect config identity")
		}
		if path == "/v1/revoke_config" {
			revoke.Store(true)
			return map[string]any{"http_status": 200}
		}
		if path != "/v1/config" || request["service_protocol"] != "awg" || request["is_connect_event"] != true {
			t.Error("invalid config request")
		}
		publicKey, _ := request["public_key"].(string)
		publicKeys <- publicKey
		pubBytes, err := base64.StdEncoding.DecodeString(publicKey)
		if err != nil || len(pubBytes) != 32 {
			t.Error("invalid X25519 public key")
		}
		raw := strings.Replace(testAWGV3INI(), testPrivateKey, "$WIREGUARD_CLIENT_PRIVATE_KEY", 1)
		raw = strings.Replace(raw, "DNS = 1.1.1.1, 2606:4700:4700::1111\n", "", 1)
		config := testVPN(t, map[string]any{"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": raw}}}}})
		return map[string]any{"http_status": 200, "config": config, "server_country_code": "us-east", "server_country_code_l10n": "us", "server_country_name": "US East", "dns1": "1.1.1.1", "dns2": "9.9.9.9"}
	})
	client := offlineGateway(t, pub)
	client.Endpoint = srv.URL
	result, err := client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "us-east", "awg")
	if err != nil {
		t.Fatal(err)
	}
	c := result.AWG
	if c == nil || c.Name != "US East" || c.CountryCode != "US" || result.ServerCountryCode != "us-east" || result.ServerCountryName != "US East" || result.CountryCode != "US" || result.ServiceProtocol != "awg" || !reflect.DeepEqual(c.DNS, []string{"1.1.1.1", "9.9.9.9"}) || !reflect.DeepEqual(result.DNS, c.DNS) || c.PersistentKeepaliveRaw != "25-35" || c.HeaderProtectionKey != "synthetic-header-protection" || c.RekeyAfterTime != "120-140" || c.S4 != 30 {
		t.Fatal("negotiated configuration fields lost")
	}
	privateBytes, err := base64.StdEncoding.DecodeString(c.PrivateKey)
	if err != nil || len(privateBytes) != 32 || c.PrivateKey == testPrivateKey {
		t.Fatal("client private key not substituted")
	}
	private, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil || base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()) != <-publicKeys {
		t.Fatal("negotiated private key does not match advertised public key")
	}
	serialized := string(testJSON(t, result))
	for _, secret := range []string{c.PrivateKey, c.PresharedKey, c.HeaderProtectionKey, gatewayTestAPIKey} {
		if strings.Contains(serialized, secret) {
			t.Fatal("negotiation serialization leaked secret")
		}
	}
	if err := client.RevokeConfig(context.Background(), gatewayTestCreds(), testUUID, "us-east"); err != nil || !revoke.Load() {
		t.Fatalf("revoke failed: %v", err)
	}
}

func TestGatewayNegotiateVLESS(t *testing.T) {
	key, pub := fixtureRSA(t)
	srv := fixtureGatewayServer(t, key, func(path string, request map[string]any) any {
		id, _ := request["public_key"].(string)
		if path != "/v1/config" || request["service_protocol"] != "vless" || !validInstallationUUID(id) || id[14] != '4' {
			t.Error("invalid VLESS request")
		}
		return map[string]any{"http_status": 200, "config": testVPN(t, map[string]any{"containers": []any{testXrayContainer(t, false)}})}
	})
	client := offlineGateway(t, pub)
	client.Endpoint = srv.URL
	result, err := client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "de", "vless")
	if err != nil || result.AWG != nil || len(result.Profiles) != 1 || result.CountryCode != "DE" {
		t.Fatalf("VLESS negotiation failed: %v", err)
	}
	if _, err := client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "de", "openvpn"); !IsRefusalCode(err, CodeProtocolUnsupported) {
		t.Fatal("unsupported negotiation admitted")
	}
}

func TestGatewayS3FailoverAndConcurrentCache(t *testing.T) {
	key, pub := fixtureRSA(t)
	var directCalls, listCalls, healthCalls, proxyCalls atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directCalls.Add(1)
		w.WriteHeader(403)
		io.WriteString(w, "<HTML>blocked</HTML>")
	}))
	t.Cleanup(direct.Close)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lmbd-health" {
			healthCalls.Add(1)
			w.WriteHeader(204)
			return
		}
		proxyCalls.Add(1)
		_, aesKey, iv := readFixtureEnvelope(t, r, key)
		w.Write(fixtureEncrypt(t, []byte(`{"http_status":200,"max_device_count":7}`), aesKey, iv))
	}))
	t.Cleanup(proxy.Close)
	// Put an unhealthy proxy first; a healthy proxy must be tried before it.
	var unhealthyPosts atomic.Int32
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			unhealthyPosts.Add(1)
		}
		w.WriteHeader(503)
	}))
	t.Cleanup(unhealthy.Close)
	digest := sha512.Sum512([]byte(pub))
	list := base64.StdEncoding.EncodeToString(fixtureEncrypt(t, testJSON(t, []string{unhealthy.URL, proxy.URL}), digest[:32], digest[32:48]))
	wantPath := "/" + base64.RawURLEncoding.EncodeToString([]byte("endpoints-amnezia-premium-us")) + ".json"
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listCalls.Add(1)
		if r.URL.Path != wantPath {
			t.Error("incorrect service/country S3 filename")
		}
		io.WriteString(w, list)
	}))
	t.Cleanup(s3.Close)
	client := offlineGateway(t, pub)
	client.Endpoint = direct.URL
	client.S3PrimaryEndpoints = []string{s3.URL}
	info, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	if err != nil || info.MaxDeviceCount != 7 {
		t.Fatalf("S3 failover failed: %v", err)
	}
	if directCalls.Load() != 1 || listCalls.Load() != 1 || healthCalls.Load() != 1 || unhealthyPosts.Load() != 0 {
		t.Fatal("incorrect failover/health-check ordering")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			info, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
			if err != nil || info.MaxDeviceCount != 7 {
				t.Error("cached proxy request failed")
			}
		}()
	}
	wg.Wait()
	if directCalls.Load() != 1 || listCalls.Load() != 1 || healthCalls.Load() != 1 || proxyCalls.Load() != 9 {
		t.Fatal("working proxy not reused")
	}
}

func TestGatewayS3GenericListAndFallback(t *testing.T) {
	key, pub := fixtureRSA(t)
	var posts atomic.Int32
	// Unhealthy proxies must still be tried after healthy candidates fail.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/lmbd-health" {
			w.WriteHeader(503)
			return
		}
		posts.Add(1)
		_, aesKey, iv := readFixtureEnvelope(t, r, key)
		w.Write(fixtureEncrypt(t, []byte(`{"http_status":200}`), aesKey, iv))
	}))
	t.Cleanup(proxy.Close)
	var pathsMu sync.Mutex
	var paths []string
	digest := sha512.Sum512([]byte(pub))
	list := base64.StdEncoding.EncodeToString(fixtureEncrypt(t, testJSON(t, []string{proxy.URL}), digest[:32], digest[32:48]))
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathsMu.Lock()
		paths = append(paths, r.URL.Path)
		pathsMu.Unlock()
		if r.URL.Path != "/fallback/endpoints.json" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, list)
	}))
	t.Cleanup(s3.Close)
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(501) }))
	t.Cleanup(direct.Close)
	client := offlineGateway(t, pub)
	client.Endpoint = direct.URL
	client.S3PrimaryEndpoints = []string{s3.URL + "/primary"}
	client.S3FallbackEndpoints = []string{s3.URL + "/fallback"}
	if _, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID); err != nil {
		t.Fatal(err)
	}
	pathsMu.Lock()
	defer pathsMu.Unlock()
	if len(paths) != 4 || !strings.HasPrefix(paths[0], "/primary/") || paths[1] != "/primary/endpoints.json" || !strings.HasPrefix(paths[2], "/fallback/") || paths[3] != "/fallback/endpoints.json" || posts.Load() != 1 {
		t.Fatal("incorrect primary/fallback discovery order")
	}
}

func TestGatewayAPIErrorsAndMalformedResponses(t *testing.T) {
	key, pub := fixtureRSA(t)
	for _, code := range []int{409, 422, 500} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var calls atomic.Int32
			srv := fixtureGatewayServer(t, key, func(_ string, _ map[string]any) any {
				calls.Add(1)
				return map[string]any{"http_status": code, "error": gatewayTestAPIKey + testPrivateKey + testPresharedKey + "synthetic-header-protection"}
			})
			client := offlineGateway(t, pub)
			client.Endpoint = srv.URL
			_, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
			assertGatewayRedaction(t, err)
			_, err = client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "us-east", "awg")
			assertGatewayRedaction(t, err)
			err = client.RevokeConfig(context.Background(), gatewayTestCreds(), testUUID, "us-east")
			assertGatewayRedaction(t, err)
			if calls.Load() != 3 {
				t.Fatal("recognized API error retried")
			}
		})
	}
	for _, tc := range []struct {
		name    string
		body    []byte
		encrypt bool
		status  int
	}{
		{"corrupt-ciphertext", []byte("corrupt"), false, 200},
		{"html", []byte("<html>" + gatewayTestAPIKey + "</html>"), false, 200},
		{"encrypted-html", []byte("<HTML>" + gatewayTestAPIKey + "</HTML>"), true, 200},
		{"invalid-json", []byte(`{"api_key":"` + gatewayTestAPIKey + `",`), true, 200},
		{"null", []byte(`null`), true, 200},
		{"unrecognized-404", []byte(`{}`), true, 404},
		{"unrecognized-501", []byte(`{}`), true, 501},
		{"unrecognized-422", []byte(`{}`), true, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, aesKey, iv := readFixtureEnvelope(t, r, key)
				w.WriteHeader(tc.status)
				if tc.encrypt {
					w.Write(fixtureEncrypt(t, tc.body, aesKey, iv))
				} else {
					w.Write(tc.body)
				}
			}))
			defer srv.Close()
			client := offlineGateway(t, pub)
			client.Endpoint = srv.URL
			_, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
			assertGatewayRedaction(t, err)
		})
	}
}

func TestGatewayNegotiationRefusalsAreRedacted(t *testing.T) {
	key, pub := fixtureRSA(t)
	for _, config := range []string{
		"vpn://bad-" + gatewayTestAPIKey,
		testVPN(t, map[string]any{"privateKey": testPrivateKey, "headerProtectionKey": "synthetic-header-protection"}),
		testVPN(t, map[string]any{"containers": []any{testXrayContainer(t, false)}}),
	} {
		srv := fixtureGatewayServer(t, key, func(_ string, _ map[string]any) any { return map[string]any{"http_status": 200, "config": config} })
		client := offlineGateway(t, pub)
		client.Endpoint = srv.URL
		_, err := client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "us-east", "awg")
		if !IsRefusalCode(err, CodeGatewayError) && !IsRefusalCode(err, CodeProtocolUnsupported) {
			t.Fatalf("expected negotiated config refusal: %v", err)
		}
		for _, secret := range []string{gatewayTestAPIKey, testPrivateKey, "synthetic-header-protection"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("negotiation error leaked secret")
			}
		}
		srv.Close()
	}
}

func TestGatewayCancellationAndTransportErrors(t *testing.T) {
	_, pub := fixtureRSA(t)
	client := offlineGateway(t, pub)
	client.Endpoint = "http://127.0.0.1:1"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.FetchAccountInfo(ctx, gatewayTestCreds(), testUUID)
	assertGatewayRedaction(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	_, err = client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	assertGatewayRedaction(t, err)
	// Deadline applies to an actual in-flight local HTTP request.
	entered := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	client.Endpoint = srv.URL
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = client.FetchAccountInfo(ctx, gatewayTestCreds(), testUUID)
	assertGatewayRedaction(t, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("deadline cause lost")
	}
	select {
	case <-entered:
	default:
		t.Fatal("timeout fixture request did not start")
	}
}

func TestGatewayInvalidKeysURLsAndMissingCredentials(t *testing.T) {
	for _, pub := range []string{"invalid-" + gatewayTestAPIKey, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte(gatewayTestAPIKey)}))} {
		client := offlineGateway(t, pub)
		_, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
		assertGatewayRedaction(t, err)
	}
	for _, base := range []string{"file:///tmp/example", "http://user:secret@127.0.0.1/", "http://127.0.0.1/?secret=1", "http://127.0.0.1/#fragment", "http://"} {
		_, err := gatewayURL(base, "v1/config")
		assertGatewayRedaction(t, err, "secret")
	}
	creds := gatewayTestCreds()
	creds.APIKey = " "
	_, err := offlineGateway(t, "").FetchAccountInfo(context.Background(), creds, testUUID)
	if !IsRefusalCode(err, CodeKeyInvalid) {
		t.Fatal("missing credentials accepted")
	}
	block, _ := pem.Decode([]byte(DefaultGatewayPublicKeyPEM))
	if block == nil || strings.HasSuffix(DefaultGatewayPublicKeyPEM, "\n") {
		t.Fatal("invalid production PEM framing")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal("invalid production public key")
	}
	if key, ok := parsed.(*rsa.PublicKey); !ok || key.N.BitLen() != 4096 {
		t.Fatal("incorrect production RSA key")
	}
}

func TestLoadOrCreateInstallationUUID(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	id, err := LoadOrCreateInstallationUUID(dir)
	if err != nil || !validInstallationUUID(id) || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) {
		t.Fatalf("create UUID failed: %v", err)
	}
	again, err := LoadOrCreateInstallationUUID(dir)
	if err != nil || again != id {
		t.Fatal("installation UUID not persistent")
	}
	path := filepath.Join(dir, "amnezia-installation-uuid")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("installation UUID file is not 0600")
	}
	st, err = os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("new cache directory is not 0700")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := LoadOrCreateInstallationUUID(dir)
			if err != nil || got != id {
				t.Error("concurrent identity changed")
			}
		}()
	}
	wg.Wait()
	if err := os.WriteFile(path, []byte(gatewayTestAPIKey), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrCreateInstallationUUID(dir)
	assertGatewayRedaction(t, err)
	body, _ := os.ReadFile(path)
	if string(body) != gatewayTestAPIKey {
		t.Fatal("invalid identifier overwritten")
	}
	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadOrCreateInstallationUUID(dir)
	assertGatewayRedaction(t, err)
	_, err = LoadOrCreateInstallationUUID("")
	assertGatewayRedaction(t, err)
}

// A constant stream exercises the exact body limit without allocating a large
// fixture in the server or depending on an advertised Content-Length.
type gatewayZeroReader struct{}

func (gatewayZeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestGatewayResponseLimitAndRedirectRefusal(t *testing.T) {
	for _, size := range []int64{maxGatewayResponseBytes, maxGatewayResponseBytes + 1} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(w, io.LimitReader(gatewayZeroReader{}, size)) }))
		client := offlineGateway(t, "")
		body, _, err := client.exchange(context.Background(), http.MethodGet, srv.URL, nil)
		if size == maxGatewayResponseBytes {
			if err != nil || int64(len(body)) != size {
				t.Fatal("valid response at exact bound refused")
			}
		} else {
			assertGatewayRedaction(t, err)
		}
		srv.Close()
	}
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	_, pub := fixtureRSA(t)
	client := offlineGateway(t, pub)
	client.Endpoint = source.URL
	_, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	assertGatewayRedaction(t, err)
	if redirected.Load() != 0 {
		t.Fatal("encrypted credentials followed redirect")
	}
}

func TestGatewayMalformedProxyLists(t *testing.T) {
	_, pub := fixtureRSA(t)
	digest := sha512.Sum512([]byte(pub))
	for _, body := range []string{
		gatewayTestAPIKey,
		base64.StdEncoding.EncodeToString([]byte("not block aligned")),
		base64.StdEncoding.EncodeToString(fixtureEncrypt(t, []byte(`{"proxy":"`+gatewayTestAPIKey+`"}`), digest[:32], digest[32:48])),
		base64.StdEncoding.EncodeToString(fixtureEncrypt(t, []byte(`[`), digest[:32], digest[32:48])),
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		client := offlineGateway(t, pub)
		_, err := client.proxyList(context.Background(), srv.URL, "endpoints.json")
		assertGatewayRedaction(t, err)
		srv.Close()
	}
}

func TestGatewayCachedProxyRecovery(t *testing.T) {
	key, pub := fixtureRSA(t)
	var broken atomic.Bool
	cached := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			w.WriteHeader(502)
			return
		}
		_, aesKey, iv := readFixtureEnvelope(t, r, key)
		w.Write(fixtureEncrypt(t, []byte(`{"http_status":200,"max_device_count":4}`), aesKey, iv))
	}))
	defer cached.Close()
	direct := fixtureGatewayServer(t, key, func(_ string, _ map[string]any) any { return map[string]any{"http_status": 200, "max_device_count": 6} })
	client := offlineGateway(t, pub)
	client.Endpoint = direct.URL
	client.workingProxy = cached.URL
	info, err := client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	if err != nil || info.MaxDeviceCount != 4 {
		t.Fatal("cached route was not used")
	}
	broken.Store(true)
	info, err = client.FetchAccountInfo(context.Background(), gatewayTestCreds(), testUUID)
	if err != nil || info.MaxDeviceCount != 6 {
		t.Fatalf("cached route did not recover through direct endpoint: %v", err)
	}
	client.mu.Lock()
	proxy := client.workingProxy
	client.mu.Unlock()
	if proxy != "" {
		t.Fatal("broken proxy remained cached")
	}
}

func TestGatewayNegotiateInnerExportMetadata(t *testing.T) {
	key, pub := fixtureRSA(t)
	for _, outer := range []bool{false, true} {
		t.Run(strconv.FormatBool(outer), func(t *testing.T) {
			srv := fixtureGatewayServer(t, key, func(path string, request map[string]any) any {
				if path != "/v1/config" {
					t.Error("unexpected gateway operation")
				}
				raw := strings.Replace(testAWGV3INI(), testPrivateKey, "$WIREGUARD_CLIENT_PRIVATE_KEY", 1)
				raw = strings.Replace(raw, "DNS = 1.1.1.1, 2606:4700:4700::1111\n", "", 1)
				export := testVPN(t, map[string]any{
					"dns1": "1.1.1.1", "dns2": "9.9.9.9",
					"api_config": map[string]any{"server_country_code": "us-east", "server_country_code_l10n": "us", "server_country_name": "USA East"},
					"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": map[string]any{"config": raw}}}},
				})
				response := map[string]any{"http_status": 201, "config": export}
				if outer {
					response["server_country_name"], response["server_country_code"], response["server_country_code_l10n"] = "Canada", "ca-east", "ca"
					response["dns1"] = "8.8.8.8"
				}
				return response
			})
			client := offlineGateway(t, pub)
			client.Endpoint = srv.URL
			result, err := client.NegotiateConfig(context.Background(), gatewayTestCreds(), testUUID, "us-west", "awg")
			if err != nil {
				t.Fatal(err)
			}
			name, country, code, dns := "USA East", "US", "us-east", []string{"1.1.1.1", "9.9.9.9"}
			if outer {
				name, country, code, dns[0] = "Canada", "CA", "ca-east", "8.8.8.8"
			}
			if result.AWG == nil || result.ServerCountryName != name || result.CountryCode != country || result.ServerCountryCode != code || result.AWG.Name != name || result.AWG.CountryCode != country || !reflect.DeepEqual(result.AWG.DNS, dns) || !reflect.DeepEqual(result.DNS, dns) {
				t.Fatal("inner metadata missing or wrapper precedence lost")
			}
		})
	}
}
