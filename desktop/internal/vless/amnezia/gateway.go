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
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"multi-tun/desktop/internal/vless/model"
)

const DefaultGatewayEndpoint = "http://gw.amnezia.org:80/"

// The exact PEM bytes participate in proxy-list key derivation. Do not append
// a newline or reformat this constant.
const DefaultGatewayPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAj5mxl/4DL3Sk89ntxs5G
X3JawGQWIoq6rvNkOzNGuNgedNS2+pi6hZl3Izl1Io9om4KiUlMT6mgLO1hTr9q+
s7CYhlvroFA7ErucF+9L+7FCt0Igi0kIK/R2/vxd/2HaUrorn/aSvvutkYwbfxqW
SwtzE+RuBeDWGvEt937OW0oqYONPYv9E4T56Dz/EZ6v2t8ejAnKLbGD/GocMmipK
7etFSiSMAB2RmaztqTq4NleBepfO80XpYlW9pCSXuHcE8wxHczkzxsbyMAMsG/K3
vUQY6qPtohqqzSSBwa/8u2ptNHBeor7l7DdYXeR/Nqcc4z92VUkZ5lOVR4evkS5V
/wQqp5tnOJEj3NjUhEhXFoNEapbZd1bh6iQoUk7jC1TdvKJ/nPKGZAsHRpr0rNKz
fx/N/Oo6lr2yh/+ps6VxTkbPmB6E85WOO3UvjImZUY0XQdBjWle/4iJLdEC77Nr0
jXhdgeypucy6jkB6iBHMeVMlrNMEV7UxoBR/cCNx55zu/8sml5ByiDvCDT7sRomN
NgVt5S/FaVjYuzFUifJ12ToChXFgESKFmuso7WluEaWvMIGREdrMrKQKHfYLOzWF
2B5ZJDqw4o03fU4J/6rw61M1b+rjVpXMjPnzc2A+RgcjTvXv955gfZkwe4lt5wk/
3j8zMVo3+zLrMTAaEeIUM0UCAwEAAQ==
-----END PUBLIC KEY-----`

var DefaultS3PrimaryEndpoints = []string{
	"https://s3.eu-north-1.amazonaws.com/amnezia/",
	"https://storage.googleapis.com/lambda-list/",
	"https://amnzstrg01.blob.core.windows.net/lambda-list/",
	"https://objectstorage.eu-zurich-1.oraclecloud.com/n/zrhfyaq6qxvh/b/lambda-list/o/",
}

var DefaultS3FallbackEndpoints = []string{
	"https://storage.mwsapis.ru/lambda-list/",
	"https://46.8.209.252/lambda-list/",
	"https://s3.cloudruserapi.net/lambda-list/",
}

const (
	DefaultGatewayOSVersion    = "macos"
	DefaultGatewayAppVersion   = "5.1.1.10"
	DefaultGatewayCLIName      = "AmneziaVPN"
	DefaultGatewayDistribution = "github"
	DefaultGatewayAppLanguage  = "en"
	maxGatewayResponseBytes    = 32 << 20
)

// GatewayClient is safe for concurrent requests. Configure its exported fields
// before use. Nil S3 endpoint slices select production defaults; empty non-nil
// slices disable discovery. HTTPClient permits fully offline loopback testing.
// The gateway wire protocol provides encryption, but no response authentication.
// HTTPS certificate verification is always the HTTP transport's responsibility.
type GatewayClient struct {
	Endpoint            string
	PublicKeyPEM        string
	HTTPClient          *http.Client
	S3PrimaryEndpoints  []string
	S3FallbackEndpoints []string

	mu           sync.Mutex
	workingProxy string
}

func NewGatewayClient() *GatewayClient { return &GatewayClient{} }

func gatewayFailure(message string) error { return NewRefusal(CodeGatewayError, message) }

func newInstallationUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", gatewayFailure("cannot generate installation identifier")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

func validInstallationUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil
}

// LoadOrCreateInstallationUUID never replaces an invalid existing identity.
// Exclusive creation prevents concurrent callers from issuing different device
// identities. The mutex also keeps readers from seeing an incomplete local write.
var installationUUIDMu sync.Mutex

func LoadOrCreateInstallationUUID(cacheDir string) (string, error) {
	installationUUIDMu.Lock()
	defer installationUUIDMu.Unlock()
	if strings.TrimSpace(cacheDir) == "" {
		return "", gatewayFailure("installation cache directory is required")
	}
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", gatewayFailure("cannot create installation cache")
	}
	path := filepath.Join(cacheDir, "amnezia-installation-uuid")
	read := func() (string, error) {
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > 128 || st.Mode().Perm()&0077 != 0 {
			return "", gatewayFailure("invalid installation identifier file")
		}
		b, err := os.ReadFile(path)
		id := strings.TrimSpace(string(b))
		if err != nil || !validInstallationUUID(id) {
			return "", gatewayFailure("invalid installation identifier file")
		}
		return id, nil
	}
	if _, err := os.Lstat(path); err == nil {
		return read()
	} else if !os.IsNotExist(err) {
		return "", gatewayFailure("cannot read installation identifier")
	}
	id, err := newInstallationUUID()
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		return read()
	}
	if err != nil {
		return "", gatewayFailure("cannot persist installation identifier")
	}
	_, writeErr := io.WriteString(f, id)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return "", gatewayFailure("cannot persist installation identifier")
	}
	return id, nil
}

func GenerateWireGuardKeypair() (privateKeyB64, publicKeyB64 string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", gatewayFailure("cannot generate client key")
	}
	return base64.StdEncoding.EncodeToString(key.Bytes()), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

type AvailableCountry struct {
	ServerCountryCode     string   `json:"server_country_code"`
	ServerCountryCodeL10n string   `json:"server_country_code_l10n"`
	ServerCountryName     string   `json:"server_country_name"`
	AvailableProtocols    []string `json:"available_protocols"`
}

func (c AvailableCountry) ISOCountryCode() string {
	valid := func(s string) string {
		if len(s) != 2 {
			return ""
		}
		for _, b := range []byte(s) {
			if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z') {
				return ""
			}
		}
		return strings.ToUpper(s)
	}
	if code := valid(c.ServerCountryCodeL10n); code != "" {
		return code
	}
	prefix, _, _ := strings.Cut(c.ServerCountryCode, "-")
	return valid(prefix)
}

type IssuedConfig struct {
	InstallationUUID      string `json:"installation_uuid"`
	OSVersion             string `json:"os_version"`
	ServerCountryCode     string `json:"server_country_code"`
	ServerCountryCodeL10n string `json:"server_country_code_l10n"`
	ServerCountryName     string `json:"server_country_name"`
	SourceType            string `json:"source_type"`
}

type AccountInfo struct {
	ActiveDeviceCount   int                `json:"active_device_count"`
	MaxDeviceCount      int                `json:"max_device_count"`
	ServiceType         string             `json:"service_type"`
	SubscriptionEndDate string             `json:"subscription_end_date"`
	AvailableCountries  []AvailableCountry `json:"available_countries"`
	IssuedConfigs       []IssuedConfig     `json:"issued_configs"`
}

func (info AccountInfo) CatalogProfiles(preferredProtocol string) []model.Profile {
	profiles := make([]model.Profile, 0, len(info.AvailableCountries))
	for _, c := range info.AvailableCountries {
		proto := preferredProtocol
		if proto == "" && len(c.AvailableProtocols) > 0 {
			proto = c.AvailableProtocols[0]
		}
		supported := false
		for _, p := range c.AvailableProtocols {
			if p == proto {
				supported = true
				break
			}
		}
		if !supported || c.ServerCountryCode == "" || (proto != "awg" && proto != "vless") {
			continue
		}
		p := model.Profile{ID: "amnezia-" + strings.ToLower(c.ServerCountryCode), Name: firstText(c.ServerCountryName, strings.ToUpper(c.ServerCountryCode)), CountryCode: c.ISOCountryCode(), Protocol: "vless", Network: "tcp", Query: map[string]string{"amnezia_gateway": "v2", "amnezia_server_country_code": c.ServerCountryCode, "amnezia_service_protocol": proto}}
		if proto == "awg" {
			p.Protocol, p.Network = "amnezia-awg", "udp"
		}
		profiles = append(profiles, p)
	}
	sort.Slice(profiles, func(i, j int) bool {
		a, b := profiles[i], profiles[j]
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.CountryCode < b.CountryCode
	})
	return profiles
}

func IsGatewayCatalogProfile(p model.Profile) bool {
	return p.Query["amnezia_gateway"] == "v2" && GatewayServerCountryCode(p) != "" && (GatewayServiceProtocol(p) == "awg" || GatewayServiceProtocol(p) == "vless")
}
func GatewayServerCountryCode(p model.Profile) string { return p.Query["amnezia_server_country_code"] }
func GatewayServiceProtocol(p model.Profile) string   { return p.Query["amnezia_service_protocol"] }

func (c *GatewayClient) metadata(creds GatewayCredentials, installationUUID string) map[string]any {
	return map[string]any{"os_version": DefaultGatewayOSVersion, "app_version": DefaultGatewayAppVersion, "cli_name": DefaultGatewayCLIName, "distribution": DefaultGatewayDistribution, "app_language": DefaultGatewayAppLanguage, "installation_uuid": installationUUID, "user_country_code": creds.UserCountryCode, "service_type": creds.ServiceType, "auth_data": map[string]string{"api_key": creds.APIKey}}
}

func (c *GatewayClient) FetchAccountInfo(ctx context.Context, creds GatewayCredentials, installationUUID string) (AccountInfo, error) {
	var info AccountInfo
	request := c.metadata(creds, installationUUID)
	request["cli_version"], request["subscription_status"] = DefaultGatewayAppVersion, "active"
	body, err := c.call(ctx, creds, "v1/account_info", request)
	if err != nil {
		return info, err
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return AccountInfo{}, gatewayFailure("invalid account information")
	}
	return info, nil
}

type NegotiatedConfig struct {
	ServerCountryCode string
	ServerCountryName string
	CountryCode       string
	ServiceProtocol   string
	DNS               []string
	AWG               *AWGConfig
	Profiles          []model.Profile
}

func (c *GatewayClient) NegotiateConfig(ctx context.Context, creds GatewayCredentials, installationUUID, serverCountryCode, serviceProtocol string) (NegotiatedConfig, error) {
	var result NegotiatedConfig
	var privateKey, publicKey string
	var err error
	switch serviceProtocol {
	case "awg":
		privateKey, publicKey, err = GenerateWireGuardKeypair()
	case "vless":
		publicKey, err = newInstallationUUID()
	default:
		return result, NewRefusal(CodeProtocolUnsupported, "unsupported Amnezia gateway protocol")
	}
	if err != nil {
		return result, err
	}
	request := c.metadata(creds, installationUUID)
	request["server_country_code"], request["service_protocol"], request["public_key"], request["is_connect_event"] = serverCountryCode, serviceProtocol, publicKey, true
	body, err := c.call(ctx, creds, "v1/config", request)
	if err != nil {
		return result, err
	}
	var response struct {
		Config                string `json:"config"`
		ServerCountryCode     string `json:"server_country_code"`
		ServerCountryCodeL10n string `json:"server_country_code_l10n"`
		ServerCountryName     string `json:"server_country_name"`
		DNS1                  string `json:"dns1"`
		DNS2                  string `json:"dns2"`
	}
	if json.Unmarshal(body, &response) != nil || !strings.HasPrefix(response.Config, "vpn://") {
		return result, gatewayFailure("invalid negotiated configuration")
	}
	export, err := decodeVPNBytes(strings.TrimPrefix(response.Config, "vpn://"))
	if err != nil {
		return result, gatewayFailure("invalid negotiated configuration")
	}
	if serviceProtocol == "awg" {
		export = bytes.ReplaceAll(export, []byte("$WIREGUARD_CLIENT_PRIVATE_KEY"), []byte(privateKey))
	}
	decoded, err := decodeExport(export)
	if err != nil {
		return result, gatewayFailure("invalid negotiated configuration")
	}
	if serviceProtocol == "awg" && decoded.AWG == nil || serviceProtocol == "vless" && len(decoded.Profiles) == 0 {
		return result, NewRefusal(CodeProtocolUnsupported, "negotiated protocol does not match request")
	}
	var inner struct {
		DNS1      string `json:"dns1"`
		DNS2      string `json:"dns2"`
		APIConfig struct {
			ServerCountryCode     string `json:"server_country_code"`
			ServerCountryCodeL10n string `json:"server_country_code_l10n"`
			ServerCountryName     string `json:"server_country_name"`
		} `json:"api_config"`
	}
	if json.Unmarshal(export, &inner) != nil {
		return result, gatewayFailure("invalid negotiated configuration")
	}
	result.ServerCountryCode = firstText(response.ServerCountryCode, inner.APIConfig.ServerCountryCode, serverCountryCode)
	result.ServerCountryName = firstText(response.ServerCountryName, inner.APIConfig.ServerCountryName)
	result.CountryCode = (AvailableCountry{ServerCountryCode: result.ServerCountryCode, ServerCountryCodeL10n: firstText(response.ServerCountryCodeL10n, inner.APIConfig.ServerCountryCodeL10n)}).ISOCountryCode()
	result.ServiceProtocol, result.AWG, result.Profiles = serviceProtocol, decoded.AWG, decoded.Profiles
	for _, dns := range []string{firstText(response.DNS1, inner.DNS1), firstText(response.DNS2, inner.DNS2)} {
		if dns != "" {
			result.DNS = append(result.DNS, dns)
		}
	}
	if result.AWG != nil {
		result.AWG.CountryCode = result.CountryCode
		result.AWG.Name = firstText(result.ServerCountryName, result.AWG.Name, strings.ToUpper(result.ServerCountryCode))
		if len(result.AWG.DNS) == 0 {
			result.AWG.DNS = append([]string(nil), result.DNS...)
		}
		result.DNS = append([]string(nil), result.AWG.DNS...)
	}
	return result, nil
}

func (c *GatewayClient) RevokeConfig(ctx context.Context, creds GatewayCredentials, installationUUID, serverCountryCode string) error {
	request := c.metadata(creds, installationUUID)
	request["server_country_code"] = serverCountryCode
	_, err := c.call(ctx, creds, "v1/revoke_config", request)
	return err
}

func encryptGatewayCBC(plain, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, gatewayFailure("invalid encryption parameters")
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+padding)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded, nil
}

func decryptGatewayCBC(ct, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, gatewayFailure("invalid encrypted response")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(plain) {
		return nil, gatewayFailure("invalid encrypted response")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, gatewayFailure("invalid encrypted response")
		}
	}
	return plain[:len(plain)-padding], nil
}

func (c *GatewayClient) publicKeyPEM() string {
	if c.PublicKeyPEM != "" {
		return c.PublicKeyPEM
	}
	return DefaultGatewayPublicKeyPEM
}

func (c *GatewayClient) envelope(payload []byte) ([]byte, []byte, []byte, error) {
	key, iv, salt := make([]byte, 32), make([]byte, 32), make([]byte, 8)
	for _, b := range [][]byte{key, iv, salt} {
		if _, err := rand.Read(b); err != nil {
			return nil, nil, nil, gatewayFailure("cannot generate request encryption")
		}
	}
	block, rest := pem.Decode([]byte(c.publicKeyPEM()))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil, nil, gatewayFailure("invalid gateway public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, nil, gatewayFailure("invalid gateway public key")
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, nil, nil, gatewayFailure("invalid gateway public key")
	}
	keys, _ := json.Marshal(map[string]string{"aes_key": base64.StdEncoding.EncodeToString(key), "aes_iv": base64.StdEncoding.EncodeToString(iv), "aes_salt": base64.StdEncoding.EncodeToString(salt)})
	encKeys, err := rsa.EncryptPKCS1v15(rand.Reader, pub, keys)
	if err != nil {
		return nil, nil, nil, gatewayFailure("cannot encrypt request keys")
	}
	ct, err := encryptGatewayCBC(payload, key, iv[:16])
	if err != nil {
		return nil, nil, nil, err
	}
	body, err := json.Marshal(map[string]string{"key_payload": base64.StdEncoding.EncodeToString(encKeys), "api_payload": base64.StdEncoding.EncodeToString(ct)})
	if err != nil {
		return nil, nil, nil, gatewayFailure("cannot encode gateway request")
	}
	return body, key, iv[:16], nil
}

func gatewayURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", gatewayFailure("invalid gateway endpoint")
	}
	return strings.TrimRight(base, "/") + "/" + path, nil
}

func (c *GatewayClient) exchange(ctx context.Context, method, endpoint string, body []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, gatewayFailure("invalid gateway request")
	}
	if method == http.MethodPost {
		id, err := newInstallationUUID()
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Client-Request-ID", id)
	}
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// Never redirect an encrypted credential-bearing request to another origin.
	copyClient := *client
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := copyClient.Do(req)
	if err != nil {
		return nil, 0, WrapRefusal(CodeGatewayError, "gateway transport failed", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponseBytes+1))
	if err != nil || len(data) > maxGatewayResponseBytes {
		return nil, resp.StatusCode, gatewayFailure("invalid gateway response size")
	}
	return data, resp.StatusCode, nil
}

// attempt distinguishes recognized API refusals (never retried) from transport,
// block-page and framing failures, for which the official S3 route is applicable.
func (c *GatewayClient) attempt(ctx context.Context, base, endpoint string, envelope, key, iv []byte) ([]byte, bool, error) {
	u, err := gatewayURL(base, endpoint)
	if err != nil {
		return nil, true, err
	}
	ct, status, err := c.exchange(ctx, http.MethodPost, u, envelope)
	if err != nil {
		return nil, true, err
	}
	if bytes.Contains(bytes.ToLower(ct), []byte("html")) {
		return nil, true, gatewayFailure("gateway returned a block page")
	}
	body, err := decryptGatewayCBC(ct, key, iv)
	if err != nil {
		return nil, true, err
	}
	var result struct {
		HTTPStatus int `json:"http_status"`
	}
	if json.Unmarshal(body, &result) != nil || bytes.Equal(bytes.TrimSpace(body), []byte("null")) || bytes.Contains(bytes.ToLower(body), []byte("html")) {
		return nil, true, gatewayFailure("invalid gateway response document")
	}
	if result.HTTPStatus >= 300 {
		return nil, false, gatewayFailure("gateway API refused request (http status " + strconv.Itoa(result.HTTPStatus) + ")")
	}
	if status >= 300 {
		return nil, true, gatewayFailure("gateway HTTP request failed")
	}
	return body, false, nil
}

func (c *GatewayClient) call(ctx context.Context, creds GatewayCredentials, endpoint string, request map[string]any) ([]byte, error) {
	if strings.TrimSpace(creds.APIKey) == "" {
		return nil, NewRefusal(CodeKeyInvalid, "missing gateway credentials")
	}
	if ctx.Err() != nil {
		return nil, WrapRefusal(CodeGatewayError, "gateway request cancelled", ctx.Err())
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, gatewayFailure("cannot encode gateway request")
	}
	envelope, key, iv, err := c.envelope(payload)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	proxy := c.workingProxy
	c.mu.Unlock()
	base := firstText(c.Endpoint, DefaultGatewayEndpoint)
	if proxy != "" {
		base = proxy
	}
	body, retry, err := c.attempt(ctx, base, endpoint, envelope, key, iv)
	if !retry {
		return body, err
	}
	if ctx.Err() != nil {
		return nil, WrapRefusal(CodeGatewayError, "gateway request cancelled", ctx.Err())
	}
	if proxy != "" {
		c.mu.Lock()
		if c.workingProxy == proxy {
			c.workingProxy = ""
		}
		c.mu.Unlock()
		body, retry, err = c.attempt(ctx, firstText(c.Endpoint, DefaultGatewayEndpoint), endpoint, envelope, key, iv)
		if !retry {
			return body, err
		}
	}
	primary, fallback := c.S3PrimaryEndpoints, c.S3FallbackEndpoints
	if primary == nil {
		primary = DefaultS3PrimaryEndpoints
	}
	if fallback == nil {
		fallback = DefaultS3FallbackEndpoints
	}
	name := base64.RawURLEncoding.EncodeToString([]byte("endpoints-"+creds.ServiceType+"-"+creds.UserCountryCode)) + ".json"
	seen := map[string]bool{base: true}
	for _, sources := range [][]string{primary, fallback} {
		for _, source := range sources {
			for _, path := range []string{name, "endpoints.json"} {
				if ctx.Err() != nil {
					return nil, WrapRefusal(CodeGatewayError, "gateway request cancelled", ctx.Err())
				}
				proxies, listErr := c.proxyList(ctx, source, path)
				if listErr != nil {
					continue
				}
				ordered := make([]string, 0, len(proxies))
				remaining := make([]string, 0, len(proxies))
				for _, p := range proxies {
					if seen[p] {
						continue
					}
					seen[p] = true
					u, urlErr := gatewayURL(p, "lmbd-health")
					if urlErr != nil {
						continue
					}
					_, status, healthErr := c.exchange(ctx, http.MethodGet, u, nil)
					if healthErr == nil && status < 400 {
						ordered = append(ordered, p)
					} else {
						remaining = append(remaining, p)
					}
				}
				for _, p := range append(ordered, remaining...) {
					body, retry, err = c.attempt(ctx, p, endpoint, envelope, key, iv)
					if !retry {
						c.mu.Lock()
						c.workingProxy = p
						c.mu.Unlock()
						return body, err
					}
				}
			}
		}
	}
	if ctx.Err() != nil {
		return nil, WrapRefusal(CodeGatewayError, "gateway request cancelled", ctx.Err())
	}
	return nil, gatewayFailure("gateway and proxy routes unavailable")
}

func (c *GatewayClient) proxyList(ctx context.Context, base, path string) ([]string, error) {
	u, err := gatewayURL(base, path)
	if err != nil {
		return nil, err
	}
	body, status, err := c.exchange(ctx, http.MethodGet, u, nil)
	if err != nil || status >= 400 {
		return nil, gatewayFailure("proxy discovery failed")
	}
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil {
		return nil, gatewayFailure("invalid proxy list")
	}
	digest := sha512.Sum512([]byte(c.publicKeyPEM()))
	// Hex-decoding sha512Hex[0:64] and [64:96] yields these byte slices.
	plain, err := decryptGatewayCBC(ct, digest[:32], digest[32:48])
	if err != nil {
		return nil, err
	}
	var proxies []string
	if json.Unmarshal(plain, &proxies) != nil {
		return nil, gatewayFailure("invalid proxy list")
	}
	return proxies, nil
}
