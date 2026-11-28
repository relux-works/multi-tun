package amnezia

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/subscription"
)

const MaxDecompressedBytes = 4 << 20

// PayloadSummary contains only structural metadata. Never copy free-form export
// text here: descriptions and even defaultContainer can contain credentials.
type PayloadSummary struct {
	Format           string
	Protocol         string
	ContainerCount   int
	ProfileCount     int
	Countries        []string
	DefaultContainer string
	OpenConstruct    string
}

type AWGConfig struct {
	Name                   string
	CountryCode            string
	EndpointHost           string
	EndpointPort           int
	Address                []string
	DNS                    []string
	AllowedIPs             []string
	MTU                    int
	PersistentKeepalive    int
	Jc, Jmin, Jmax         int
	S1, S2, S3, S4         int
	H1, H2, H3, H4         string
	I1, I2, I3, I4, I5     string
	PublicKey              string
	PrivateKey             string `json:"-"`
	PresharedKey           string `json:"-"`
	PersistentKeepaliveRaw string
	HeaderProtectionKey    string `json:"-"`
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         string
	DisableCookies         string
}

type GatewayCredentials struct {
	Name            string `json:"name,omitempty"`
	Description     string `json:"description,omitempty"`
	ConfigVersion   int    `json:"config_version"`
	ServiceType     string `json:"service_type"`
	ServiceProtocol string `json:"service_protocol"`
	UserCountryCode string `json:"user_country_code"`
	APIKey          string `json:"-"`
}

type DecodedPayload struct {
	Format          string
	Protocol        string
	Profiles        []model.Profile
	AWG             *AWGConfig
	Gateway         *GatewayCredentials
	SubscriptionURL string
	Summary         PayloadSummary
}

func (d DecodedPayload) ValidateRunnable(engineType string) error {
	engine := strings.ToLower(strings.TrimSpace(engineType))
	awgEngine := engine == "" || engine == "sing-box" || engine == "singbox" || engine == "amnezia-awg"
	switch d.Protocol {
	case "amnezia-awg":
		if !awgEngine {
			return NewRefusal(CodeEngineUnavailable, "incompatible engine for amnezia-awg")
		}
	case "amnezia-gateway":
		if d.Gateway == nil {
			return NewRefusal(CodeGatewayUnimplemented, "unsupported Amnezia gateway credentials")
		}
		if d.Gateway.ServiceProtocol == "awg" && !awgEngine {
			return NewRefusal(CodeEngineUnavailable, "incompatible engine for amnezia-awg")
		}
	}
	return nil
}

func invalidPayload() error {
	return NewRefusal(CodeKeyInvalid, "invalid amnezia payload")
}

// EncodeVPNURI writes Qt's qCompress framing, followed by URL-safe base64.
func EncodeVPNURI(jsonData []byte) (string, error) {
	if uint64(len(jsonData)) > uint64(^uint32(0)) {
		return "", NewRefusal(CodeKeyInvalid, "amnezia payload exceeds qCompress length capacity")
	}
	var buf bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(jsonData)))
	buf.Write(header[:])
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(jsonData); err != nil {
		return "", invalidPayload()
	}
	if err := zw.Close(); err != nil {
		return "", invalidPayload()
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeKey is entirely offline. Errors deliberately discard parser diagnostics
// because those diagnostics may quote credentials from the input.
func DecodeKey(raw string) (DecodedPayload, error) {
	trimmed := strings.TrimSpace(raw)
	var d DecodedPayload
	var err error
	switch {
	case trimmed == "":
		return d, NewRefusal(CodeKeyEmpty, "amnezia key is empty")
	case trimmed == PlaceholderKey:
		return d, NewRefusal(CodeKeyPlaceholder, "replace the amnezia placeholder key")
	case len(trimmed) > MaxDecompressedBytes*2:
		return d, NewRefusal(CodeKeyInvalid, "amnezia payload exceeds maximum decompressed size")
	case strings.HasPrefix(trimmed, "vpn://"):
		var body []byte
		body, err = decodeVPNBytes(strings.TrimSpace(strings.TrimPrefix(trimmed, "vpn://")))
		if err == nil {
			d, err = decodeExport(body)
		}
	case strings.HasPrefix(strings.ToLower(trimmed), "vless://"):
		// ParseProfiles expects a lower-case scheme; DecodeKey admits either case.
		d.Format, d.Protocol = "vless", "vless"
		d.Profiles, err = subscription.ParseProfiles("vless://" + trimmed[len("vless://"):])
		if err != nil {
			err = invalidPayload()
		}
		for i := range d.Profiles {
			d.Profiles[i].CountryCode = subscription.ProfileCountryCode(d.Profiles[i])
		}
	case strings.HasPrefix(strings.ToLower(trimmed), "https://"):
		parsed, parseErr := url.Parse(trimmed)
		if parseErr != nil || parsed.Host == "" || parsed.Hostname() == "" {
			return DecodedPayload{}, invalidPayload()
		}
		d.Format, d.Protocol, d.SubscriptionURL = "subscription_url", "subscription", trimmed
	case strings.HasPrefix(strings.ToLower(trimmed), "http://"):
		return d, NewRefusal(CodeKeyInvalid, "amnezia subscription URL must use https")
	case strings.Contains(trimmed, "[Interface]") && strings.Contains(trimmed, "[Peer]"):
		d.Format, d.Protocol = "awg_ini", "amnezia-awg"
		d.AWG, err = ParseAWGINI(trimmed)
	default:
		return d, NewRefusal(CodeKeyInvalid, "unsupported amnezia key format")
	}
	if err != nil {
		return DecodedPayload{}, err
	}
	d.Summary.Format, d.Summary.Protocol = d.Format, d.Protocol
	d.Summary.ProfileCount = len(d.Profiles)
	countries := make(map[string]bool)
	for _, profile := range d.Profiles {
		if country := subscription.ProfileCountryCode(profile); country != "" {
			countries[country] = true
		}
	}
	if d.AWG != nil && d.AWG.CountryCode != "" {
		countries[d.AWG.CountryCode] = true
	}
	for country := range countries {
		d.Summary.Countries = append(d.Summary.Countries, country)
	}
	sort.Strings(d.Summary.Countries)
	return d, nil
}

func decodeVPNBytes(encoded string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, invalidPayload()
	}
	if len(raw) >= 6 {
		zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
		if err == nil {
			declared := binary.BigEndian.Uint32(raw[:4])
			if declared == 0 || declared > MaxDecompressedBytes {
				_ = zr.Close()
				return nil, NewRefusal(CodeKeyInvalid, "amnezia payload exceeds maximum decompressed size")
			}
			body, readErr := io.ReadAll(io.LimitReader(zr, MaxDecompressedBytes+1))
			closeErr := zr.Close()
			// Qt's qUncompress treats the 4-byte big-endian prefix as an initial
			// buffer hint and grows dynamically if inflate emits more bytes (real
			// Amnezia Premium API v2 keys carry 0x000000ff with >255-byte JSON).
			// Enforce both the bounded 4 MiB decompression cap and zlib checksum
			// verification via zr.Close().
			if readErr != nil || closeErr != nil || len(body) == 0 || len(body) > MaxDecompressedBytes {
				return nil, invalidPayload()
			}
			return body, nil
		}
	}
	if len(raw) > 0 && raw[0] == '{' && len(raw) <= MaxDecompressedBytes {
		return raw, nil
	}
	return nil, invalidPayload()
}

type exportServer struct {
	Description       string            `json:"description"`
	HostName          string            `json:"hostName"`
	Country           string            `json:"country"`
	CountryCode       string            `json:"country_code"`
	ServerCountryCode string            `json:"server_country_code"`
	DefaultContainer  string            `json:"defaultContainer"`
	Containers        []exportContainer `json:"containers"`
}

type exportContainer struct {
	Container   string          `json:"container"`
	Description string          `json:"description"`
	Xray        json.RawMessage `json:"xray"`
	AWG         json.RawMessage `json:"awg"`
	Wireguard   json.RawMessage `json:"wireguard"`
}

func decodeExport(body []byte) (DecodedPayload, error) {
	d := DecodedPayload{Format: "vpn"}
	if !utf8.Valid(body) {
		return d, invalidPayload()
	}
	var root struct {
		exportServer
		Servers       []exportServer  `json:"servers"`
		ConfigVersion int             `json:"config_version"`
		APIEndpoint   json.RawMessage `json:"api_endpoint"`
		APIKey        json.RawMessage `json:"api_key"`
		APIConfig     json.RawMessage `json:"api_config"`
		AuthData      json.RawMessage `json:"auth_data"`
		Name          string          `json:"name"`
	}
	if err := json.Unmarshal(body, &root); err != nil || bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return d, invalidPayload()
	}
	servers := root.Servers
	var staticErr error
	if len(root.Containers) > 0 {
		servers = append([]exportServer{root.exportServer}, servers...)
	}
	for _, server := range servers {
		if knownContainer(server.DefaultContainer) && d.Summary.DefaultContainer == "" {
			d.Summary.DefaultContainer = server.DefaultContainer
		}
		for _, container := range server.Containers {
			d.Summary.ContainerCount++
			name := firstText(server.Description, container.Description)
			country := exportCountry(server, name)
			switch {
			case container.Container == "amnezia-xray" || len(container.Xray) > 0:
				config, err := lastConfig(container.Xray)
				if err != nil {
					staticErr = err
					continue
				}
				profiles, err := parseXray(config, name, country)
				if err != nil {
					staticErr = err
					continue
				}
				d.Profiles = append(d.Profiles, profiles...)
			case container.Container == "amnezia-awg" || container.Container == "amnezia-wireguard" || len(container.AWG) > 0 || len(container.Wireguard) > 0:
				raw := container.AWG
				if len(raw) == 0 {
					raw = container.Wireguard
				}
				config, err := lastConfig(raw)
				if err != nil {
					staticErr = err
					continue
				}
				cfg, err := parseAWGExport(config)
				if err != nil {
					staticErr = err
					continue
				}
				cfg.Name, cfg.CountryCode = name, country
				if cfg.Name == "" {
					cfg.Name = net.JoinHostPort(cfg.EndpointHost, strconv.Itoa(cfg.EndpointPort))
				}
				if d.AWG == nil {
					d.AWG = cfg
				}
			}
		}
	}
	if len(d.Profiles) == 0 && d.AWG == nil {
		var api struct {
			ServiceType     string `json:"service_type"`
			ServiceProtocol string `json:"service_protocol"`
			UserCountryCode string `json:"user_country_code"`
		}
		var auth struct {
			APIKey string `json:"api_key"`
		}
		if root.ConfigVersion == 2 && json.Unmarshal(root.APIConfig, &api) == nil && json.Unmarshal(root.AuthData, &auth) == nil && api.ServiceType == "amnezia-premium" {
			if strings.TrimSpace(auth.APIKey) == "" {
				return d, invalidPayload()
			}
			if api.ServiceProtocol == "" {
				api.ServiceProtocol = "awg"
			}
			if api.ServiceProtocol != "awg" && api.ServiceProtocol != "vless" {
				return d, NewRefusal(CodeProtocolUnsupported, "unsupported Amnezia gateway protocol")
			}
			d.Format, d.Protocol = "amnezia-premium-v2", "amnezia-gateway"
			d.Gateway = &GatewayCredentials{Name: root.Name, Description: root.Description, ConfigVersion: 2, ServiceType: api.ServiceType, ServiceProtocol: api.ServiceProtocol, UserCountryCode: api.UserCountryCode, APIKey: auth.APIKey}
			return d, nil
		}
		if len(root.APIEndpoint) > 0 || len(root.APIKey) > 0 || len(root.APIConfig) > 0 || len(root.AuthData) > 0 {
			return d, NewRefusal(CodeGatewayUnimplemented, "unsupported Amnezia gateway credentials")
		}
	}
	if staticErr != nil {
		return d, staticErr
	}
	switch {
	case len(d.Profiles) > 0:
		d.Protocol = "vless"
	case d.AWG != nil:
		d.Protocol = "amnezia-awg"
	case d.Summary.ContainerCount > 0:
		return d, NewRefusal(CodeProtocolUnsupported, "amnezia export has no supported static protocol")
	default:
		return d, invalidPayload()
	}
	return d, nil
}

func knownContainer(value string) bool {
	switch value {
	case "amnezia-xray", "amnezia-awg", "amnezia-wireguard", "amnezia-openvpn", "amnezia-cloak", "amnezia-shadowsocks":
		return true
	}
	return false
}

func firstText(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func exportCountry(server exportServer, name string) string {
	for _, value := range []string{server.ServerCountryCode, server.CountryCode, server.Country} {
		if code := subscription.ProfileCountryCode(model.Profile{CountryCode: value}); code != "" {
			return code
		}
	}
	return subscription.CountryCode(name)
}

// last_config is a JSON document in current exports and a JSON string holding
// that document in older exports. Unwrap precisely that one string layer.
func lastConfig(raw json.RawMessage) ([]byte, error) {
	var wrapper struct {
		LastConfig json.RawMessage `json:"last_config"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil || len(wrapper.LastConfig) == 0 {
		return nil, invalidPayload()
	}
	config := bytes.TrimSpace(wrapper.LastConfig)
	if len(config) > 0 && config[0] == '"' {
		var text string
		if err := json.Unmarshal(config, &text); err != nil {
			return nil, invalidPayload()
		}
		return []byte(text), nil
	}
	return config, nil
}

func parseXray(raw []byte, name, country string) ([]model.Profile, error) {
	var config struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID, Flow, Encryption string
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings struct {
				Network, Security string
				TLSSettings       struct {
					ServerName, Fingerprint string
					ALPN                    []string
				} `json:"tlsSettings"`
				RealitySettings struct {
					ServerName, Fingerprint, PublicKey, ShortID, SpiderX string
				} `json:"realitySettings"`
				GRPCSettings struct {
					ServiceName, Authority string
				} `json:"grpcSettings"`
			} `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, invalidPayload()
	}
	var profiles []model.Profile
	for _, outbound := range config.Outbounds {
		if outbound.Protocol != "vless" {
			continue
		}
		for _, next := range outbound.Settings.Vnext {
			if len(next.Users) == 0 || next.Users[0].ID == "" || next.Address == "" || next.Port < 1 || next.Port > 65535 {
				return nil, invalidPayload()
			}
			stream := outbound.StreamSettings
			query := url.Values{}
			set := func(key, value string) {
				if value != "" {
					query.Set(key, value)
				}
			}
			set("type", firstText(stream.Network, "tcp"))
			set("security", stream.Security)
			set("flow", next.Users[0].Flow)
			set("encryption", firstText(next.Users[0].Encryption, "none"))
			switch stream.Security {
			case "reality":
				set("sni", stream.RealitySettings.ServerName)
				set("fp", stream.RealitySettings.Fingerprint)
				set("pbk", stream.RealitySettings.PublicKey)
				set("sid", stream.RealitySettings.ShortID)
				set("spx", stream.RealitySettings.SpiderX)
			case "tls":
				set("sni", stream.TLSSettings.ServerName)
				set("fp", stream.TLSSettings.Fingerprint)
				set("alpn", strings.Join(stream.TLSSettings.ALPN, ","))
			}
			set("serviceName", stream.GRPCSettings.ServiceName)
			set("authority", stream.GRPCSettings.Authority)
			uri := url.URL{
				Scheme: "vless", User: url.User(next.Users[0].ID),
				Host:     net.JoinHostPort(next.Address, strconv.Itoa(next.Port)),
				RawQuery: query.Encode(), Fragment: firstText(name, net.JoinHostPort(next.Address, strconv.Itoa(next.Port))),
			}
			profile, err := subscription.ParseVLESSURI(uri.String())
			if err != nil {
				return nil, invalidPayload()
			}
			digest := sha1.Sum([]byte(uri.String()))
			profile.ID = hex.EncodeToString(digest[:6])
			profile.CountryCode = firstText(country, subscription.CountryCode(profile.DisplayName()))
			profiles = append(profiles, profile)
		}
	}
	return profiles, nil
}

func parseAWGExport(raw []byte) (*AWGConfig, error) {
	var config struct {
		Config   string `json:"Config"`
		MTU      int
		HostName string `json:"hostName"`
		Port     int
	}
	// MTU and port have appeared as both numbers and strings in exports.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, invalidPayload()
	}
	ini, ok := fields["Config"]
	if !ok {
		ini = fields["config"]
	}
	if err := json.Unmarshal(ini, &config.Config); err != nil {
		return nil, invalidPayload()
	}
	for key, dst := range map[string]*int{"MTU": &config.MTU, "port": &config.Port} {
		if value, ok := fields[key]; ok {
			var number json.Number
			if err := json.Unmarshal(value, &number); err != nil {
				return nil, invalidPayload()
			}
			parsed, err := strconv.Atoi(number.String())
			if err != nil || parsed < 0 || (key == "port" && parsed > 65535) {
				return nil, invalidPayload()
			}
			*dst = parsed
		}
	}
	if value, ok := fields["hostName"]; ok {
		if err := json.Unmarshal(value, &config.HostName); err != nil {
			return nil, invalidPayload()
		}
	}
	cfg, err := ParseAWGINI(config.Config)
	if err != nil {
		return nil, err
	}
	if config.MTU != 0 {
		cfg.MTU = config.MTU
	}
	if config.HostName != "" {
		cfg.EndpointHost = config.HostName
	}
	if config.Port != 0 {
		cfg.EndpointPort = config.Port
	}
	return cfg, nil
}

// ParseAWGINI parses one interface and one peer without contacting an endpoint
// or invoking WireGuard, a tunnel helper, or the macOS Keychain.
func ParseAWGINI(raw string) (*AWGConfig, error) {
	if len(raw) > MaxDecompressedBytes {
		return nil, invalidPayload()
	}
	cfg := &AWGConfig{}
	section := ""
	seen := make(map[string]bool)
	values := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), MaxDecompressedBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" || seen[line] {
				return nil, invalidPayload()
			}
			section = line
			seen[line] = true
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || section == "" || value == "" {
			return nil, invalidPayload()
		}
		// Inline comments are delimited by whitespace so base64 and endpoint
		// tokens are preserved exactly.
		for _, marker := range []string{" #", " ;", "\t#", "\t;"} {
			if before, _, found := strings.Cut(value, marker); found {
				value = strings.TrimSpace(before)
			}
		}
		if values[section+key] {
			return nil, invalidPayload()
		}
		values[section+key] = true
		var number *int
		var text *string
		var list *[]string
		switch section + key {
		case "[Interface]PrivateKey":
			text = &cfg.PrivateKey
		case "[Interface]HeaderProtectionKey":
			text = &cfg.HeaderProtectionKey
		case "[Interface]ContentPaddingAddition":
			text = &cfg.ContentPaddingAddition
		case "[Interface]RekeyAfterTime":
			text = &cfg.RekeyAfterTime
		case "[Interface]RekeyTimeout":
			text = &cfg.RekeyTimeout
		case "[Interface]RejectAfterTime":
			text = &cfg.RejectAfterTime
		case "[Interface]KeepaliveTimeout":
			text = &cfg.KeepaliveTimeout
		case "[Interface]MaxHandshakeAttempts":
			text = &cfg.MaxHandshakeAttempts
		case "[Interface]RandomTrailers":
			text = &cfg.RandomTrailers
		case "[Interface]DisableCookies":
			text = &cfg.DisableCookies
		case "[Interface]Address":
			list = &cfg.Address
		case "[Interface]DNS":
			list = &cfg.DNS
		case "[Interface]MTU":
			number = &cfg.MTU
		case "[Interface]Jc":
			number = &cfg.Jc
		case "[Interface]Jmin":
			number = &cfg.Jmin
		case "[Interface]Jmax":
			number = &cfg.Jmax
		case "[Interface]S1":
			number = &cfg.S1
		case "[Interface]S2":
			number = &cfg.S2
		case "[Interface]S3":
			number = &cfg.S3
		case "[Interface]S4":
			number = &cfg.S4
		case "[Interface]H1":
			text = &cfg.H1
		case "[Interface]H2":
			text = &cfg.H2
		case "[Interface]H3":
			text = &cfg.H3
		case "[Interface]H4":
			text = &cfg.H4
		case "[Interface]I1":
			text = &cfg.I1
		case "[Interface]I2":
			text = &cfg.I2
		case "[Interface]I3":
			text = &cfg.I3
		case "[Interface]I4":
			text = &cfg.I4
		case "[Interface]I5":
			text = &cfg.I5
		case "[Peer]PublicKey":
			text = &cfg.PublicKey
		case "[Peer]PresharedKey":
			text = &cfg.PresharedKey
		case "[Peer]AllowedIPs":
			list = &cfg.AllowedIPs
		case "[Peer]PersistentKeepalive":
			bounds := strings.Split(value, "-")
			if len(bounds) > 2 {
				return nil, invalidPayload()
			}
			min, err := strconv.ParseUint(bounds[0], 10, 16)
			if err != nil {
				return nil, invalidPayload()
			}
			if len(bounds) == 2 {
				max, err := strconv.ParseUint(bounds[1], 10, 16)
				if err != nil || min > max {
					return nil, invalidPayload()
				}
			}
			cfg.PersistentKeepalive, cfg.PersistentKeepaliveRaw = int(min), value
		case "[Peer]Endpoint":
			host, port, err := net.SplitHostPort(value)
			if err != nil || host == "" {
				return nil, invalidPayload()
			}
			cfg.EndpointHost = host
			cfg.EndpointPort, err = strconv.Atoi(port)
			if err != nil || cfg.EndpointPort < 1 || cfg.EndpointPort > 65535 {
				return nil, invalidPayload()
			}
		default:
			// Reject hooks and other unsupported directives rather than silently
			// accepting a configuration whose effects cannot be represented.
			return nil, invalidPayload()
		}
		if text != nil {
			*text = value
		}
		if list != nil {
			for _, item := range strings.Split(value, ",") {
				if item = strings.TrimSpace(item); item == "" {
					return nil, invalidPayload()
				} else {
					*list = append(*list, item)
				}
			}
		}
		if number != nil {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return nil, invalidPayload()
			}
			*number = parsed
		}
	}
	if scanner.Err() != nil || !seen["[Interface]"] || !seen["[Peer]"] || cfg.PrivateKey == "" || cfg.PublicKey == "" || cfg.EndpointHost == "" {
		return nil, invalidPayload()
	}
	return cfg, nil
}
