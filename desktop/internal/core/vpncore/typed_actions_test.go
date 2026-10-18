package vpncore

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/singbox"
)

func TestSingBoxConfigValidationRejectsOutsideRendererSchema(t *testing.T) {
	// This negative table proves executable/file primitives, non-rendered types, non-loopback SOCKS, collisions, and an unknown key at every object position are refused.
	cases := map[string]string{
		"tor executable and args": `{"outbounds":[{"type":"tor","executable_path":"/tmp/run-me","extra_args":["--anything"]}]}`,
		"ssh private key":         `{"outbounds":[{"type":"ssh","private_key_path":"/private/key"}]}`,
		"tls certificate path":    `{"outbounds":[{"type":"vless","tls":{"certificate_path":"/private/cert"}}]}`,
		"tls key path":            `{"outbounds":[{"type":"vless","tls":{"key_path":"/private/key"}}]}`,
		"tls ech config path":     `{"outbounds":[{"type":"vless","tls":{"ech":{"config_path":"/private/ech"}}}]}`,
		"tls acme data directory": `{"outbounds":[{"type":"vless","tls":{"acme":{"data_directory":"/private/acme"}}}]}`,
		"non-loopback socks":      `{"outbounds":[{"type":"socks","server":"192.0.2.1"}]}`,
		"missing socks server":    `{"outbounds":[{"type":"socks"}]}`,
		"unknown top level":       `{"unknown":true}`,
		"unknown log":             `{"log":{"unknown":true}}`,
		"unknown dns":             `{"dns":{"unknown":true}}`,
		"unknown dns server":      `{"dns":{"servers":[{"type":"local","unknown":true}]}}`,
		"unknown dns tls":         `{"dns":{"servers":[{"type":"tls","tls":{"unknown":true}}]}}`,
		"unknown dns rule":        `{"dns":{"rules":[{"unknown":true}]}}`,
		"unknown inbound":         `{"inbounds":[{"type":"tun","unknown":true}]}`,
		"unknown outbound":        `{"outbounds":[{"type":"direct","unknown":true}]}`,
		"unknown vless tls":       `{"outbounds":[{"type":"vless","tls":{"unknown":true}}]}`,
		"unknown reality":         `{"outbounds":[{"type":"vless","tls":{"reality":{"unknown":true}}}]}`,
		"unknown utls":            `{"outbounds":[{"type":"vless","tls":{"utls":{"unknown":true}}}]}`,
		"unknown transport":       `{"outbounds":[{"type":"vless","transport":{"type":"grpc","unknown":true}}]}`,
		"unknown route":           `{"route":{"unknown":true}}`,
		"unknown resolver":        `{"route":{"default_domain_resolver":{"unknown":true}}}`,
		"unknown route rule":      `{"route":{"rules":[{"unknown":true}]}}`,
		"unknown rule set":        `{"route":{"rule_set":[{"type":"inline","unknown":true}]}}`,
		"unknown inline rule":     `{"route":{"rule_set":[{"type":"inline","rules":[{"unknown":true}]}]}}`,
		"remote rule set":         `{"route":{"rule_set":[{"type":"remote","url":"https://example.test/rules"}]}}`,
		"non-tun inbound":         `{"inbounds":[{"type":"mixed","listen":"127.0.0.1"}]}`,
		"case unknown":            `{"log":{"Output":"/tmp/x"}}`,
		"case colliding keys":     `{"route":{"rule_set":[{"type":"inline","Type":"inline"}]}}`,
		"case top-level dup":      `{"log":{},"LOG":{}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSingBoxConfig([]byte(raw)); err == nil {
				t.Fatalf("validateSingBoxConfig(%s) error = nil", raw)
			}
		})
	}
}

func TestSingBoxConfigValidationAcceptsEveryRendererVariant(t *testing.T) {
	// These real-renderer controls prove the positive schema covers both engines, TUN/overlay/routing helpers, tcp/gRPC, TLS/Reality, flow, and process rules.
	realityTCP := model.Profile{
		UUID: "00000000-0000-0000-0000-000000000001", Host: "203.0.113.77", Port: 443, Network: "tcp",
		Security: "reality", SNI: "example.com", Fingerprint: "chrome", PublicKey: "public-key", ShortID: "abcd",
	}
	grpcTLS := model.Profile{
		UUID: "00000000-0000-0000-0000-000000000002", Host: "vpn.example.com", Port: 443, Network: "grpc",
		ServiceName: "service", Security: "tls", SNI: "vpn.example.com", Fingerprint: "chrome",
	}
	withFlow := realityTCP
	withFlow.Flow = "xtls-rprx-vision"

	overlayConfig := config.Default()
	overlayConfig.Routing.BypassSuffixes = []string{".ru"}
	overlayConfig.Routing.BypassExcludes = []string{"t.me"}
	overlayConfig.Routing.Routes = []string{"10.0.0.0/8"}
	fragment := true
	overlayConfig.Singbox = &config.SingboxConfig{
		Sniff: &config.SniffConfig{Enabled: &fragment, Sniffers: []string{"tls"}, Timeout: "1s"},
		TLS: config.TLSClientConfig{
			Fragment: &fragment, FragmentFallbackDelay: "250ms", RecordFragment: &fragment, CurvePreferences: []string{"X25519"},
		},
	}
	xrayConfig := config.Default()
	xrayConfig.Engine = &config.EngineConfig{Type: config.EngineXray, Xray: &config.XrayEngineConfig{
		SocksListen: "127.0.0.1", SocksPort: 21808, ProcessNames: []string{"xray"},
	}}

	cases := map[string]func() ([]byte, error){
		"vless tcp reality": func() ([]byte, error) { return singbox.Render(config.Default(), realityTCP) },
		"vless grpc tls":    func() ([]byte, error) { return singbox.Render(config.Default(), grpcTLS) },
		"vless flow":        func() ([]byte, error) { return singbox.Render(config.Default(), withFlow) },
		"overlay and routes": func() ([]byte, error) {
			return singbox.RenderWithOptions(overlayConfig, realityTCP, singbox.RenderOptions{OverlayDNS: &singbox.OverlayDNS{
				Domains: []string{"corp.example"}, Nameservers: []string{"10.0.0.53"}, RouteExcludes: []string{"10.0.0.0/8"},
			}})
		},
		"xray frontend": func() ([]byte, error) {
			return singbox.RenderXrayFrontendWithOptions(xrayConfig, grpcTLS, singbox.RenderOptions{})
		},
	}
	for name, render := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := render()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := validateSingBoxConfig(data); err != nil {
				t.Fatalf("validate rendered config: %v\n%s", err, data)
			}
		})
	}
}

func TestSingBoxSchemaContainsNoFilesystemOrControlPlaneKeys(t *testing.T) {
	// This schema guard proves future allowed-key additions cannot silently introduce path/file/exec/control-plane primitives.
	for schemaName, schema := range singBoxSchemas {
		for key := range schema.fields {
			lower := strings.ToLower(key)
			for _, forbidden := range []string{"path", "dir", "file", "executable", "args", "api", "controller", "cache", "output"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("schema %q allows key %q containing forbidden fragment %q", schemaName, key, forbidden)
				}
			}
		}
	}
}

func TestSCUtilValidationRejectsOutsideGrammar(t *testing.T) {
	// This negative table proves global keys, command substitution tokens, and trailing junk cannot reach scutil.
	for _, input := range []string{
		"set State:/Network/Global/DNS\n",
		"d.add X `id`\n",
		"d.init trailing\n",
	} {
		if err := validateSCUtilInput(input); err == nil {
			t.Fatalf("validateSCUtilInput(%q) error = nil", input)
		}
	}
}

func TestSCUtilValidationAcceptsCurrentVLESSInput(t *testing.T) {
	// This positive control proves the exact apply/remove grammar emitted by vless-tun remains accepted.
	uuid := "01234567-89AB-CDEF-0123-456789ABCDEF"
	input := strings.Join([]string{
		"d.init",
		"d.add ConfirmedServiceID " + uuid,
		"d.add InterfaceName utun7",
		"d.add ServerAddresses * 1.1.1.1 2606:4700:4700::1111",
		"set State:/Network/Service/" + uuid + "/DNS",
		"d.init",
		"d.add Addresses * 198.18.0.1",
		"d.add InterfaceName utun7",
		"d.add Router 198.18.0.1",
		"set State:/Network/Service/" + uuid + "/IPv4",
		"remove State:/Network/Service/" + uuid + "/DNS",
		"remove State:/Network/Service/" + uuid + "/IPv4",
	}, "\n") + "\n"
	if err := validateSCUtilInput(input); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkSetupValidationHasPositiveAndNegativeControls(t *testing.T) {
	// This proves only a listed service plus IPs (or Empty) passes, while unknown services and non-IP servers fail.
	order := []byte("(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n")
	if err := validateNetworkSetup("Wi-Fi", []string{"1.1.1.1", "2606:4700:4700::1111"}, order); err != nil {
		t.Fatalf("valid setup: %v", err)
	}
	if err := validateNetworkSetup("Wi-Fi", []string{"Empty"}, order); err != nil {
		t.Fatalf("valid Empty setup: %v", err)
	}
	for _, tc := range []struct {
		service string
		servers []string
	}{{"Ethernet", []string{"1.1.1.1"}}, {"Wi-Fi", []string{"not-an-ip"}}} {
		if err := validateNetworkSetup(tc.service, tc.servers, order); err == nil {
			t.Fatalf("validateNetworkSetup(%q,%v) error = nil", tc.service, tc.servers)
		}
	}
}

func TestResolverCleanupRemovesOnlyMarkedRegularFiles(t *testing.T) {
	// This proves cleanup removes the two owned marker families while leaving unmarked files and symlinks untouched.
	dir := t.TempDir()
	marked := filepath.Join(dir, "marked")
	public := filepath.Join(dir, "public")
	unmarked := filepath.Join(dir, "unmarked")
	for path, data := range map[string]string{marked: "# Added by openconnect-tun DNS shim\nnameserver 1.1.1.1\n", public: "# Added by openconnect-tun public bypass x\n", unmarked: "nameserver 8.8.8.8\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(marked, link); err != nil {
		t.Fatal(err)
	}
	previous := resolverDirVPNCore
	resolverDirVPNCore = dir
	t.Cleanup(func() { resolverDirVPNCore = previous })
	if err := newServiceDaemon(ServiceConfig{}, 501, 20).handleResolverCleanup(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{marked, public} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
	for _, path := range []string{unmarked, link} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s removed: %v", path, err)
		}
	}
}

func TestTCPDumpCommandValidationAndExactPositiveCommand(t *testing.T) {
	// This proves plain and cisco-dump's pktap,all interfaces are accepted while shell-bearing interface/filter values and option injection are refused.
	want := []string{"/usr/sbin/tcpdump", "-i", "lo0", "-s", "0", "-U", "--apple-pcapng", "-Z", "alexis", "-w", "/runtime/capture.pcap", "tcp", "and", "host", "127.0.0.1"}
	got, err := buildTCPDumpCommand("lo0", []string{"tcp", "and", "host", "127.0.0.1"}, true, "alexis", "/runtime/capture.pcap")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("command=%v error=%v want=%v", got, err, want)
	}
	if _, err := buildTCPDumpCommand("pktap,all", []string{"tcp"}, true, "alexis", "/runtime/capture.pcap"); err != nil {
		t.Fatalf("cisco-dump default interface rejected: %v", err)
	}
	for _, tc := range []struct {
		iface  string
		filter []string
	}{{"lo0;id", []string{"tcp"}}, {"lo0", []string{"$HOME"}}, {"lo0", []string{"tcp;id"}}, {"lo0", []string{"-w"}}} {
		if _, err := buildTCPDumpCommand(tc.iface, tc.filter, false, "", "/runtime/capture.pcap"); err == nil {
			t.Fatalf("unsafe command accepted: %#v", tc)
		}
	}
}

func TestTCPDumpRunAsUserIsDerivedFromPeerUID(t *testing.T) {
	// This seam proves the request carries only a boolean and the daemon derives -Z from its authenticated client uid.
	previousLookup := lookupUserVPNCore
	lookupUserVPNCore = func(id string) (*user.User, error) {
		if id != "501" {
			t.Fatalf("lookup id=%q", id)
		}
		return &user.User{Username: "derived-user"}, nil
	}
	t.Cleanup(func() { lookupUserVPNCore = previousLookup })
	account, err := lookupUserVPNCore("501")
	if err != nil || account.Username != "derived-user" {
		t.Fatalf("account=%#v err=%v", account, err)
	}
}

func TestTCPDumpRefusesCallerControlledRunAsIdentity(t *testing.T) {
	// This negative control proves omitting run_as_user cannot produce a root-running capture or accept a caller-supplied -Z value.
	d := newServiceDaemon(ServiceConfig{RuntimeDir: t.TempDir()}, 501, 20)
	if _, _, err := d.handleTCPDumpStart(Request{Interface: "lo0", Filter: []string{"tcp"}}); err == nil || !strings.Contains(err.Error(), "run_as_user=true") {
		t.Fatalf("handleTCPDumpStart() error = %v", err)
	}
}

// Duplicate keys resolve last-wins in the validator; the bytes handed to
// sing-box are the re-encoded tree, so an earlier hidden value never reaches it.
func TestSingBoxConfigValidationWritesCanonicalTree(t *testing.T) {
	raw := `{"log":{"output":"/etc/sudoers.d/x"},"log":{"level":"warn"}}`
	canonical, err := validateSingBoxConfig([]byte(raw))
	if err != nil {
		t.Fatalf("validateSingBoxConfig() error = %v, want the last-wins tree accepted", err)
	}
	if strings.Contains(string(canonical), "output") || strings.Contains(string(canonical), "sudoers") {
		t.Fatalf("canonical config = %s, still carries the shadowed value", canonical)
	}
	if !strings.Contains(string(canonical), `"level":"warn"`) {
		t.Fatalf("canonical config = %s, lost the effective value", canonical)
	}
}

// The renderer expresses TCP by omitting transport, so an explicit tcp
// transport object is outside the renderer-derived schema and is refused,
// while the grpc transport the renderer emits stays accepted.
func TestSingBoxSchemaRefusesUnrenderedTCPTransport(t *testing.T) {
	base := func(transport string) []byte {
		return []byte(`{"outbounds":[{"type":"vless","tag":"proxy","server":"203.0.113.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","transport":` + transport + `}]}`)
	}
	if _, err := validateSingBoxConfig(base(`{"type":"tcp"}`)); err == nil {
		t.Fatal("validateSingBoxConfig(tcp transport) error = nil, want refusal")
	}
	if _, err := validateSingBoxConfig(base(`{"type":"grpc","service_name":"svc"}`)); err != nil {
		t.Fatalf("validateSingBoxConfig(grpc transport) error = %v, want accepted", err)
	}
}
