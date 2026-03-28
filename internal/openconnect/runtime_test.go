package openconnect

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindOpenConnectPIDFromOutput(t *testing.T) {
	pid, err := findOpenConnectPIDFromOutput("123\n456\n")
	if err != nil {
		t.Fatalf("findOpenConnectPIDFromOutput() error = %v", err)
	}
	if pid != 456 {
		t.Fatalf("pid = %d, want 456", pid)
	}
}

func TestResolveCacheDirDefault(t *testing.T) {
	cacheDir := ResolveCacheDir("")
	if cacheDir == "" {
		t.Fatal("ResolveCacheDir(\"\") returned empty path")
	}
	if !strings.Contains(filepath.Clean(cacheDir), filepath.Join("Caches", "openconnect-tun")) &&
		!strings.HasSuffix(filepath.Clean(cacheDir), filepath.Join(".cache", "openconnect-tun")) {
		t.Fatalf("cacheDir = %q, want openconnect-tun cache root", cacheDir)
	}
}

func TestAuthStageWriter_EmitsStageSummariesWithoutFullLogSpam(t *testing.T) {
	var logBuf bytes.Buffer
	var progressBuf bytes.Buffer

	writer := newAuthStageWriter(&logBuf, &progressBuf, false)
	_, _ = writer.Write([]byte("info: full flow: fetching SAML config from vpn-gw2.corp.example/outside...\n"))
	_, _ = writer.Write([]byte("info: page type: lo"))
	_, _ = writer.Write([]byte("gin\ninfo: page type: otp\ninfo: page type: otp\n"))
	writer.Flush()

	progress := progressBuf.String()
	if !strings.Contains(progress, "auth_stage: fetching_saml_config\n") {
		t.Fatalf("progress missing fetching stage: %q", progress)
	}
	if !strings.Contains(progress, "auth_stage: login_page\n") {
		t.Fatalf("progress missing login stage: %q", progress)
	}
	if !strings.Contains(progress, "auth_stage: otp_page_waiting_for_second_factor\n") {
		t.Fatalf("progress missing otp stage: %q", progress)
	}
	if strings.Count(progress, "auth_stage: otp_page_waiting_for_second_factor\n") != 1 {
		t.Fatalf("progress duplicated otp stage: %q", progress)
	}
	if got := logBuf.String(); !strings.Contains(got, "info: page type: otp\ninfo: page type: otp\n") {
		t.Fatalf("raw log output not preserved: %q", got)
	}
}

func TestClassifyAuthStage_UsesTOTPVariantWhenConfigured(t *testing.T) {
	stage := classifyAuthStage("info: page type: otp", true)
	if stage != "otp_page_autofilling_totp" {
		t.Fatalf("stage = %q, want otp_page_autofilling_totp", stage)
	}
}

func TestFindOpenConnectCSDPostScriptPrefersStableHomebrewOptPath(t *testing.T) {
	root := t.TempDir()

	cellarBinary := filepath.Join(root, "Cellar", "openconnect", "9.12_1", "bin", "openconnect")
	if err := os.MkdirAll(filepath.Dir(cellarBinary), 0o755); err != nil {
		t.Fatalf("MkdirAll(cellar) error = %v", err)
	}
	if err := os.WriteFile(cellarBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(cellarBinary) error = %v", err)
	}

	rawBinary := filepath.Join(root, "bin", "openconnect")
	if err := os.MkdirAll(filepath.Dir(rawBinary), 0o755); err != nil {
		t.Fatalf("MkdirAll(bin) error = %v", err)
	}
	if err := os.Symlink(cellarBinary, rawBinary); err != nil {
		t.Fatalf("Symlink(rawBinary) error = %v", err)
	}

	stableScript := filepath.Join(root, "opt", "openconnect", "libexec", "openconnect", "csd-post.sh")
	if err := os.MkdirAll(filepath.Dir(stableScript), 0o755); err != nil {
		t.Fatalf("MkdirAll(stableScript) error = %v", err)
	}
	if err := os.WriteFile(stableScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(stableScript) error = %v", err)
	}

	versionedScript := filepath.Join(root, "Cellar", "openconnect", "9.12_1", "libexec", "openconnect", "csd-post.sh")
	if err := os.MkdirAll(filepath.Dir(versionedScript), 0o755); err != nil {
		t.Fatalf("MkdirAll(versionedScript) error = %v", err)
	}
	if err := os.WriteFile(versionedScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(versionedScript) error = %v", err)
	}

	got := findOpenConnectCSDPostScript(rawBinary)
	if filepath.Clean(got) != filepath.Clean(stableScript) && filepath.Clean(got) != filepath.Clean("/private"+stableScript) {
		t.Fatalf("findOpenConnectCSDPostScript() = %q, want %q", got, stableScript)
	}
}

func TestShellQuoteEscapesSingleQuotes(t *testing.T) {
	got := shellQuote("a'b c")
	want := `'a'"'"'b c'`
	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func TestScriptDiagnosticsWrapperScriptLogsDNSAndResolverState(t *testing.T) {
	script := scriptDiagnosticsWrapperScript("/tmp/openconnect.log", "vpn-slice --domains-vpn-dns corp.example 10.0.0.0/8", nil, "/tmp/pycompat", []string{"10.0.0.0/8"})

	for _, needle := range []string{
		"vpnc_wrapper_env_begin",
		"INTERNAL_IP4_",
		"CISCO_",
		"scutil --dns",
		"netstat -rn -f inet",
		"/etc/resolver",
		`/bin/sh -c "$base_command"`,
		"vpnc_wrapper_base_exit:",
		"vpnc_wrapper_pythonpath:",
		"vpnc_wrapper_route_override: begin",
		"10.0.0.0/8",
		"/tmp/pycompat",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("wrapper script missing %q:\n%s", needle, script)
		}
	}
}

func TestScriptDiagnosticsWrapperScriptIncludesSupplementalDNSShim(t *testing.T) {
	script := scriptDiagnosticsWrapperScript("/tmp/openconnect.log", "/opt/homebrew/etc/vpnc/vpnc-script", &supplementalResolverSpec{
		Label:                "corp-outside",
		SearchDomain:         "region.corp.example",
		Nameservers:          []string{"10.23.16.4", "10.23.0.23"},
		Domains:              []string{"corp.example", "inside.corp.example"},
		SearchCleanupDomains: []string{"corp.example", "inside.corp.example"},
		ProbeHosts:           []string{"gitlab.services.corp.example"},
		RouteOverrides:       []string{"10.0.0.0/8"},
	}, "", []string{"10.0.0.0/8"})

	for _, needle := range []string{
		"vpnc_wrapper_dns_shim: apply",
		"vpnc_wrapper_dns_shim: remove",
		"vpnc_wrapper_dns_shim: restored search.tailscale",
		"vpnc_wrapper_dns_shim: sanitized search.tailscale",
		"capture_default_route",
		"pin_vpn_gateway_route",
		"remove_scoped_default_route",
		"filter_probe_host_addresses",
		"vpnc_wrapper_probe_route_sync_begin:",
		"vpnc_wrapper_probe_route_sync_end:",
		"vpnc_wrapper_probe_route_sync:",
		"vpnc_wrapper_probe_begin:",
		"vpnc_wrapper_probe_dscacheutil_begin",
		"vpnc_wrapper_probe_route_begin",
		"resolve_probe_host_addresses",
		"gitlab.services.corp.example",
		"/etc/resolver/$domain",
		"/etc/resolver/search.tailscale",
		"10.23.16.4",
		"10.23.0.23",
		"corp.example",
		"inside.corp.example",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("wrapper script missing %q:\n%s", needle, script)
		}
	}
}

func TestScriptDiagnosticsWrapperScriptUsesScutilStateForSplitInclude(t *testing.T) {
	script := scriptDiagnosticsWrapperScript("/tmp/openconnect.log", "/Users/alexis/.local/bin/vpn-slice --domains-vpn-dns corp.example 10.0.0.0/8", &supplementalResolverSpec{
		Label:          "split-include",
		SearchDomain:   "corp.example",
		ServiceID:      "01234567-89AB-CDEF-0123-456789ABCDEF",
		UseScutilState: true,
		Nameservers:    []string{"10.23.16.4", "10.23.0.23"},
		Domains:        []string{"corp.example"},
		ProbeHosts:     []string{"gitlab.services.corp.example"},
	}, "/tmp/pycompat", []string{"10.23.16.4/32", "10.0.0.0/8"})

	for _, needle := range []string{
		`[ "$use_scutil_state" = "1" ] && return 0`,
		"vpnc_wrapper_vpngateway_route:",
		"vpnc_wrapper_default_route_remove:",
		"vpnc_wrapper_scutil_state: apply",
		"vpnc_wrapper_scutil_state: remove",
		"vpnc_wrapper_dns_shim: clear split-include resolvers",
		"sync_probe_host_routes apply",
		"State:/Network/Service/$scutil_service_id/DNS",
		"State:/Network/Service/$scutil_service_id/IPv4",
		"SupplementalMatchDomains",
		"d.add SearchDomains *",
		"d.add ServerAddresses *",
		"vpnc_wrapper_route_override_host:",
		`"$cidr" -interface "$TUNDEV"`,
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("wrapper script missing %q:\n%s", needle, script)
		}
	}
}

func TestPrepareVPNslicePythonCompatWritesDistutilsShim(t *testing.T) {
	helperDir := t.TempDir()

	pyCompatDir, err := prepareVPNslicePythonCompat(helperDir, "/Users/alexis/.local/bin/vpn-slice --domains-vpn-dns corp.example 10.0.0.0/8")
	if err != nil {
		t.Fatalf("prepareVPNslicePythonCompat() error = %v", err)
	}
	if pyCompatDir == "" {
		t.Fatal("prepareVPNslicePythonCompat() returned empty path")
	}

	versionPy := filepath.Join(pyCompatDir, "distutils", "version.py")
	data, err := os.ReadFile(versionPy)
	if err != nil {
		t.Fatalf("ReadFile(version.py) error = %v", err)
	}
	if !strings.Contains(string(data), "class LooseVersion") {
		t.Fatalf("version.py missing LooseVersion:\n%s", string(data))
	}
}

func TestSupplementalResolverSpecForConnectOnlyAppliesInFullMode(t *testing.T) {
	full := supplementalResolverSpecForConnect(ConnectModeFull, "vpn-gw2.corp.example/outside", ConnectOptions{})
	if full == nil {
		t.Fatal("full mode returned nil supplemental resolver spec")
	}
	if full.Label != "corp-outside" {
		t.Fatalf("full.Label = %q, want corp-outside", full.Label)
	}

	split := supplementalResolverSpecForConnect(ConnectModeSplitInclude, "vpn-gw2.corp.example/outside", ConnectOptions{
		IncludeRoutes:  []string{"10.0.0.0/8"},
		VPNDomains:     []string{"corp.example"},
		VPNNameservers: []string{"10.23.16.4", "10.23.0.23"},
	})
	if split == nil {
		t.Fatal("split mode returned nil supplemental resolver spec")
	}
	if split.Label != "split-include" {
		t.Fatalf("split.Label = %q, want split-include", split.Label)
	}
	if !containsString(split.Nameservers, "10.23.16.4") {
		t.Fatalf("split.Nameservers = %#v, want 10.23.16.4", split.Nameservers)
	}
	if !containsString(split.Domains, "corp.example") {
		t.Fatalf("split.Domains = %#v, want corp.example", split.Domains)
	}
	for _, domain := range []string{"inside.corp.example", "region.corp.example", "branch.example"} {
		if !containsString(split.Domains, domain) {
			t.Fatalf("split.Domains = %#v, want %q", split.Domains, domain)
		}
	}
	if split.SearchDomain != "region.corp.example" {
		t.Fatalf("split.SearchDomain = %q, want region.corp.example", split.SearchDomain)
	}
	if !split.UseScutilState {
		t.Fatal("split.UseScutilState = false, want true")
	}
	if !split.ManageSearchResolver {
		t.Fatal("split.ManageSearchResolver = false, want true")
	}
	if !containsString(split.RouteOverrides, "10.0.0.0/8") {
		t.Fatalf("split.RouteOverrides = %#v, want 10.0.0.0/8", split.RouteOverrides)
	}
	if !containsString(split.RouteOverrides, "10.23.16.4/32") || !containsString(split.RouteOverrides, "10.23.0.23/32") {
		t.Fatalf("split.RouteOverrides = %#v, want DNS host routes", split.RouteOverrides)
	}

	splitNoNameservers := supplementalResolverSpecForConnect(ConnectModeSplitInclude, "vpn-gw2.corp.example/outside", ConnectOptions{
		VPNDomains: []string{"corp.example"},
	})
	if splitNoNameservers == nil {
		t.Fatal("splitNoNameservers = nil, want corp-outside fallback spec")
	}
	if !containsString(splitNoNameservers.Nameservers, "10.23.16.4") {
		t.Fatalf("splitNoNameservers.Nameservers = %#v, want 10.23.16.4", splitNoNameservers.Nameservers)
	}
	if splitNoNameservers.SearchDomain != "region.corp.example" {
		t.Fatalf("splitNoNameservers.SearchDomain = %q, want region.corp.example", splitNoNameservers.SearchDomain)
	}

	unsupported := supplementalResolverSpecForConnect("weird", "vpn-gw2.corp.example/outside", ConnectOptions{})
	if unsupported != nil {
		t.Fatalf("unsupported = %#v, want nil", unsupported)
	}
}

func TestSupplementalResolverServiceIDStableAndUUIDShaped(t *testing.T) {
	gotA := supplementalResolverServiceID("20260327T133554Z", "split-include")
	gotB := supplementalResolverServiceID("20260327T133554Z", "split-include")
	gotC := supplementalResolverServiceID("20260327T133555Z", "split-include")

	if gotA != gotB {
		t.Fatalf("service id unstable: %q vs %q", gotA, gotB)
	}
	if gotA == gotC {
		t.Fatalf("service id should change across sessions: %q", gotA)
	}
	if len(gotA) != 36 || strings.Count(gotA, "-") != 4 {
		t.Fatalf("service id = %q, want UUID-like shape", gotA)
	}
}

func TestAppendOpenConnectClientIdentityArgsIncludesCiscoLikeFlags(t *testing.T) {
	args := appendOpenConnectClientIdentityArgs([]string{"--protocol=anyconnect"}, aggregateAuthClientProfile{
		Version:      "4.10.07061",
		DeviceID:     "mac-intel",
		ComputerName: "Alexis M1 Max",
	}, "Alexis-M1-Max")

	for _, needle := range []string{
		"--useragent=AnyConnect",
		"--os=mac-intel",
		"--version-string",
		"4.10.07061",
		"--local-hostname",
		"Alexis-M1-Max",
	} {
		if !containsString(args, needle) {
			t.Fatalf("args = %#v, want %q", args, needle)
		}
	}
}

func TestPrepareOpenConnectAuthHelpersCreatesBrowserAndCSDWrappers(t *testing.T) {
	root := t.TempDir()

	cellarBinary := filepath.Join(root, "Cellar", "openconnect", "9.12_1", "bin", "openconnect")
	if err := os.MkdirAll(filepath.Dir(cellarBinary), 0o755); err != nil {
		t.Fatalf("MkdirAll(cellar) error = %v", err)
	}
	if err := os.WriteFile(cellarBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(cellarBinary) error = %v", err)
	}

	rawBinary := filepath.Join(root, "bin", "openconnect")
	if err := os.MkdirAll(filepath.Dir(rawBinary), 0o755); err != nil {
		t.Fatalf("MkdirAll(bin) error = %v", err)
	}
	if err := os.Symlink(cellarBinary, rawBinary); err != nil {
		t.Fatalf("Symlink(rawBinary) error = %v", err)
	}

	stableScript := filepath.Join(root, "opt", "openconnect", "libexec", "openconnect", "csd-post.sh")
	if err := os.MkdirAll(filepath.Dir(stableScript), 0o755); err != nil {
		t.Fatalf("MkdirAll(stableScript) error = %v", err)
	}
	if err := os.WriteFile(stableScript, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(stableScript) error = %v", err)
	}

	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(toolDir) error = %v", err)
	}
	writeTool := func(name string) string {
		path := filepath.Join(toolDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
		return path
	}
	vpnAuthPath := writeTool("vpn-auth")
	pythonPath := writeTool("python3")
	curlPath := writeTool("curl")

	prevLookPath := execLookPathOpenConnect
	execLookPathOpenConnect = func(name string) (string, error) {
		switch name {
		case "vpn-auth":
			return vpnAuthPath, nil
		case "python3":
			return pythonPath, nil
		case "curl":
			return curlPath, nil
		default:
			return prevLookPath(name)
		}
	}
	defer func() {
		execLookPathOpenConnect = prevLookPath
	}()

	spec, err := prepareOpenConnectAuthHelpers(rawBinary, "vpn-gw2.corp.example/outside", ConnectOptions{
		Auth: "saml",
		Credentials: Credentials{
			Username:   "alice",
			Password:   "secret",
			TOTPSecret: "totp",
		},
	}, io.Discard)
	if err != nil {
		t.Fatalf("prepareOpenConnectAuthHelpers() error = %v", err)
	}
	if spec.Cleanup == nil {
		t.Fatal("Cleanup is nil")
	}
	defer spec.Cleanup()

	if !containsString(spec.Args, "--external-browser") {
		t.Fatalf("Args missing --external-browser: %v", spec.Args)
	}
	if !containsString(spec.Args, "--csd-wrapper") {
		t.Fatalf("Args missing --csd-wrapper: %v", spec.Args)
	}

	env := envSliceToMap(spec.Env)
	if env["OPENCONNECT_TUN_BROWSER_MODE"] != "vpn_auth" {
		t.Fatalf("OPENCONNECT_TUN_BROWSER_MODE = %q, want vpn_auth", env["OPENCONNECT_TUN_BROWSER_MODE"])
	}
	if env["OPENCONNECT_TUN_VPN_AUTH_BIN"] != vpnAuthPath {
		t.Fatalf("OPENCONNECT_TUN_VPN_AUTH_BIN = %q, want %q", env["OPENCONNECT_TUN_VPN_AUTH_BIN"], vpnAuthPath)
	}
	if env["OPENCONNECT_TUN_JSON_PYTHON"] != pythonPath {
		t.Fatalf("OPENCONNECT_TUN_JSON_PYTHON = %q, want %q", env["OPENCONNECT_TUN_JSON_PYTHON"], pythonPath)
	}
	if env["OPENCONNECT_TUN_CURL_BIN"] != curlPath {
		t.Fatalf("OPENCONNECT_TUN_CURL_BIN = %q, want %q", env["OPENCONNECT_TUN_CURL_BIN"], curlPath)
	}
	if filepath.Clean(env["OPENCONNECT_TUN_CSD_POST_BIN"]) != filepath.Clean(stableScript) &&
		filepath.Clean(env["OPENCONNECT_TUN_CSD_POST_BIN"]) != filepath.Clean("/private"+stableScript) {
		t.Fatalf("OPENCONNECT_TUN_CSD_POST_BIN = %q, want %q", env["OPENCONNECT_TUN_CSD_POST_BIN"], stableScript)
	}
	if env["OPENCONNECT_TUN_VPN_AUTH_USERNAME"] != "alice" || env["OPENCONNECT_TUN_VPN_AUTH_PASSWORD"] != "secret" || env["OPENCONNECT_TUN_VPN_AUTH_TOTP_SECRET"] != "totp" {
		t.Fatalf("browser wrapper credential env missing: %+v", env)
	}
}

func TestBuildSAMLAuthReplyXMLUsesOpaquePlaceholdersAndToken(t *testing.T) {
	xml := buildSAMLAuthReplyXML(&samlAuthState{
		OpaqueXML:     "<opaque is-for=\"sg\"><auth-method>single-sign-on-v2</auth-method><group-alias>outside</group-alias></opaque>",
		AuthMethod:    "single-sign-on-v2",
		HostScanToken: "HOSTSCAN123",
		ClientProfile: aggregateAuthClientProfile{
			Version:         "4.10.07061",
			DeviceID:        "mac-intel",
			ComputerName:    "MacBook Pro",
			DeviceType:      "MacBookPro18,2",
			PlatformVersion: "26.3.1",
			UniqueID:        "LEGACY123",
			UniqueIDGlobal:  "GLOBAL123",
		},
	}, "ABC123TOKEN")

	if !strings.Contains(xml, "<version who=\"vpn\">4.10.07061</version>") {
		t.Fatalf("reply XML missing AnyConnect version: %q", xml)
	}
	if !strings.Contains(xml, "<device-id computer-name=\"MacBook Pro\" device-type=\"MacBookPro18,2\" platform-version=\"26.3.1\" unique-id=\"LEGACY123\" unique-id-global=\"GLOBAL123\">mac-intel</device-id>") {
		t.Fatalf("reply XML missing rich device-id: %q", xml)
	}
	if !strings.Contains(xml, "<group-select>outside</group-select>") {
		t.Fatalf("reply XML missing group-select: %q", xml)
	}
	if !strings.Contains(xml, "<host-scan-token>HOSTSCAN123</host-scan-token>") {
		t.Fatalf("reply XML missing host-scan-token: %q", xml)
	}
	if !strings.Contains(xml, "<opaque is-for=\"sg\"><auth-method>single-sign-on-v2</auth-method><group-alias>outside</group-alias></opaque>") {
		t.Fatalf("reply XML missing opaque block: %q", xml)
	}
	if !strings.Contains(xml, "<sso-token>ABC123TOKEN</sso-token>") {
		t.Fatalf("reply XML missing SSO token: %q", xml)
	}
	if !strings.Contains(xml, "<session-token/><session-id/>") {
		t.Fatalf("reply XML missing empty session placeholders: %q", xml)
	}
}

func TestBuildSAMLAuthReplyXMLVariantsIncludeCapabilitiesVariants(t *testing.T) {
	variants := buildSAMLAuthReplyXMLVariants(&samlAuthState{
		OpaqueXML:     "<opaque is-for=\"sg\"><auth-method>single-sign-on-v2</auth-method><group-alias>outside</group-alias></opaque>",
		AuthMethod:    "single-sign-on-v2",
		HostScanToken: "HOSTSCAN123",
		ClientProfile: aggregateAuthClientProfile{
			Version:      "4.10.07061",
			DeviceID:     "mac-intel",
			MacAddresses: []string{"AA:BB:CC:DD:EE:FF"},
			AuthMethods: []string{
				"multiple-cert",
				"single-sign-on",
				"single-sign-on-v2",
			},
		},
	}, "ABC123TOKEN")

	if len(variants) < 2 {
		t.Fatalf("variants = %+v, want multiple reply layouts", variants)
	}

	var sawCapabilitiesAndPlaceholders bool
	var sawCapabilitiesOnly bool
	var sawFullProfileAndPlaceholders bool
	var sawFullProfileOnly bool
	for _, variant := range variants {
		switch variant.Name {
		case "capabilities_and_placeholders":
			sawCapabilitiesAndPlaceholders = strings.Contains(variant.XML, "<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>") &&
				strings.Contains(variant.XML, "<group-select>outside</group-select>") &&
				strings.Contains(variant.XML, "<host-scan-token>HOSTSCAN123</host-scan-token>") &&
				strings.Contains(variant.XML, "<session-token/><session-id/>")
		case "capabilities_only":
			sawCapabilitiesOnly = strings.Contains(variant.XML, "<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>") &&
				strings.Contains(variant.XML, "<group-select>outside</group-select>") &&
				strings.Contains(variant.XML, "<host-scan-token>HOSTSCAN123</host-scan-token>") &&
				!strings.Contains(variant.XML, "<session-token/><session-id/>")
		case "full_profile_and_placeholders":
			sawFullProfileAndPlaceholders = strings.Contains(variant.XML, "<mac-address-list><mac-address>AA:BB:CC:DD:EE:FF</mac-address></mac-address-list>") &&
				strings.Contains(variant.XML, "<auth-method>multiple-cert</auth-method>") &&
				strings.Contains(variant.XML, "<auth-method>single-sign-on-v2</auth-method>") &&
				strings.Contains(variant.XML, "<group-select>outside</group-select>") &&
				strings.Contains(variant.XML, "<host-scan-token>HOSTSCAN123</host-scan-token>") &&
				strings.Contains(variant.XML, "<session-token/><session-id/>")
		case "full_profile_only":
			sawFullProfileOnly = strings.Contains(variant.XML, "<mac-address-list><mac-address>AA:BB:CC:DD:EE:FF</mac-address></mac-address-list>") &&
				strings.Contains(variant.XML, "<auth-method>multiple-cert</auth-method>") &&
				strings.Contains(variant.XML, "<auth-method>single-sign-on-v2</auth-method>") &&
				strings.Contains(variant.XML, "<group-select>outside</group-select>") &&
				strings.Contains(variant.XML, "<host-scan-token>HOSTSCAN123</host-scan-token>") &&
				!strings.Contains(variant.XML, "<session-token/><session-id/>")
		}
	}
	if !sawCapabilitiesAndPlaceholders || !sawCapabilitiesOnly || !sawFullProfileAndPlaceholders || !sawFullProfileOnly {
		t.Fatalf("variants missing expected capability layouts: %+v", variants)
	}
}

func TestCompleteSAMLAuthPrefersContinuationOverFollowup(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	var serverURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("io.ReadAll(request body) error = %v", err)
		}
		body := string(bodyBytes)

		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		switch {
		case strings.Contains(body, "<mac-address-list>"):
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>TG-Corp-SMS-ISSO-OUTSIDE</tunnel-group><auth-method>single-sign-on-v2</auth-method><config-hash>1758892975877</config-hash></opaque>
</config-auth>`)
		case strings.Contains(body, "<capabilities><auth-method>single-sign-on-v2</auth-method></capabilities>") &&
			strings.Contains(body, "<session-token/><session-id/>"):
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>TG-Corp-SMS-ISSO-OUTSIDE</tunnel-group><auth-method>single-sign-on-v2</auth-method><config-hash>1758892975877</config-hash></opaque>
<auth id="main"><sso-v2-login>`+serverURL+`/sso</sso-v2-login></auth>
</config-auth>`)
		default:
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="complete" aggregate-auth-version="2">
<error id="13" param1="" param2="">Unable to complete connection: Cisco Secure Desktop not installed on the client</error>
</config-auth>`)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	state := &samlAuthState{
		BaseHost:      strings.TrimPrefix(server.URL, "http://"),
		RequestURL:    server.URL,
		ReplyURL:      server.URL + "/outside",
		GroupAccess:   "vpn-gw2.corp.example/outside",
		HostScanToken: "HOSTSCAN123",
		OpaqueXML:     "<opaque is-for=\"sg\"><tunnel-group>TG-Corp-SMS-ISSO-OUTSIDE</tunnel-group><auth-method>single-sign-on-v2</auth-method><config-hash>1758892975877</config-hash></opaque>",
		AuthMethod:    "single-sign-on-v2",
		ClientProfile: aggregateAuthClientProfile{
			Version:      "4.10.07061",
			DeviceID:     "mac-intel",
			MacAddresses: []string{"AA:BB:CC:DD:EE:FF"},
			AuthMethods: []string{
				"multiple-cert",
				"single-sign-on",
				"single-sign-on-v2",
			},
		},
		CookieJar: jar,
	}

	_, err = completeSAMLAuth(state, "vpn-gw2.corp.example/outside", "ABC123TOKEN", io.Discard)
	if err == nil {
		t.Fatal("completeSAMLAuth() error = nil, want continuation auth-request")
	}

	var continuation *samlAuthReplyContinue
	if !errors.As(err, &continuation) || continuation == nil || continuation.State == nil {
		t.Fatalf("completeSAMLAuth() error = %v, want continuation auth-request", err)
	}
	if got := continuation.State.SSOLoginURL; got != "" {
		t.Fatalf("continuation.State.SSOLoginURL = %q, want empty", got)
	}
	if got := continuation.State.ReplyURL; got != "https://vpn-gw2.corp.example/outside" {
		t.Fatalf("continuation.State.ReplyURL = %q, want normalized group URL", got)
	}
}

func TestParseSAMLAuthStateFromResponse(t *testing.T) {
	response := `<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg"><tunnel-group>TG-Corp</tunnel-group><auth-method>single-sign-on-v2</auth-method><group-alias>outside</group-alias></opaque>
<auth id="main"><sso-v2-login>https://vpn-gw2.corp.example/+CSCOE+/saml/sp/login?tgname=TG</sso-v2-login></auth>
<host-scan-ticket>TICKET123</host-scan-ticket>
<host-scan-token>TOKEN123</host-scan-token>
<host-scan-wait-uri>/+CSCOE+/sdesktop/wait.html</host-scan-wait-uri>
</config-auth>`

	state, err := parseSAMLAuthStateFromResponse(response, "https://vpn-gw2.corp.example/", "vpn-gw2.corp.example/outside", aggregateAuthClientProfile{
		Version:  "4.10.07061",
		DeviceID: "mac-intel",
	}, nil)
	if err != nil {
		t.Fatalf("parseSAMLAuthStateFromResponse() error = %v", err)
	}
	if state.SSOLoginURL != "https://vpn-gw2.corp.example/+CSCOE+/saml/sp/login?tgname=TG" {
		t.Fatalf("SSOLoginURL = %q", state.SSOLoginURL)
	}
	if state.ReplyURL != "https://vpn-gw2.corp.example/outside" {
		t.Fatalf("ReplyURL = %q", state.ReplyURL)
	}
	if state.RequestURL != "https://vpn-gw2.corp.example/" {
		t.Fatalf("RequestURL = %q", state.RequestURL)
	}
	if state.HostScanTicket != "TICKET123" || state.HostScanToken != "TOKEN123" {
		t.Fatalf("hostscan = %+v", state)
	}
}

func TestBuildAggregateAuthInitXMLUsesRichAnyConnectIdentity(t *testing.T) {
	xml := buildAggregateAuthInitXML("vpn-gw2.corp.example/outside", aggregateAuthClientProfile{
		Version:         "4.10.07061",
		DeviceID:        "mac-intel",
		ComputerName:    "MacBook Pro",
		DeviceType:      "MacBookPro18,2",
		PlatformVersion: "26.3.1",
		UniqueID:        "LEGACY123",
		UniqueIDGlobal:  "GLOBAL123",
		MacAddresses:    []string{"F4:D4:88:6C:73:ED", "22:64:81:21:99:98"},
		AuthMethods: []string{
			"multiple-cert",
			"single-sign-on",
			"single-sign-on-v2",
			"single-sign-on-external-browser",
		},
	})

	if !strings.Contains(xml, "<version who=\"vpn\">4.10.07061</version>") {
		t.Fatalf("init XML missing AnyConnect version: %q", xml)
	}
	if !strings.Contains(xml, "<device-id computer-name=\"MacBook Pro\" device-type=\"MacBookPro18,2\" platform-version=\"26.3.1\" unique-id=\"LEGACY123\" unique-id-global=\"GLOBAL123\">mac-intel</device-id>") {
		t.Fatalf("init XML missing rich device-id: %q", xml)
	}
	if !strings.Contains(xml, "<mac-address-list><mac-address>F4:D4:88:6C:73:ED</mac-address><mac-address>22:64:81:21:99:98</mac-address></mac-address-list>") {
		t.Fatalf("init XML missing mac-address-list: %q", xml)
	}
	if !strings.Contains(xml, "<capabilities><auth-method>multiple-cert</auth-method><auth-method>single-sign-on</auth-method><auth-method>single-sign-on-v2</auth-method><auth-method>single-sign-on-external-browser</auth-method></capabilities>") {
		t.Fatalf("init XML missing AnyConnect capabilities: %q", xml)
	}
}

func TestStoreSAMLHostScanCookieAddsSdesktopCookie(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	state := &samlAuthState{
		HostScanToken: "HOSTSCAN123",
		CookieJar:     jar,
	}
	rawURL := "https://vpn-gw2.corp.example/outside"
	if err := storeSAMLHostScanCookie(state, rawURL); err != nil {
		t.Fatalf("storeSAMLHostScanCookie() error = %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	cookies := jar.Cookies(parsed)
	for _, cookie := range cookies {
		if cookie.Name == "sdesktop" && cookie.Value == "HOSTSCAN123" {
			return
		}
	}
	t.Fatalf("sdesktop cookie not stored, got %+v", cookies)
}

func TestStoreSAMLHostScanCookieOverridesExistingSdesktopCookie(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	rawURL := "https://vpn-gw2.corp.example/outside"
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	jar.SetCookies(parsed, []*http.Cookie{{
		Name:  "sdesktop",
		Value: "OLDTOKEN",
		Path:  "/",
	}})

	state := &samlAuthState{
		HostScanToken: "NEWTOKEN",
		CookieJar:     jar,
	}
	if err := storeSAMLHostScanCookie(state, rawURL); err != nil {
		t.Fatalf("storeSAMLHostScanCookie() error = %v", err)
	}

	cookies := jar.Cookies(parsed)
	for _, cookie := range cookies {
		if cookie.Name == "sdesktop" {
			if cookie.Value != "NEWTOKEN" {
				t.Fatalf("sdesktop cookie value = %q, want NEWTOKEN", cookie.Value)
			}
			return
		}
	}
	t.Fatalf("sdesktop cookie missing after override, got %+v", cookies)
}

func TestStoreSAMLCookieAddsAcSamlv2TokenAndDescribesJar(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	state := &samlAuthState{CookieJar: jar}
	rawURL := "https://vpn-gw2.corp.example/outside"
	if err := storeSAMLCookie(state, rawURL, "acSamlv2Token", "SAML123"); err != nil {
		t.Fatalf("storeSAMLCookie() error = %v", err)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	cookies := jar.Cookies(parsed)
	var found bool
	for _, cookie := range cookies {
		if cookie.Name == "acSamlv2Token" && cookie.Value == "SAML123" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("acSamlv2Token cookie not stored, got %+v", cookies)
	}
	summary := describeCookiesForURL(jar, rawURL)
	if !strings.Contains(summary, "acSamlv2Token=7") {
		t.Fatalf("describeCookiesForURL() = %q, want acSamlv2Token length", summary)
	}
}

func TestStoreASAWebViewCookiesImportsOnlyASAHostCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	state := &samlAuthState{
		ReplyURL:  "https://vpn-gw2.corp.example/outside",
		CookieJar: jar,
	}
	result := &vpnAuthResult{
		Cookies: []vpnAuthCookie{
			{Name: "CSRFtoken", Value: "abc123", Domain: "vpn-gw2.corp.example", Path: "/"},
			{Name: "webvpnlogin", Value: "1", Domain: "vpn-gw2.corp.example", Path: "/+webvpn+"},
			{Name: "KEYCLOAK_SESSION", Value: "secret", Domain: "sso.corp.example", Path: "/auth/realms/corp/"},
		},
	}

	if err := storeASAWebViewCookies(state, result, io.Discard); err != nil {
		t.Fatalf("storeASAWebViewCookies() error = %v", err)
	}

	parsed, err := url.Parse(state.ReplyURL)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	cookies := jar.Cookies(parsed)
	if len(cookies) != 1 || cookies[0].Name != "CSRFtoken" {
		t.Fatalf("imported cookies at reply URL = %+v, want CSRFtoken only", cookies)
	}
	if summary := describeCookiesForURL(jar, state.ReplyURL); !strings.Contains(summary, "CSRFtoken=6") {
		t.Fatalf("describeCookiesForURL() = %q, want CSRFtoken on reply URL", summary)
	}
	webvpnURL, err := url.Parse("https://vpn-gw2.corp.example/+webvpn+/index.html")
	if err != nil {
		t.Fatalf("url.Parse(webvpnURL) error = %v", err)
	}
	webvpnCookies := jar.Cookies(webvpnURL)
	var sawWebVPNLogin bool
	for _, cookie := range webvpnCookies {
		if cookie.Name == "webvpnlogin" && cookie.Value == "1" {
			sawWebVPNLogin = true
			break
		}
	}
	if !sawWebVPNLogin {
		t.Fatalf("webvpn path cookies = %+v, want webvpnlogin", webvpnCookies)
	}
	for _, cookie := range cookies {
		if cookie.Name == "KEYCLOAK_SESSION" {
			t.Fatalf("unexpected foreign-domain cookie imported: %+v", cookies)
		}
	}
}

func TestMarshalBrowserPresetCookiesIncludesMinimalASAContextOnly(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	replyURL := "https://vpn-gw2.corp.example/outside"
	replyParsed, err := url.Parse(replyURL)
	if err != nil {
		t.Fatalf("url.Parse(replyURL) error = %v", err)
	}
	jar.SetCookies(replyParsed, []*http.Cookie{{
		Name:  "sdesktop",
		Value: "stub-token",
		Path:  "/",
	}, {
		Name:  "CSRFtoken",
		Value: "abc123",
		Path:  "/",
	}, {
		Name:  "acSamlv2Token",
		Value: "trigger-me-not",
		Path:  "/",
	}})

	webvpnURL, err := url.Parse("https://vpn-gw2.corp.example/+webvpn+/index.html")
	if err != nil {
		t.Fatalf("url.Parse(webvpnURL) error = %v", err)
	}
	jar.SetCookies(webvpnURL, []*http.Cookie{{
		Name:  "webvpnlogin",
		Value: "1",
		Path:  "/+webvpn+",
	}})

	state := &samlAuthState{
		BaseHost:   "vpn-gw2.corp.example",
		ReplyURL:   replyURL,
		RequestURL: "https://vpn-gw2.corp.example/",
		CookieJar:  jar,
	}
	jsonString, summary, err := marshalBrowserPresetCookies(state, nil)
	if err != nil {
		t.Fatalf("marshalBrowserPresetCookies() error = %v", err)
	}
	if !strings.Contains(summary, "sdesktop") || !strings.Contains(summary, "webvpnlogin") {
		t.Fatalf("summary = %q, want sdesktop and webvpnlogin", summary)
	}
	if strings.Contains(summary, "CSRFtoken") || strings.Contains(summary, "acSamlv2Token") {
		t.Fatalf("summary = %q, want only minimal ASA context", summary)
	}
	if !strings.Contains(jsonString, "\"name\":\"sdesktop\"") || !strings.Contains(jsonString, "\"name\":\"webvpnlogin\"") {
		t.Fatalf("jsonString = %q, want sdesktop and webvpn cookies", jsonString)
	}
	if strings.Contains(jsonString, "\"name\":\"CSRFtoken\"") || strings.Contains(jsonString, "\"name\":\"acSamlv2Token\"") {
		t.Fatalf("jsonString = %q, want only minimal ASA context", jsonString)
	}
}

func TestMarshalBrowserPresetCookiesIncludesOnlyForeignDomainBrowserCookies(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	state := &samlAuthState{
		BaseHost:   "vpn-gw2.corp.example",
		ReplyURL:   "https://vpn-gw2.corp.example/outside",
		RequestURL: "https://vpn-gw2.corp.example/",
		CookieJar:  jar,
	}
	browserAuth := &vpnAuthResult{
		Cookies: []vpnAuthCookie{
			{Name: "AUTH_SESSION_ID", Value: "session", Domain: "sso.corp.example", Path: "/auth/realms/corp/"},
			{Name: "KEYCLOAK_SESSION", Value: "kc", Domain: "sso.corp.example", Path: "/auth/realms/corp/"},
			{Name: "CSRFtoken", Value: "csrf", Domain: "vpn-gw2.corp.example", Path: "/"},
			{Name: "acSamlv2Token", Value: "trigger", Domain: "vpn-gw2.corp.example", Path: "/"},
		},
	}

	jsonString, summary, err := marshalBrowserPresetCookies(state, browserAuth)
	if err != nil {
		t.Fatalf("marshalBrowserPresetCookies() error = %v", err)
	}
	if !strings.Contains(summary, "AUTH_SESSION_ID") || !strings.Contains(summary, "KEYCLOAK_SESSION") {
		t.Fatalf("summary = %q, want foreign-domain cookies", summary)
	}
	if strings.Contains(summary, "CSRFtoken") || strings.Contains(summary, "acSamlv2Token") {
		t.Fatalf("summary = %q, want ASA-host browser cookies skipped", summary)
	}
	if !strings.Contains(jsonString, "\"domain\":\"sso.corp.example\"") {
		t.Fatalf("jsonString = %q, want sso.corp.example cookies", jsonString)
	}
	if strings.Contains(jsonString, "\"domain\":\"vpn-gw2.corp.example\"") {
		t.Fatalf("jsonString = %q, want ASA-host browser cookies skipped", jsonString)
	}
}

func TestDeriveTunnelGroupCookiePrefersGroupAliasThenPath(t *testing.T) {
	state := &samlAuthState{
		OpaqueXML:   "<opaque><group-alias>outside</group-alias><tunnel-group>TG-Corp</tunnel-group></opaque>",
		GroupAccess: "vpn-gw2.corp.example/outside",
	}
	if got := deriveTunnelGroupCookie(state); got != "outside" {
		t.Fatalf("deriveTunnelGroupCookie() = %q, want outside", got)
	}

	state = &samlAuthState{
		OpaqueXML:   "<opaque><tunnel-group>TG-Corp</tunnel-group></opaque>",
		GroupAccess: "vpn-gw2.corp.example/outside",
	}
	if got := deriveTunnelGroupCookie(state); got != "outside" {
		t.Fatalf("deriveTunnelGroupCookie() path fallback = %q, want outside", got)
	}
}

func TestWaitForHostScanFollowsRedirectChain(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New() error = %v", err)
	}

	var sawSdesktop bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/wait":
			if got := r.Header.Get("X-Aggregate-Auth"); got != "1" {
				t.Fatalf("initial wait request missing aggregate auth header, got %q", got)
			}
			http.SetCookie(w, &http.Cookie{Name: "hsdone", Value: "1", Path: "/"})
			http.Redirect(w, r, "/complete", http.StatusFound)
		case "/complete":
			if got := r.Header.Get("X-Aggregate-Auth"); got != "" {
				t.Fatalf("redirect request should not send aggregate auth header, got %q", got)
			}
			for _, cookie := range r.Cookies() {
				if cookie.Name == "sdesktop" && cookie.Value == "HOSTSCAN123" {
					sawSdesktop = true
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	prevClientFactory := newSAMLHTTPClient
	newSAMLHTTPClient = func(jar http.CookieJar, checkRedirect func(*http.Request, []*http.Request) error) *http.Client {
		client := server.Client()
		client.Timeout = authTimeout
		client.Jar = jar
		client.CheckRedirect = checkRedirect
		return client
	}
	defer func() {
		newSAMLHTTPClient = prevClientFactory
	}()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(server.URL) error = %v", err)
	}

	state := &samlAuthState{
		BaseHost:        parsed.Host,
		HostScanWaitURI: "/wait",
		HostScanToken:   "HOSTSCAN123",
		CookieJar:       jar,
	}

	var logBuf bytes.Buffer
	if err := waitForHostScan(state, &logBuf); err != nil {
		t.Fatalf("waitForHostScan() error = %v", err)
	}
	if !sawSdesktop {
		t.Fatalf("redirect target did not receive sdesktop cookie; log = %q", logBuf.String())
	}
	if got := logBuf.String(); !strings.Contains(got, "hostscan_wait_location: /complete\n") {
		t.Fatalf("wait log missing redirect location: %q", got)
	}
	if strings.Count(logBuf.String(), "hostscan_wait_status: ") != 2 {
		t.Fatalf("wait log should contain two statuses, got %q", logBuf.String())
	}
	if state.RequestURL != server.URL+"/complete" {
		t.Fatalf("RequestURL = %q, want %q", state.RequestURL, server.URL+"/complete")
	}
}

func TestExtractLastXMLTagReturnsTrailingMatch(t *testing.T) {
	body := "<opaque><auth-method>single-sign-on-v2</auth-method><auth-method>single-sign-on-external-browser</auth-method></opaque>"
	if got := extractLastXMLTag(body, "auth-method"); got != "single-sign-on-external-browser" {
		t.Fatalf("extractLastXMLTag() = %q, want %q", got, "single-sign-on-external-browser")
	}
}

func TestHasPendingHostScanChallenge(t *testing.T) {
	if hasPendingHostScanChallenge(nil, nil) {
		t.Fatal("nil state reported pending hostscan")
	}

	if hasPendingHostScanChallenge(&samlAuthState{}, nil) {
		t.Fatal("empty state reported pending hostscan")
	}

	state := &samlAuthState{
		HostScanTicket: "ticket-1",
		HostScanToken:  "token-1",
	}
	if !hasPendingHostScanChallenge(state, map[string]struct{}{}) {
		t.Fatal("unseen hostscan token should be pending")
	}
	if hasPendingHostScanChallenge(state, map[string]struct{}{"token-1": {}}) {
		t.Fatal("seen hostscan token should not be pending")
	}
}

func TestShouldPreferSSOAfterHostScan(t *testing.T) {
	state := &samlAuthState{
		SSOLoginURL:    "https://vpn-gw2.corp.example/+CSCOE+/saml/sp/login?tgname=TG",
		HostScanTicket: "ticket-2",
		HostScanToken:  "token-2",
		RequestURL:     "https://vpn-gw2.corp.example/",
		ReplyURL:       "https://vpn-gw2.corp.example/outside",
	}
	if !shouldPreferSSOAfterHostScan("vpn-gw2.corp.example/outside", map[string]struct{}{"token-1": {}}, state) {
		t.Fatal("shouldPreferSSOAfterHostScan() = false, want true")
	}
	if shouldPreferSSOAfterHostScan("vpn-gw2.corp.example/outside", nil, state) {
		t.Fatal("shouldPreferSSOAfterHostScan() should require prior successful hostscan")
	}
	state.RequestURL = "https://vpn-gw2.corp.example/outside"
	if shouldPreferSSOAfterHostScan("vpn-gw2.corp.example/outside", map[string]struct{}{"token-1": {}}, state) {
		t.Fatal("shouldPreferSSOAfterHostScan() should stay false on original reply URL")
	}
}

func TestParseAnyConnectUDIDOutput(t *testing.T) {
	if got := parseAnyConnectUDIDOutput("\nUDID : 960FC5033699859E0F30FBEFAA6AC9C2832A0596\n"); got != "960FC5033699859E0F30FBEFAA6AC9C2832A0596" {
		t.Fatalf("parseAnyConnectUDIDOutput() = %q", got)
	}
	if got := parseAnyConnectUDIDOutput("noise"); got != "" {
		t.Fatalf("parseAnyConnectUDIDOutput() = %q, want empty", got)
	}
}

func TestParsePlatformUUIDOutput(t *testing.T) {
	out := "      \"IOPlatformUUID\" = \"B02FA318-0500-5E6F-9E40-83657D5A2237\"\n"
	if got := parsePlatformUUIDOutput(out); got != "B02FA318-0500-5E6F-9E40-83657D5A2237" {
		t.Fatalf("parsePlatformUUIDOutput() = %q", got)
	}
}

func TestXMLStarletShimScriptSupportsCSDQueries(t *testing.T) {
	helperDir := t.TempDir()
	shimPath := filepath.Join(helperDir, "xmlstarlet")
	if err := writeExecutableFile(shimPath, xmlstarletShimScript()); err != nil {
		t.Fatalf("writeExecutableFile(xmlstarlet) error = %v", err)
	}

	versionOut, err := exec.Command(shimPath, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("xmlstarlet --version error = %v, output = %s", err, versionOut)
	}
	if !strings.Contains(string(versionOut), "xmlstarlet shim") {
		t.Fatalf("xmlstarlet --version output = %q", string(versionOut))
	}

	tokenCmd := exec.Command(shimPath, "sel", "-t", "-v", "/hostscan/token")
	tokenCmd.Stdin = strings.NewReader("<hostscan><token>ABCDEF</token></hostscan>")
	tokenOut, err := tokenCmd.Output()
	if err != nil {
		t.Fatalf("token extraction error = %v", err)
	}
	if strings.TrimSpace(string(tokenOut)) != "ABCDEF" {
		t.Fatalf("token extraction output = %q, want %q", string(tokenOut), "ABCDEF")
	}

	fieldCmd := exec.Command(shimPath, "sel", "-t", "-v", "/data/hostscan/field/@value")
	fieldCmd.Stdin = strings.NewReader("<data><hostscan><field value=\"'File','vpn','/tmp/test'\"/><field value=\"'Process','vpnagentd','vpnagentd'\"/></hostscan></data>")
	fieldOut, err := fieldCmd.Output()
	if err != nil {
		t.Fatalf("field extraction error = %v", err)
	}
	gotFields := strings.Split(strings.TrimSpace(string(fieldOut)), "\n")
	if len(gotFields) != 2 {
		t.Fatalf("field extraction output = %q", string(fieldOut))
	}
	if gotFields[0] != "'File','vpn','/tmp/test'" || gotFields[1] != "'Process','vpnagentd','vpnagentd'" {
		t.Fatalf("field extraction values = %q", gotFields)
	}
}

func TestCurlShimScriptCachesDataXMLAndAugmentsScanPayload(t *testing.T) {
	helperDir := t.TempDir()

	curlShimPath := filepath.Join(helperDir, "curl")
	if err := writeExecutableFile(curlShimPath, curlShimScript()); err != nil {
		t.Fatalf("writeExecutableFile(curl) error = %v", err)
	}

	fakeCurlPath := filepath.Join(helperDir, "real-curl")
	fakeCurlScript := `#!/bin/sh
set -eu

url=
for arg in "$@"; do
  case "$arg" in
    http://*|https://*)
      url=$arg
      ;;
  esac
done

case "$url" in
  */+CSCOE+/sdesktop/token.xml*)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<hostscan><token>REAL_SDESKTOP_TOKEN</token></hostscan>
EOF
    ;;
  */CACHE/sdesktop/data.xml)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<data>
  <hostscan>
    <field type="dropdown" name="lHostScanList8" value="'Process','9','kesl'" />
    <field type="dropdown" name="lHostScanList10" value="'File','11','/var/cache/tmp/ad'" />
    <field type="dropdown" name="cInspectorExtension0" value="secinsp_5_2_3_6~Advanced Endpoint Assessment~am_enforce=1;am_count=1;am_product.mac=Kaspersky Endpoint Security (Mac)|11.x;am_defupdate.mac=1;am_defupdate_days.mac=7;pfw_enforce.mac=0;pfw_count.mac=0" />
  </hostscan>
</data>
EOF
    ;;
  */+CSCOE+/sdesktop/scan.xml*)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<hostscan><status>TOKEN_SUCCESS</status></hostscan>
EOF
    ;;
  *)
    exit 1
    ;;
esac
`
	if err := writeExecutableFile(fakeCurlPath, fakeCurlScript); err != nil {
		t.Fatalf("writeExecutableFile(real-curl) error = %v", err)
	}

	env := append(
		os.Environ(),
		"OPENCONNECT_TUN_REAL_CURL_BIN="+fakeCurlPath,
		"OPENCONNECT_TUN_WA_DIAGNOSE_PATH="+filepath.Join(helperDir, "missing-waDiagnose.json"),
	)

	dataCmd := exec.Command(curlShimPath, "-fsSL", "https://vpn-gw2.corp.example/CACHE/sdesktop/data.xml")
	dataCmd.Env = env
	if out, err := dataCmd.CombinedOutput(); err != nil {
		t.Fatalf("data curl error = %v, output = %s", err, out)
	}

	tokenCmd := exec.Command(curlShimPath, "-fsSL", "https://vpn-gw2.corp.example/+CSCOE+/sdesktop/token.xml?ticket=TICKET&stub=0")
	tokenCmd.Env = env
	if out, err := tokenCmd.CombinedOutput(); err != nil {
		t.Fatalf("token curl error = %v, output = %s", err, out)
	}

	responsePath := filepath.Join(helperDir, "response.txt")
	if err := os.WriteFile(responsePath, []byte("endpoint.device.hostname=\"macbook\";\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(response.txt) error = %v", err)
	}

	scanCmd := exec.Command(curlShimPath, "-s", "-H", "Content-Type: text/xml", "--data-binary", "@"+responsePath, "https://vpn-gw2.corp.example/+CSCOE+/sdesktop/scan.xml?reusebrowser=1")
	scanCmd.Env = env
	if out, err := scanCmd.CombinedOutput(); err != nil {
		t.Fatalf("scan curl error = %v, output = %s", err, out)
	}

	contents, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("ReadFile(response.txt) error = %v", err)
	}
	body := string(contents)
	if !strings.Contains(body, `endpoint.am["Kaspersky Endpoint Security (Mac)|11.x"].exists="true";`) {
		t.Fatalf("augmented response missing full antimalware label: %q", body)
	}
	if !strings.Contains(body, `endpoint.am["Kaspersky Endpoint Security (Mac)"].exists="true";`) {
		t.Fatalf("augmented response missing short antimalware label: %q", body)
	}
	if !strings.Contains(body, `endpoint.am["Kaspersky Endpoint Security (Mac)|11.x"].lastupdate="0";`) {
		t.Fatalf("augmented response missing antimalware lastupdate: %q", body)
	}
	if strings.Contains(body, `endpoint.process["9"].exists="true";`) {
		t.Fatalf("augmented response should not force process presence: %q", body)
	}
	if strings.Contains(body, `endpoint.file["11"].exists="true";`) {
		t.Fatalf("augmented response should not force file presence: %q", body)
	}

	tokenBody, err := os.ReadFile(filepath.Join(helperDir, "csd-token.txt"))
	if err != nil {
		t.Fatalf("ReadFile(csd-token.txt) error = %v", err)
	}
	if strings.TrimSpace(string(tokenBody)) != "REAL_SDESKTOP_TOKEN" {
		t.Fatalf("cached token = %q, want REAL_SDESKTOP_TOKEN", string(tokenBody))
	}
}

func TestCurlShimScriptPrefersWADiagnoseAugmentationOverFakeSecinsp(t *testing.T) {
	helperDir := t.TempDir()

	curlShimPath := filepath.Join(helperDir, "curl")
	if err := writeExecutableFile(curlShimPath, curlShimScript()); err != nil {
		t.Fatalf("writeExecutableFile(curl) error = %v", err)
	}

	fakeCurlPath := filepath.Join(helperDir, "real-curl")
	fakeCurlScript := `#!/bin/sh
set -eu

url=
for arg in "$@"; do
  case "$arg" in
    http://*|https://*)
      url=$arg
      ;;
  esac
done

case "$url" in
  */+CSCOE+/sdesktop/token.xml*)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<hostscan><token>REAL_SDESKTOP_TOKEN</token></hostscan>
EOF
    ;;
  */CACHE/sdesktop/data.xml)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<data>
  <hostscan>
    <field type="dropdown" name="lHostScanList8" value="'Process','9','kesl'" />
    <field type="dropdown" name="lHostScanList10" value="'File','11','/var/cache/tmp/ad'" />
    <field type="dropdown" name="cInspectorExtension0" value="secinsp_5_2_3_6~Advanced Endpoint Assessment~am_enforce=1;am_count=1;am_product.mac=Kaspersky Endpoint Security (Mac)|11.x;am_defupdate.mac=1;am_defupdate_days.mac=7;pfw_enforce.mac=1;pfw_count.mac=1" />
  </hostscan>
</data>
EOF
    ;;
  */+CSCOE+/sdesktop/scan.xml*)
    cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<hostscan><status>TOKEN_SUCCESS</status></hostscan>
EOF
    ;;
  *)
    exit 1
    ;;
esac
`
	if err := writeExecutableFile(fakeCurlPath, fakeCurlScript); err != nil {
		t.Fatalf("writeExecutableFile(real-curl) error = %v", err)
	}

	waDiagnosePath := filepath.Join(helperDir, "waDiagnose.txt")
	waDiagnoseFixture := `{
  "detected_products": [
    {
      "sig_name": "Xprotect",
      "methods": [
        {"method_name": "GetVersion", "result": {"version": "5335"}},
        {"method_name": "GetRealTimeProtectionState", "result": {"enabled": true, "details": {"antivirus": true}}},
        {"method_name": "GetDefinitionState", "result": {"definitions": [{"name": "Xprotect", "version": "5335", "last_update": "1774474826", "type": "antimalware"}]}}
      ]
    },
    {
      "sig_name": "Gatekeeper",
      "methods": [
        {"method_name": "GetRealTimeProtectionState", "result": {"enabled": true, "details": {"antivirus": true, "antispyware": true}}}
      ]
    },
    {
      "sig_name": "Packet Filter",
      "methods": [
        {"method_name": "GetVersion", "result": {"version": "1.5.00.33356"}},
        {"method_name": "GetFirewallState", "result": {"enabled": true}}
      ]
    }
  ],
  "system_info": {
    "protected": true,
    "protected_info": "2"
  }
}`
	if err := os.WriteFile(waDiagnosePath, []byte(waDiagnoseFixture), 0o644); err != nil {
		t.Fatalf("WriteFile(waDiagnose.txt) error = %v", err)
	}

	env := append(
		os.Environ(),
		"OPENCONNECT_TUN_REAL_CURL_BIN="+fakeCurlPath,
		"OPENCONNECT_TUN_WA_DIAGNOSE_PATH="+waDiagnosePath,
	)

	dataCmd := exec.Command(curlShimPath, "-fsSL", "https://vpn-gw2.corp.example/CACHE/sdesktop/data.xml")
	dataCmd.Env = env
	if out, err := dataCmd.CombinedOutput(); err != nil {
		t.Fatalf("data curl error = %v, output = %s", err, out)
	}

	tokenCmd := exec.Command(curlShimPath, "-fsSL", "https://vpn-gw2.corp.example/+CSCOE+/sdesktop/token.xml?ticket=TICKET&stub=0")
	tokenCmd.Env = env
	if out, err := tokenCmd.CombinedOutput(); err != nil {
		t.Fatalf("token curl error = %v, output = %s", err, out)
	}

	responsePath := filepath.Join(helperDir, "response.txt")
	if err := os.WriteFile(responsePath, []byte("endpoint.device.hostname=\"macbook\";\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(response.txt) error = %v", err)
	}

	scanCmd := exec.Command(curlShimPath, "-s", "-H", "Content-Type: text/xml", "--data-binary", "@"+responsePath, "https://vpn-gw2.corp.example/+CSCOE+/sdesktop/scan.xml?reusebrowser=1")
	scanCmd.Env = env
	if out, err := scanCmd.CombinedOutput(); err != nil {
		t.Fatalf("scan curl error = %v, output = %s", err, out)
	}

	contents, err := os.ReadFile(responsePath)
	if err != nil {
		t.Fatalf("ReadFile(response.txt) error = %v", err)
	}
	body := string(contents)
	if !strings.Contains(body, `endpoint.device.protection="protected";`) {
		t.Fatalf("augmented response missing device protection: %q", body)
	}
	if !strings.Contains(body, `endpoint.device.protection_version="2";`) {
		t.Fatalf("augmented response missing device protection version: %q", body)
	}
	if !strings.Contains(body, `endpoint.am["Xprotect|5335"].exists="true";`) {
		t.Fatalf("augmented response missing xprotect versioned label: %q", body)
	}
	if !strings.Contains(body, `endpoint.am["Xprotect"].lastupdate="1774474826";`) {
		t.Fatalf("augmented response missing xprotect update timestamp: %q", body)
	}
	if !strings.Contains(body, `endpoint.am["Gatekeeper"].exists="true";`) {
		t.Fatalf("augmented response missing gatekeeper label: %q", body)
	}
	if !strings.Contains(body, `endpoint.fw["Packet Filter"].enabled="ok";`) {
		t.Fatalf("augmented response missing packet filter firewall state: %q", body)
	}
	if strings.Contains(body, `endpoint.am["Kaspersky Endpoint Security (Mac)|11.x"]`) {
		t.Fatalf("augmented response should prefer waDiagnose over fake secinsp antimalware: %q", body)
	}
	if strings.Contains(body, `endpoint.process["9"].exists="true";`) {
		t.Fatalf("augmented response should not force process presence: %q", body)
	}
	if strings.Contains(body, `endpoint.file["11"].exists="true";`) {
		t.Fatalf("augmented response should not force file presence: %q", body)
	}
}

func TestCSDWrapperScriptRewritesStubToZero(t *testing.T) {
	helperDir := t.TempDir()
	wrapperPath := filepath.Join(helperDir, "csd-wrapper.sh")
	if err := writeExecutableFile(wrapperPath, csdWrapperScript()); err != nil {
		t.Fatalf("writeExecutableFile(csd-wrapper) error = %v", err)
	}

	fakeCSDPost := filepath.Join(helperDir, "csd-post.sh")
	if err := os.WriteFile(fakeCSDPost, []byte("#!/bin/sh\nprintf '%s\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(csd-post.sh) error = %v", err)
	}

	cmd := exec.Command(wrapperPath, "/dev/null", "-ticket", "ABC", "-stub", "SHOULD_NOT_SURVIVE", "-group", "outside")
	cmd.Env = append(os.Environ(), "OPENCONNECT_TUN_CSD_POST_BIN="+fakeCSDPost)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("csd wrapper error = %v", err)
	}

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{"/dev/null", "-ticket", "ABC", "-stub", "0", "-group", "outside"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("wrapper args = %q, want %q", got, want)
	}
}

func TestCSDWrapperScriptPrefersNativeHelperWhenConfigured(t *testing.T) {
	helperDir := t.TempDir()
	wrapperPath := filepath.Join(helperDir, "csd-wrapper.sh")
	if err := writeExecutableFile(wrapperPath, csdWrapperScript()); err != nil {
		t.Fatalf("writeExecutableFile(csd-wrapper) error = %v", err)
	}
	nativeScriptPath := filepath.Join(helperDir, "csd-native.py")
	if err := os.WriteFile(nativeScriptPath, []byte("print('unused')\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(csd-native.py) error = %v", err)
	}

	fakePython := filepath.Join(helperDir, "python3")
	if err := os.WriteFile(fakePython, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(python3) error = %v", err)
	}

	cmd := exec.Command(wrapperPath, "/dev/null", "-ticket", "ABC", "-stub", "ORIGINAL")
	cmd.Env = append(os.Environ(),
		"OPENCONNECT_TUN_NATIVE_CSD_PYTHON="+fakePython,
		"OPENCONNECT_TUN_NATIVE_CSD_LIB="+filepath.Join(helperDir, "libcsd.dylib"),
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("native wrapper error = %v", err)
	}

	got := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{nativeScriptPath, "/dev/null", "-ticket", "ABC", "-stub", "ORIGINAL"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("native wrapper args = %q, want %q", got, want)
	}
}

func TestNativeCSDPythonScriptDetachesInsteadOfFreeingOnSuccess(t *testing.T) {
	script := nativeCSDPythonScript()

	if !strings.Contains(script, "lib.csd_detach.restype = ctypes.c_int") {
		t.Fatalf("native helper missing csd_detach binding: %q", script)
	}
	if !strings.Contains(script, "detach_rc = lib.csd_detach()") {
		t.Fatalf("native helper missing csd_detach call: %q", script)
	}
	if !strings.Contains(script, "if not success:") {
		t.Fatalf("native helper missing failure-only cleanup guard: %q", script)
	}
	if !strings.Contains(script, "elif not detached:") {
		t.Fatalf("native helper missing successful no-free fallback: %q", script)
	}
	if !strings.Contains(script, "skipping csd_free after successful run") {
		t.Fatalf("native helper missing explicit no-free log line: %q", script)
	}
}

func TestNormalizeAuthModeDefaultsToAggregate(t *testing.T) {
	cases := map[string]string{
		"":            "aggregate",
		"saml":        "aggregate",
		"openconnect": "openconnect",
		"password":    "aggregate",
		"aggregate":   "aggregate",
	}
	for input, want := range cases {
		if got := normalizeAuthMode(input); got != want {
			t.Fatalf("normalizeAuthMode(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestResolveOpenConnectAuthTargetUsesUsergroupForURLPath(t *testing.T) {
	targetURL, usergroup := resolveOpenConnectAuthTarget("vpn-gw2.corp.example/outside")
	if targetURL != "https://vpn-gw2.corp.example" {
		t.Fatalf("targetURL = %q, want https://vpn-gw2.corp.example", targetURL)
	}
	if usergroup != "outside" {
		t.Fatalf("usergroup = %q, want outside", usergroup)
	}

	targetURL, usergroup = resolveOpenConnectAuthTarget("vpn-gw2.corp.example")
	if targetURL != "https://vpn-gw2.corp.example" {
		t.Fatalf("targetURL without path = %q, want https://vpn-gw2.corp.example", targetURL)
	}
	if usergroup != "" {
		t.Fatalf("usergroup without path = %q, want empty", usergroup)
	}
}

func TestBuildNativeCSDConfigUsesResolvedIPAndFingerprint(t *testing.T) {
	root := t.TempDir()
	libPath := filepath.Join(root, ".cisco", "vpn", "cache", "lib64_appid", "libcsd.dylib")
	if err := os.MkdirAll(filepath.Dir(libPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(libPath) error = %v", err)
	}
	if err := os.WriteFile(libPath, []byte("stub"), 0o644); err != nil {
		t.Fatalf("WriteFile(libPath) error = %v", err)
	}

	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(toolDir) error = %v", err)
	}
	pythonPath := filepath.Join(toolDir, "python3")
	if err := os.WriteFile(pythonPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(python3) error = %v", err)
	}

	prevHomeDir := userHomeDirOpenConnect
	prevLookupHost := lookupHostOpenConnect
	prevCertSHA1 := serverCertSHA1OpenConnect
	prevLookPath := execLookPathOpenConnect
	userHomeDirOpenConnect = func() (string, error) { return root, nil }
	lookupHostOpenConnect = func(host string) ([]string, error) {
		if host != "vpn-gw2.corp.example" {
			t.Fatalf("lookup host = %q, want vpn-gw2.corp.example", host)
		}
		return []string{"198.51.100.22"}, nil
	}
	serverCertSHA1OpenConnect = func(host string, port string) (string, error) {
		if host != "vpn-gw2.corp.example" {
			t.Fatalf("cert host = %q, want vpn-gw2.corp.example", host)
		}
		if port != "" && port != "443" {
			t.Fatalf("cert port = %q, want empty/443", port)
		}
		return "771ECE8134D5ABCC56255A29600A6D39793AB307", nil
	}
	execLookPathOpenConnect = func(name string) (string, error) {
		if name == "python3" {
			return pythonPath, nil
		}
		return prevLookPath(name)
	}
	defer func() {
		userHomeDirOpenConnect = prevHomeDir
		lookupHostOpenConnect = prevLookupHost
		serverCertSHA1OpenConnect = prevCertSHA1
		execLookPathOpenConnect = prevLookPath
	}()

	cfg, err := buildNativeCSDConfig("vpn-gw2.corp.example", "", "outside")
	if err != nil {
		t.Fatalf("buildNativeCSDConfig() error = %v", err)
	}
	if cfg.LibPath != libPath {
		t.Fatalf("LibPath = %q, want %q", cfg.LibPath, libPath)
	}
	if cfg.PythonPath != pythonPath {
		t.Fatalf("PythonPath = %q, want %q", cfg.PythonPath, pythonPath)
	}
	if cfg.HostURL != "https://198.51.100.22" {
		t.Fatalf("HostURL = %q, want https://198.51.100.22", cfg.HostURL)
	}
	if cfg.FQDN != "vpn-gw2.corp.example" {
		t.Fatalf("FQDN = %q", cfg.FQDN)
	}
	if cfg.Group != "outside" {
		t.Fatalf("Group = %q, want outside", cfg.Group)
	}
	if cfg.ResultURL != "https://vpn-gw2.corp.example/CACHE/sdesktop/install/result.htm" {
		t.Fatalf("ResultURL = %q", cfg.ResultURL)
	}
	if cfg.ServerCertHash != "sha1:771ECE8134D5ABCC56255A29600A6D39793AB307" {
		t.Fatalf("ServerCertHash = %q", cfg.ServerCertHash)
	}
}

func TestResolveNativeCSDHostURLFallsBackToSystemLookup(t *testing.T) {
	prevLookupHost := lookupHostOpenConnect
	prevSystemLookupHost := systemLookupHostOpenConnect
	lookupHostOpenConnect = func(host string) ([]string, error) {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	systemLookupHostOpenConnect = func(host string) []string {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("system lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return []string{"10.24.79.46"}
	}
	defer func() {
		lookupHostOpenConnect = prevLookupHost
		systemLookupHostOpenConnect = prevSystemLookupHost
	}()

	got, err := resolveNativeCSDHostURL("vpn-gw2.internal.corp.example")
	if err != nil {
		t.Fatalf("resolveNativeCSDHostURL() error = %v", err)
	}
	if got != "https://10.24.79.46" {
		t.Fatalf("resolveNativeCSDHostURL() = %q, want %q", got, "https://10.24.79.46")
	}
}

func TestNewSAMLHTTPClientDialsSystemResolvedAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Host; got != "vpn-gw2.internal.corp.example" && !strings.HasPrefix(got, "vpn-gw2.internal.corp.example:") {
			t.Fatalf("Host = %q", got)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("url.Parse(server.URL) error = %v", err)
	}
	serverHost, serverPort, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatalf("SplitHostPort(server host) error = %v", err)
	}

	prevLookupHost := lookupHostOpenConnect
	prevSystemLookupHost := systemLookupHostOpenConnect
	lookupHostOpenConnect = func(host string) ([]string, error) {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	systemLookupHostOpenConnect = func(host string) []string {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("system lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return []string{serverHost}
	}
	defer func() {
		lookupHostOpenConnect = prevLookupHost
		systemLookupHostOpenConnect = prevSystemLookupHost
	}()

	client := newSAMLHTTPClient(nil, nil)
	resp, err := client.Get("http://vpn-gw2.internal.corp.example:" + serverPort + "/")
	if err != nil {
		t.Fatalf("client.Get() error = %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(body) error = %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", string(body))
	}
}

func TestResolveOpenConnectResolveUsesHostIPFormat(t *testing.T) {
	prevLookupHost := lookupHostOpenConnect
	prevSystemLookupHost := systemLookupHostOpenConnect
	lookupHostOpenConnect = func(host string) ([]string, error) {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	systemLookupHostOpenConnect = func(host string) []string {
		if host != "vpn-gw2.internal.corp.example" {
			t.Fatalf("system lookup host = %q, want vpn-gw2.internal.corp.example", host)
		}
		return []string{"10.24.79.46"}
	}
	t.Cleanup(func() {
		lookupHostOpenConnect = prevLookupHost
		systemLookupHostOpenConnect = prevSystemLookupHost
	})

	got := resolveOpenConnectResolve("vpn-gw2.internal.corp.example/outside")
	if got != "vpn-gw2.internal.corp.example:10.24.79.46" {
		t.Fatalf("resolveOpenConnectResolve() = %q, want %q", got, "vpn-gw2.internal.corp.example:10.24.79.46")
	}
}

func TestFindOpenConnectInterfaceFromLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "openconnect.log")
	if err := os.WriteFile(logPath, []byte(strings.Join([]string{
		"noise",
		"  InterfaceName : utun9",
		"TUNDEV=utun11",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("WriteFile(log) error = %v", err)
	}

	got := findOpenConnectInterfaceFromLog(logPath)
	if got != "utun11" {
		t.Fatalf("findOpenConnectInterfaceFromLog() = %q, want %q", got, "utun11")
	}
}

func TestEnsureSudoCredentialsFallsBackToInteractivePrompt(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "sudo.log")
	sudoPath := filepath.Join(root, "sudo")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + shellQuote(logPath) + "\n" +
		"if [ \"$1\" = \"-n\" ] && [ \"$2\" = \"true\" ]; then\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [ \"$1\" = \"-v\" ]; then\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 1\n"
	if err := os.WriteFile(sudoPath, []byte(script), 0o755); err != nil {
		t.Fatalf("WriteFile(sudo) error = %v", err)
	}

	prevCmd := execCommandOpenConnect
	prevTTY := stdinSupportsPromptOpenConnect
	execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
		if name == "sudo" {
			return exec.Command(sudoPath, args...)
		}
		return prevCmd(name, args...)
	}
	stdinSupportsPromptOpenConnect = func() bool { return true }
	t.Cleanup(func() {
		execCommandOpenConnect = prevCmd
		stdinSupportsPromptOpenConnect = prevTTY
	})

	if err := ensureSudoCredentials(); err != nil {
		t.Fatalf("ensureSudoCredentials() error = %v", err)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile(sudo.log) error = %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("sudo invocations = %q, want two calls", string(raw))
	}
	if lines[0] != "-n true" || lines[1] != "-v" {
		t.Fatalf("sudo call order = %q, want '-n true' then '-v'", string(raw))
	}
}

func TestConnectFailsBeforeSessionArtifactsWhenSudoUnavailableNonInteractive(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")

	prevLookPath := execLookPathOpenConnect
	prevCmd := execCommandOpenConnect
	prevTTY := stdinSupportsPromptOpenConnect
	execLookPathOpenConnect = func(name string) (string, error) {
		switch name {
		case "openconnect":
			return "/tmp/openconnect", nil
		case "vpn-slice":
			return "/tmp/vpn-slice", nil
		default:
			return "", exec.ErrNotFound
		}
	}
	execCommandOpenConnect = func(name string, args ...string) *exec.Cmd {
		if name == "sudo" {
			return exec.Command("false")
		}
		return prevCmd(name, args...)
	}
	stdinSupportsPromptOpenConnect = func() bool { return false }
	t.Cleanup(func() {
		execLookPathOpenConnect = prevLookPath
		execCommandOpenConnect = prevCmd
		stdinSupportsPromptOpenConnect = prevTTY
	})

	_, err := Connect(ConnectOptions{
		Server:         "vpn-gw2.corp.example/outside",
		Mode:           ConnectModeSplitInclude,
		PrivilegedMode: PrivilegedModeSudo,
		IncludeRoutes:  []string{"10.0.0.0/8"},
		VPNDomains:     []string{"corp.example"},
		VPNNameservers: []string{"10.23.16.4", "10.23.0.23"},
		CacheDir:       cacheDir,
	})
	if err == nil {
		t.Fatal("Connect() error = nil, want sudo authentication failure")
	}
	if !strings.Contains(err.Error(), "sudo credentials are not cached") {
		t.Fatalf("Connect() error = %v, want cached sudo hint", err)
	}
	if _, statErr := os.Stat(SessionsDir(cacheDir)); !os.IsNotExist(statErr) {
		t.Fatalf("SessionsDir(%q) exists after failure, want no session artifacts", cacheDir)
	}
	if _, statErr := os.Stat(CurrentPath(cacheDir)); !os.IsNotExist(statErr) {
		t.Fatalf("CurrentPath(%q) exists after failure, want no runtime file", cacheDir)
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func envSliceToMap(values []string) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		parts := strings.SplitN(value, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	return result
}
