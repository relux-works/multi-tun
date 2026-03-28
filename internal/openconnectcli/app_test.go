package openconnectcli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"multi-tun/internal/openconnect"
	"multi-tun/internal/openconnectcfg"
)

func TestResolveCredentials_UsesKeychainBackedUsernamePasswordAndTOTP(t *testing.T) {
	original := keychainGet
	t.Cleanup(func() {
		keychainGet = original
	})

	values := map[string]string{
		"corp-vpn/username":    "alice",
		"corp-vpn/password":    "secret-password",
		"corp-vpn/totp_secret": "totp-secret",
	}
	keychainGet = func(account string) (string, error) {
		value, ok := values[account]
		if !ok {
			return "", fmt.Errorf("missing %s", account)
		}
		return value, nil
	}

	username, password, totp, err := resolveCredentials("", "", "", openconnectcfg.AuthConfig{
		UsernameKeychainAccount: "corp-vpn/username",
		PasswordKeychainAccount: "corp-vpn/password",
		TOTPKeychainAccount:     "corp-vpn/totp_secret",
	}, false)
	if err != nil {
		t.Fatalf("resolveCredentials returned error: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username = %q, want %q", username, "alice")
	}
	if password != "secret-password" {
		t.Fatalf("password = %q, want %q", password, "secret-password")
	}
	if totp != "totp-secret" {
		t.Fatalf("totp = %q, want %q", totp, "totp-secret")
	}
}

func TestResolveCredentials_PrefersExplicitValuesAndFallsBackToPlainUsername(t *testing.T) {
	original := keychainGet
	t.Cleanup(func() {
		keychainGet = original
	})

	keychainGet = func(account string) (string, error) {
		return "from-keychain-" + account, nil
	}

	username, password, totp, err := resolveCredentials("flag-user", "flag-pass", "flag-totp", openconnectcfg.AuthConfig{
		Username:                "config-user",
		UsernameKeychainAccount: "corp-vpn/username",
		PasswordKeychainAccount: "corp-vpn/password",
		TOTPKeychainAccount:     "corp-vpn/totp_secret",
	}, false)
	if err != nil {
		t.Fatalf("resolveCredentials returned error: %v", err)
	}
	if username != "flag-user" {
		t.Fatalf("username = %q, want %q", username, "flag-user")
	}
	if password != "flag-pass" {
		t.Fatalf("password = %q, want %q", password, "flag-pass")
	}
	if totp != "flag-totp" {
		t.Fatalf("totp = %q, want %q", totp, "flag-totp")
	}

	username, password, totp, err = resolveCredentials("", "", "", openconnectcfg.AuthConfig{
		Username: "config-user",
	}, false)
	if err != nil {
		t.Fatalf("resolveCredentials returned error: %v", err)
	}
	if username != "config-user" {
		t.Fatalf("plain username fallback = %q, want %q", username, "config-user")
	}
	if password != "" {
		t.Fatalf("password = %q, want empty", password)
	}
	if totp != "" {
		t.Fatalf("totp = %q, want empty", totp)
	}
}

func TestStartAlias_UsesStartFailurePrefix(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	exitCode := app.Run([]string{"start", "--config", missingConfig})
	if exitCode != 1 {
		t.Fatalf("Run(start) exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "start failed:") {
		t.Fatalf("stderr = %q, want start failure prefix", stderr.String())
	}
}

func TestDeriveStatusViewPrefersOpenConnectRuntime(t *testing.T) {
	t.Parallel()

	view := deriveStatusView(
		"disconnected",
		nil,
		&openconnect.RuntimeStatus{
			PID:       30870,
			Interface: "utun8",
			Uptime:    "00:36",
		},
	)

	if view.State != openconnect.StateConnected {
		t.Fatalf("State = %q, want %q", view.State, openconnect.StateConnected)
	}
	if view.StateSource != "openconnect_runtime" {
		t.Fatalf("StateSource = %q, want %q", view.StateSource, "openconnect_runtime")
	}
	if view.Duration != "00:36" {
		t.Fatalf("Duration = %q, want %q", view.Duration, "00:36")
	}
	if view.CiscoState != openconnect.StateDisconnected {
		t.Fatalf("CiscoState = %q, want %q", view.CiscoState, openconnect.StateDisconnected)
	}
}

func TestDeriveStatusViewFallsBackToCiscoInfo(t *testing.T) {
	t.Parallel()

	view := deriveStatusView(
		openconnect.StateDisconnected,
		&openconnect.ConnectionInfo{
			State:    openconnect.StateConnected,
			Duration: "01:23:45",
		},
		nil,
	)

	if view.State != openconnect.StateConnected {
		t.Fatalf("State = %q, want %q", view.State, openconnect.StateConnected)
	}
	if view.StateSource != "cisco_cli" {
		t.Fatalf("StateSource = %q, want %q", view.StateSource, "cisco_cli")
	}
	if view.Duration != "01:23:45" {
		t.Fatalf("Duration = %q, want %q", view.Duration, "01:23:45")
	}
	if view.CiscoState != "" {
		t.Fatalf("CiscoState = %q, want empty", view.CiscoState)
	}
}

func TestParseRunOptionsUsesSplitIncludeDefaultsFromConfig(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_profile": "Ural Outside extended",
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8", "172.16.0.0/12"],
    "vpn_domains": ["corp.example", "branch.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}

	app := New(ioDiscard{}, ioDiscard{})
	options, exitCode, err := app.parseRunOptions("start", []string{"--config", configPath, "--dry-run"})
	if err != nil {
		t.Fatalf("parseRunOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if options.mode != openconnect.ConnectModeSplitInclude {
		t.Fatalf("mode = %q, want %q", options.mode, openconnect.ConnectModeSplitInclude)
	}
	if !reflect.DeepEqual(options.includeRoutes, []string{"10.0.0.0/8", "172.16.0.0/12"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"corp.example", "branch.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.23.16.4", "10.23.0.23"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsMergesCLIWithSplitIncludeDefaults(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}

	app := New(ioDiscard{}, ioDiscard{})
	options, exitCode, err := app.parseRunOptions("start", []string{
		"--config", configPath,
		"--dry-run",
		"--route", "172.16.0.0/12",
		"--route", "10.0.0.0/8",
		"--vpn-domains", "branch.example,corp.example,workspace.example",
	})
	if err != nil {
		t.Fatalf("parseRunOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if !reflect.DeepEqual(options.includeRoutes, []string{"10.0.0.0/8", "172.16.0.0/12"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"corp.example", "branch.example", "workspace.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.23.16.4", "10.23.0.23"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestResolveSplitIncludeTargetsIgnoresDefaultsOutsideSplitMode(t *testing.T) {
	t.Parallel()

	routes, domains := resolveSplitIncludeTargets(openconnect.ConnectModeFull, openconnectcfg.SplitIncludeConfig{
		Routes:     []string{"10.0.0.0/8"},
		VPNDomains: []string{"corp.example"},
	}, []string{"172.16.0.0/12"}, []string{"branch.example"})

	if routes != nil {
		t.Fatalf("routes = %#v, want nil", routes)
	}
	if domains != nil {
		t.Fatalf("domains = %#v, want nil", domains)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}
