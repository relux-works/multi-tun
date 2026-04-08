package openconnectcli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"multi-tun/internal/keychain"
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

func TestRunSetupWritesConfigAndSeedsKeychainPlaceholders(t *testing.T) {
	originalSet := keychainSetWithOptions
	originalExists := keychainExists
	originalGet := keychainGet
	originalResolve := resolveSetupHostEntry
	originalHome := userHomeDirOpenConnect
	t.Cleanup(func() {
		keychainSetWithOptions = originalSet
		keychainExists = originalExists
		keychainGet = originalGet
		resolveSetupHostEntry = originalResolve
		userHomeDirOpenConnect = originalHome
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	configPath := filepath.Join(t.TempDir(), "openconnect.json")

	type keychainWrite struct {
		Value   string
		Label   string
		Kind    string
		Comment string
	}
	writes := map[string]keychainWrite{}
	keychainSetWithOptions = func(account, value string, options keychain.SetOptions) error {
		writes[account] = keychainWrite{
			Value:   value,
			Label:   options.Label,
			Kind:    options.Kind,
			Comment: options.Comment,
		}
		return nil
	}
	keychainExists = func(account string) bool {
		return false
	}
	keychainGet = func(account string) (string, error) {
		return "", fmt.Errorf("unexpected get %s", account)
	}
	userHomeDirOpenConnect = func() (string, error) {
		return t.TempDir(), nil
	}
	resolveSetupHostEntry = func(paths []string, selector string) (openconnect.HostEntry, error) {
		if selector != "Corp VPN" {
			t.Fatalf("selector = %q, want %q", selector, "Corp VPN")
		}
		return openconnect.HostEntry{
			Name:    "Corp VPN",
			Address: "vpn.example.com/engineering",
		}, nil
	}

	exitCode := app.Run([]string{"setup", "--config", configPath, "--vpn-name", "Corp VPN"})
	if exitCode != 0 {
		t.Fatalf("Run(setup) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if got := writes["vpn-example-com-engineering/username"].Value; got != "REPLACE_ME_USERNAME" {
		t.Fatalf("username placeholder = %q", got)
	}
	if got := writes["vpn-example-com-engineering/password"].Value; got != "REPLACE_ME_PASSWORD" {
		t.Fatalf("password placeholder = %q", got)
	}
	if got := writes["vpn-example-com-engineering/totp_secret"].Value; got != "REPLACE_ME_TOTP_SECRET" {
		t.Fatalf("totp placeholder = %q", got)
	}
	if got := writes["vpn-example-com-engineering/password"].Label; got != "multi-tun password (vpn.example.com/engineering)" {
		t.Fatalf("password label = %q", got)
	}
	if got := writes["vpn-example-com-engineering/totp_secret"].Label; got != "multi-tun TOTP secret (vpn.example.com/engineering)" {
		t.Fatalf("totp label = %q", got)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(configPath) error = %v", err)
	}
	if !strings.Contains(string(raw), `"server_url": "vpn.example.com/engineering"`) {
		t.Fatalf("config missing server_url: %s", string(raw))
	}
	if !strings.Contains(stdout.String(), "config: "+configPath) {
		t.Fatalf("stdout = %q, want config path", stdout.String())
	}
}

func TestRunSetupPreservesExistingSecretsWhileRefreshingMetadata(t *testing.T) {
	originalSet := keychainSetWithOptions
	originalExists := keychainExists
	originalGet := keychainGet
	t.Cleanup(func() {
		keychainSetWithOptions = originalSet
		keychainExists = originalExists
		keychainGet = originalGet
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	configPath := filepath.Join(t.TempDir(), "openconnect.json")

	type keychainWrite struct {
		Value string
		Label string
	}
	writes := map[string]keychainWrite{}
	keychainExists = func(account string) bool {
		return true
	}
	keychainGet = func(account string) (string, error) {
		return "secret-for-" + account, nil
	}
	keychainSetWithOptions = func(account, value string, options keychain.SetOptions) error {
		writes[account] = keychainWrite{Value: value, Label: options.Label}
		return nil
	}

	exitCode := app.Run([]string{
		"setup",
		"--config", configPath,
		"--vpn-name", "Corp VPN",
		"--server-url", "vpn.example.com/engineering",
	})
	if exitCode != 0 {
		t.Fatalf("Run(setup) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if got := writes["vpn-example-com-engineering/password"].Value; got != "secret-for-vpn-example-com-engineering/password" {
		t.Fatalf("password value = %q", got)
	}
	if got := writes["vpn-example-com-engineering/password"].Label; got != "multi-tun password (vpn.example.com/engineering)" {
		t.Fatalf("password label = %q", got)
	}
}

func TestRunSetupRequiresVPNName(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	exitCode := app.Run([]string{"setup"})
	if exitCode != 1 {
		t.Fatalf("Run(setup) exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "--vpn-name or --profile is required") {
		t.Fatalf("stderr = %q", stderr.String())
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

func TestParseRunOptionsUsesProfileSpecificSplitIncludeOverrides(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_profile": "Ural Outside extended",
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  },
  "profiles": {
    "Ural Outside extended": {
      "split_include": {
        "routes": ["172.16.0.0/12"],
        "vpn_domains": ["services.corp.example"],
        "nameservers": ["10.24.60.8"]
      }
    }
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
	if options.profile != "Ural Outside extended" {
		t.Fatalf("profile = %q, want %q", options.profile, "Ural Outside extended")
	}
	if !reflect.DeepEqual(options.includeRoutes, []string{"172.16.0.0/12"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"services.corp.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.24.60.8"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsUsesServerSpecificSplitIncludeOverrides(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "split_include": {
        "routes": ["11.0.0.0/8"],
        "vpn_domains": ["outside.corp.example"],
        "nameservers": ["10.24.60.197"]
      }
    }
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}

	app := New(ioDiscard{}, ioDiscard{})
	options, exitCode, err := app.parseRunOptions("start", []string{
		"--config", configPath,
		"--dry-run",
		"--server", "vpn-gw2.corp.example/outside",
	})
	if err != nil {
		t.Fatalf("parseRunOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if !reflect.DeepEqual(options.includeRoutes, []string{"11.0.0.0/8"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"outside.corp.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.24.60.197"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsProfileOverridesBeatServerOverrides(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_server": "vpn-gw2.corp.example/outside",
  "default_profile": "Ural Outside extended",
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "split_include": {
        "routes": ["11.0.0.0/8"],
        "vpn_domains": ["server.corp.example"],
        "nameservers": ["10.24.60.197"]
      }
    }
  },
  "profiles": {
    "Ural Outside extended": {
      "split_include": {
        "routes": ["172.16.0.0/12"],
        "vpn_domains": ["profile.corp.example"],
        "nameservers": ["10.24.60.8"]
      }
    }
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
	if !reflect.DeepEqual(options.includeRoutes, []string{"172.16.0.0/12"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"profile.corp.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.24.60.8"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsAllowsOverridesToClearGlobalSplitIncludeLists(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_profile": "Public Corp",
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  },
  "profiles": {
    "Public Corp": {
      "split_include": {
        "routes": [],
        "vpn_domains": [],
        "nameservers": []
      }
    }
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
	if options.includeRoutes != nil {
		t.Fatalf("includeRoutes = %#v, want nil", options.includeRoutes)
	}
	if options.vpnDomains != nil {
		t.Fatalf("vpnDomains = %#v, want nil", options.vpnDomains)
	}
	if options.vpnNameservers != nil {
		t.Fatalf("vpnNameservers = %#v, want nil", options.vpnNameservers)
	}
}

func TestParseRunOptionsAppliesBypassSuffixesOverVPNDomains(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example", "bypass.corp.example"],
    "bypass_suffixes": [".Bypass.Corp.Example"],
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
	if !reflect.DeepEqual(options.vpnDomains, []string{"corp.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.bypassSuffixes, []string{"bypass.corp.example"}) {
		t.Fatalf("bypassSuffixes = %#v", options.bypassSuffixes)
	}
}

func TestParseRunOptionsUsesServerOverridesResolvedFromDefaultProfile(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)

	profileDir := filepath.Join(homeDir, "Downloads", "cisco-anyconnect-profiles", "profiles")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(profileDir) error = %v", err)
	}
	profilePath := filepath.Join(profileDir, "corp.xml")
	if err := os.WriteFile(profilePath, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AnyConnectProfile>
  <ServerList>
    <HostEntry>
      <HostName>Ural Outside extended</HostName>
      <HostAddress>vpn-gw2.corp.example/outside</HostAddress>
    </HostEntry>
  </ServerList>
</AnyConnectProfile>
`), 0o644); err != nil {
		t.Fatalf("WriteFile(profilePath) error = %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default_profile": "Ural Outside extended",
  "default_mode": "split-include",
  "split_include": {
    "routes": ["10.0.0.0/8"],
    "vpn_domains": ["corp.example"],
    "nameservers": ["10.23.16.4", "10.23.0.23"]
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "profiles": {
        "Ural Outside extended": {}
      },
      "split_include": {
        "vpn_domains": ["server.corp.example"],
        "bypass_suffixes": ["bypass.corp.example"],
        "nameservers": ["10.24.60.197"]
      }
    }
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
	if options.profile != "Ural Outside extended" {
		t.Fatalf("profile = %q, want %q", options.profile, "Ural Outside extended")
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"server.corp.example"}) {
		t.Fatalf("vpnDomains = %#v", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.bypassSuffixes, []string{"bypass.corp.example"}) {
		t.Fatalf("bypassSuffixes = %#v", options.bypassSuffixes)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.24.60.197"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsUsesRemasteredDefaultSelectionAndNestedProfilePolicy(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default": {
    "server_url": "vpn-gw2.corp.example/outside",
    "profile": "Ural Outside extended"
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "profiles": {
        "Ural Outside extended": {
          "mode": "split-include",
          "split_include": {
            "routes": ["10.0.0.0/8", "172.16.0.0/12"],
            "vpn_domains": ["corp.example", "inside.corp.example", "branch.example"],
            "bypass_suffixes": ["bypass.corp.example"],
            "nameservers": ["10.23.16.4", "10.23.0.23"]
          }
        }
      }
    }
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
	if options.server != "vpn-gw2.corp.example/outside" {
		t.Fatalf("server = %q, want %q", options.server, "vpn-gw2.corp.example/outside")
	}
	if options.profile != "Ural Outside extended" {
		t.Fatalf("profile = %q, want %q", options.profile, "Ural Outside extended")
	}
	if options.mode != openconnect.ConnectModeSplitInclude {
		t.Fatalf("mode = %q, want %q", options.mode, openconnect.ConnectModeSplitInclude)
	}
	if !reflect.DeepEqual(options.includeRoutes, []string{"10.0.0.0/8", "172.16.0.0/12"}) {
		t.Fatalf("includeRoutes = %#v", options.includeRoutes)
	}
	if !reflect.DeepEqual(options.vpnDomains, []string{"corp.example", "branch.example"}) {
		t.Fatalf("vpnDomains = %#v, want covered child domains collapsed", options.vpnDomains)
	}
	if !reflect.DeepEqual(options.bypassSuffixes, []string{"bypass.corp.example"}) {
		t.Fatalf("bypassSuffixes = %#v", options.bypassSuffixes)
	}
	if !reflect.DeepEqual(options.vpnNameservers, []string{"10.23.16.4", "10.23.0.23"}) {
		t.Fatalf("vpnNameservers = %#v", options.vpnNameservers)
	}
}

func TestParseRunOptionsResolvesServerFromNestedProfileWithoutXML(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(configPath, []byte(`{
  "default": {
    "profile": "Ural Outside extended"
  },
  "servers": {
    "vpn-gw2.corp.example/outside": {
      "profiles": {
        "Ural Outside extended": {
          "mode": "split-include",
          "split_include": {
            "vpn_domains": ["corp.example"],
            "nameservers": ["10.23.16.4"]
          }
        }
      }
    }
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
	if options.server != "vpn-gw2.corp.example/outside" {
		t.Fatalf("server = %q, want config-resolved server", options.server)
	}
	if options.mode != openconnect.ConnectModeSplitInclude {
		t.Fatalf("mode = %q, want split-include", options.mode)
	}
}

func TestNormalizeDomainSuffixListCollapsesCoveredSuffixes(t *testing.T) {
	t.Parallel()

	got := normalizeDomainSuffixList([]string{
		"inside.corp.example",
		"corp.example",
		"REGION.CORP.EXAMPLE",
		"branch.example",
		".inside.corp.example",
	})

	want := []string{"corp.example", "branch.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeDomainSuffixList() = %#v, want %#v", got, want)
	}
}

func TestResolveSplitIncludeTargetsIgnoresDefaultsOutsideSplitMode(t *testing.T) {
	t.Parallel()

	routes, domains := resolveSplitIncludeTargets(openconnect.ConnectModeFull, openconnectcfg.SplitIncludeConfig{
		Routes:     []string{"10.0.0.0/8"},
		VPNDomains: []string{"corp.example"},
	}, []string{"172.16.0.0/12"}, []string{"branch.example"}, nil)

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
