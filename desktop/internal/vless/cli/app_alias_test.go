package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

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

func TestCommandConfigPathResolvesRelativeNameUnderConfigDir(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)

	got, err := commandConfigPath("", []string{"fortinet"})
	if err != nil {
		t.Fatalf("commandConfigPath() error = %v", err)
	}

	want := filepath.Join(configRoot, "vless-tun", "fortinet.json")
	if got != want {
		t.Fatalf("commandConfigPath() = %q, want %q", got, want)
	}
}

func TestCommandConfigPathPreservesAbsolutePath(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "custom.json")

	got, err := commandConfigPath("", []string{absolute})
	if err != nil {
		t.Fatalf("commandConfigPath() error = %v", err)
	}
	if got != absolute {
		t.Fatalf("commandConfigPath() = %q, want %q", got, absolute)
	}
}

func TestCommandConfigPathRejectsFlagAndPositionalConfig(t *testing.T) {
	_, err := commandConfigPath("/tmp/config.json", []string{"dance"})
	if err == nil {
		t.Fatal("commandConfigPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "both with --config and positional argument") {
		t.Fatalf("commandConfigPath() error = %q", err)
	}
}

func TestStartOptionsUsePositionalServerAndProfile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	options, exitCode, err := app.parseStartOptions("start", []string{"dance", "default"}, false)
	if err != nil {
		t.Fatalf("parseStartOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("parseStartOptions() exitCode = %d, want 0", exitCode)
	}
	if options.configPath != "" {
		t.Fatalf("configPath = %q, want default config", options.configPath)
	}
	if options.serverName != "dance" {
		t.Fatalf("serverName = %q, want dance", options.serverName)
	}
	if options.configProfile != "default" {
		t.Fatalf("configProfile = %q, want default", options.configProfile)
	}
	if options.refresh {
		t.Fatal("refresh = true, want parser default false before auto-profile resolution")
	}
	if options.refreshSet {
		t.Fatal("refreshSet = true, want omitted refresh flag")
	}
}

func TestStartOptionsAllowCachedFallback(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	options, exitCode, err := app.parseStartOptions("start", []string{"--refresh=false", "dance"}, true)
	if err != nil {
		t.Fatalf("parseStartOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("parseStartOptions() exitCode = %d, want 0", exitCode)
	}
	if options.refresh {
		t.Fatal("refresh = true, want cached fallback")
	}
	if !options.refreshSet {
		t.Fatal("refreshSet = false, want explicit cached fallback")
	}
	if options.serverName != "dance" {
		t.Fatalf("serverName = %q, want dance", options.serverName)
	}
}

func TestStartOptionsAllowExplicitRefresh(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	options, exitCode, err := app.parseStartOptions("start", []string{"--refresh", "dance"}, false)
	if err != nil {
		t.Fatalf("parseStartOptions() error = %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("parseStartOptions() exitCode = %d, want 0", exitCode)
	}
	if !options.refresh {
		t.Fatal("refresh = false, want explicit refresh")
	}
	if !options.refreshSet {
		t.Fatal("refreshSet = false, want explicit refresh")
	}
}

func TestEffectiveStartRefreshFollowsAutoProfileOnly(t *testing.T) {
	autoProfile := config.ProjectConfig{}
	if !effectiveStartRefresh(autoProfile, startOptions{}) {
		t.Fatal("effectiveStartRefresh(auto profile) = false, want true")
	}

	selectedProfile := config.ProjectConfig{Default: &config.DefaultConfig{ProfileSelector: "Germany"}}
	if effectiveStartRefresh(selectedProfile, startOptions{}) {
		t.Fatal("effectiveStartRefresh(selected profile) = true, want false")
	}

	if !effectiveStartRefresh(selectedProfile, startOptions{refresh: true, refreshSet: true}) {
		t.Fatal("effectiveStartRefresh(explicit refresh) = false, want true")
	}

	if effectiveStartRefresh(autoProfile, startOptions{refresh: false, refreshSet: true}) {
		t.Fatal("effectiveStartRefresh(explicit cached fallback) = true, want false")
	}
}

func TestStartOptionsRejectFlagAndPositionalServer(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	_, exitCode, err := app.parseStartOptions("start", []string{"--server", "dance", "fortinetz"}, false)
	if err == nil {
		t.Fatal("parseStartOptions() error = nil, want conflict")
	}
	if exitCode != 2 {
		t.Fatalf("parseStartOptions() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(err.Error(), "server specified both") {
		t.Fatalf("parseStartOptions() error = %q", err)
	}
}

func TestStartOptionsRejectsMoreThanServerAndProfile(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	_, exitCode, err := app.parseStartOptions("start", []string{"dance", "default", "--refresh"}, false)
	if err == nil {
		t.Fatal("parseStartOptions() error = nil, want unexpected argument")
	}
	if exitCode != 2 {
		t.Fatalf("parseStartOptions() exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(err.Error(), "flags before positionals") {
		t.Fatalf("parseStartOptions() error = %q", err)
	}
}

func TestStopTargetsIncludeAllServerCacheDirsWhenNoServerSelected(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {
    "server": "fortinetz",
    "profile": "nl"
  },
  "servers": {
    "dance": {
      "source": {"mode": "proxy", "url": "https://example.com/dance"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "default": {"selector": "Sweden"}
      }
    },
    "fortinetz": {
      "source": {"mode": "proxy", "url": "https://example.com/fortinetz"},
      "cache_dir": "/tmp/vless-fortinetz",
      "artifacts": {"singbox_config_path": "/tmp/fortinetz.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "nl": {"selector": "Netherlands"},
        "de": {"selector": "Germany"}
      }
    },
    "freedom": {
      "source": {"mode": "proxy", "url": "https://example.com/freedom"},
      "cache_dir": "/tmp/vless-freedom",
      "artifacts": {"singbox_config_path": "/tmp/freedom.json"},
      "engine": {"type": "xray"},
      "profiles": {
        "fr": {"selector": "France"}
      }
    }
  },
  "network": {
    "mode": "tun",
    "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}
  },
  "dns": {
    "proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	targets, err := stopTargetsForConfig(path, "")
	if err != nil {
		t.Fatalf("stopTargetsForConfig() error = %v", err)
	}
	if got, want := len(targets), 3; got != want {
		t.Fatalf("len(targets) = %d, want %d", got, want)
	}

	cacheDirs := map[string]bool{}
	for _, target := range targets {
		cacheDirs[target.cacheDir] = true
	}
	for _, want := range []string{"/tmp/vless-dance", "/tmp/vless-fortinetz", "/tmp/vless-freedom"} {
		if !cacheDirs[want] {
			t.Fatalf("cacheDirs missing %q: %v", want, cacheDirs)
		}
	}
}

func TestReconnectStopsAllConfiguredSessionCacheDirs(t *testing.T) {
	path := writeCLISelectionConfig(t)

	previous := stopCurrentSessionFunc
	var stoppedCacheDirs []string
	stopCurrentSessionFunc = func(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
		stoppedCacheDirs = append(stoppedCacheDirs, cacheDir)
		return nil, "none", nil
	}
	t.Cleanup(func() {
		stopCurrentSessionFunc = previous
	})

	results, err := stopConfiguredSessions(path, false, time.Second)
	if err != nil {
		t.Fatalf("stopConfiguredSessions() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("stopConfiguredSessions() returned %d stopped sessions, want none", len(results))
	}

	cacheDirs := map[string]bool{}
	for _, cacheDir := range stoppedCacheDirs {
		cacheDirs[cacheDir] = true
	}
	for _, want := range []string{"/tmp/vless-dance", "/tmp/vless-fortinetz", "/tmp/vless-freedom"} {
		if !cacheDirs[want] {
			t.Fatalf("stopped cache dirs missing %q: %v", want, stoppedCacheDirs)
		}
	}
}

func TestCleanupStaleCurrentSessionUsesStopLogic(t *testing.T) {
	previous := stopCurrentSessionFunc
	defer func() {
		stopCurrentSessionFunc = previous
	}()

	cacheDir := filepath.Join(t.TempDir(), "cache")
	launch := config.PrivilegedLaunchConfig{Mode: config.LaunchModeHelper}
	called := false
	stopCurrentSessionFunc = func(gotCacheDir string, gotLaunch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
		called = true
		if gotCacheDir != cacheDir {
			t.Fatalf("cacheDir = %q, want %q", gotCacheDir, cacheDir)
		}
		if gotLaunch.Mode != launch.Mode {
			t.Fatalf("launch.mode = %q, want %q", gotLaunch.Mode, launch.Mode)
		}
		if !force {
			t.Fatal("force = false, want true for stale startup cleanup")
		}
		if timeout != 1500*time.Millisecond {
			t.Fatalf("timeout = %s, want 1.5s", timeout)
		}
		return &session.CurrentSession{ID: "stale", PID: 4242}, "stale", nil
	}

	if err := cleanupStaleCurrentSession(cacheDir, launch); err != nil {
		t.Fatalf("cleanupStaleCurrentSession() error = %v", err)
	}
	if !called {
		t.Fatal("stopCurrentSessionFunc was not called")
	}
}

func TestReconnectStopsConfiguredSessionsBeforePreparingNewStart(t *testing.T) {
	path := writeReconnectUnmatchedProfileConfig(t)

	previous := stopCurrentSessionFunc
	var stoppedCacheDirs []string
	stopCurrentSessionFunc = func(cacheDir string, launch config.PrivilegedLaunchConfig, force bool, timeout time.Duration) (*session.CurrentSession, string, error) {
		stoppedCacheDirs = append(stoppedCacheDirs, cacheDir)
		return nil, "none", nil
	}
	t.Cleanup(func() {
		stopCurrentSessionFunc = previous
	})

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"reconnect", "--config", path})
	if exitCode != 1 {
		t.Fatalf("Run(reconnect) exitCode = %d, want 1", exitCode)
	}
	if len(stoppedCacheDirs) != 1 || stoppedCacheDirs[0] != "/tmp/vless-dance" {
		t.Fatalf("stoppedCacheDirs = %v, want [/tmp/vless-dance]", stoppedCacheDirs)
	}
	if !strings.Contains(stderr.String(), "reconnect failed:") {
		t.Fatalf("stderr = %q, want reconnect failure", stderr.String())
	}
}

func TestDiagnoseDefaultsToTunnelAndRejectsProviderArgument(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"diagnose", "dance"})
	if exitCode != 2 {
		t.Fatalf("Run(diagnose dance) exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "diagnose config") {
		t.Fatalf("stderr = %q, want diagnose config guidance", stderr.String())
	}
}

func TestDiagnoseConfigUsesPositionalServer(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {
    "server": "dance",
    "profile": "default"
  },
  "servers": {
    "dance": {
      "source": {"mode": "proxy", "url": "https://example.com/dance"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "default": {"selector": "Sweden"}
      }
    }
  },
  "network": {
    "mode": "tun",
    "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}
  },
  "dns": {
    "proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"diagnose", "config", "--config", path, "dance"})
	if exitCode != 0 {
		t.Fatalf("Run(diagnose config) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "diagnostic: config") {
		t.Fatalf("stdout = %q, want config diagnostic", stdout.String())
	}
	if !strings.Contains(stdout.String(), "server: dance") {
		t.Fatalf("stdout = %q, want selected server", stdout.String())
	}
}

func TestSetCurrentUsesPositionalServerAndWritesConfig(t *testing.T) {
	t.Parallel()

	path := writeCLISelectionConfig(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"set-current", "--config", path, "dance"})
	if exitCode != 0 {
		t.Fatalf("Run(set-current) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "current.server: dance") {
		t.Fatalf("stdout = %q, want current server", stdout.String())
	}
	if !strings.Contains(stdout.String(), "current.profile: default") {
		t.Fatalf("stdout = %q, want default profile", stdout.String())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(raw), `"server": "dance"`) {
		t.Fatalf("config = %s, want current server dance", string(raw))
	}
	if !strings.Contains(string(raw), `"profile": "default"`) {
		t.Fatalf("config = %s, want current profile default", string(raw))
	}
}

func TestSetCurrentRequiresProfileForMultiProfileServer(t *testing.T) {
	t.Parallel()

	path := writeCLISelectionConfig(t)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"set-current", "--config", path, "fortinetz"})
	if exitCode != 1 {
		t.Fatalf("Run(set-current) exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "profile is required") {
		t.Fatalf("stderr = %q, want profile required", stderr.String())
	}
}

func TestSetupWritesConfigAndReportsPath(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	configPath := filepath.Join(t.TempDir(), "vless.json")
	exitCode := app.Run([]string{
		"setup",
		"--config", configPath,
		"--source-url", "vless://uuid@example.com:443?security=reality#demo",
		"--profile", "demo",
	})
	if exitCode != 0 {
		t.Fatalf("Run(setup) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config: "+configPath) {
		t.Fatalf("stdout = %q, want config path", stdout.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("Stat(configPath) error = %v", err)
	}
}

func writeCLISelectionConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {
    "server": "fortinetz",
    "profile": "nl"
  },
  "servers": {
    "dance": {
      "source": {"mode": "proxy", "url": "https://example.com/dance"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "default": {"selector": "Sweden"}
      }
    },
    "fortinetz": {
      "source": {"mode": "proxy", "url": "https://example.com/fortinetz"},
      "cache_dir": "/tmp/vless-fortinetz",
      "artifacts": {"singbox_config_path": "/tmp/fortinetz.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "nl": {"selector": "Netherlands"},
        "de": {"selector": "Germany"}
      }
    },
    "freedom": {
      "source": {"mode": "proxy", "url": "https://example.com/freedom"},
      "cache_dir": "/tmp/vless-freedom",
      "artifacts": {"singbox_config_path": "/tmp/freedom.json"},
      "engine": {"type": "xray"},
      "profiles": {
        "fr": {"selector": "France"}
      }
    }
  },
  "network": {
    "mode": "tun",
    "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}
  },
  "dns": {
    "proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeReconnectUnmatchedProfileConfig(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {
    "server": "dance",
    "profile": "default"
  },
  "servers": {
    "dance": {
      "source": {"mode": "direct", "url": "vless://00000000-0000-0000-0000-000000000000@example.com:443?security=tls&type=tcp#demo"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "engine": {"type": "sing-box"},
      "profiles": {
        "default": {"selector": "missing-profile"}
      }
    }
  },
  "network": {
    "mode": "tun",
    "tun": {"interface_name": "utun233", "addresses": ["172.19.0.1/30"]}
  },
  "dns": {
    "proxy_resolver": {"address": "1.1.1.1", "port": 853, "tls_server_name": "cloudflare-dns.com"}
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
