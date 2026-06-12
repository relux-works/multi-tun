package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchOrDefaultUsesImplicitDefaults(t *testing.T) {
	t.Parallel()

	cfg := ProjectConfig{}
	got := cfg.LaunchOrDefault()
	if got.Mode != LaunchModeAuto {
		t.Fatalf("mode = %q, want %q", got.Mode, LaunchModeAuto)
	}
	if got.Label != defaultLaunchdLabel {
		t.Fatalf("label = %q, want %q", got.Label, defaultLaunchdLabel)
	}
	if got.PlistPath != defaultLaunchdPlistPath {
		t.Fatalf("plist_path = %q, want %q", got.PlistPath, defaultLaunchdPlistPath)
	}
}

func TestSourceModeInfersDirectFromVLESSURI(t *testing.T) {
	t.Parallel()

	cfg := ProjectConfig{
		Source: SourceConfig{
			URL: "vless://uuid@example.com:443?security=reality#demo",
		},
	}
	if got, want := cfg.SourceMode(), SourceModeDirect; got != want {
		t.Fatalf("SourceMode() = %q, want %q", got, want)
	}
}

func TestValidateRejectsUnknownLaunchMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Network.Mode = RenderModeTun
	cfg.Launch = &LaunchConfig{Mode: "bogus"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}

func TestValidateRejectsDirectModeWithoutVLESSURI(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Source = SourceConfig{
		Mode: SourceModeDirect,
		URL:  "https://example.com/subscription",
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}

func TestValidateAcceptsHelperLaunchMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Network.Mode = RenderModeTun
	cfg.Launch = &LaunchConfig{Mode: LaunchModeHelper}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() returned error: %v", err)
	}
}

func TestDefaultLoggingConfig(t *testing.T) {
	t.Parallel()

	cfg := Default()
	if got, want := cfg.LogLevel(), DefaultLogLevel; got != want {
		t.Fatalf("LogLevel() = %q, want %q", got, want)
	}
	if got, want := cfg.LogMaxLines(), DefaultLogMaxLines; got != want {
		t.Fatalf("LogMaxLines() = %d, want %d", got, want)
	}
}

func TestValidateRejectsUnknownLoggingLevel(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Logging.Level = "chatty"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want logging level error")
	}
	for _, want := range []string{"logging.level", "trace, debug, info, warn, error, fatal, panic", `"logging": {"level": "warn"}`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() error = %q, want substring %q", err, want)
		}
	}
}

func TestValidateRejectsNegativeLoggingMaxLines(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Logging.MaxLines = -1

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() error = nil, want logging max_lines error")
	}
	if !strings.Contains(err.Error(), "logging.max_lines must be >= 0") {
		t.Fatalf("Validate() error = %q, want logging.max_lines", err)
	}
}

func TestSingboxConfigPathPrefersArtifactsPath(t *testing.T) {
	t.Parallel()

	cfg := ProjectConfig{
		Artifacts: ArtifactsConfig{
			SingboxConfigPath: "/tmp/generated/sing-box.json",
		},
		SubscriptionURL: "https://legacy.example.com",
		Render: &RenderConfig{
			OutputPath: "/tmp/generated/legacy.json",
		},
	}

	if got, want := cfg.SingboxConfigPath(), "/tmp/generated/sing-box.json"; got != want {
		t.Fatalf("SingboxConfigPath() = %q, want %q", got, want)
	}
}

func TestEngineDefaultsToSingboxAndDerivesXrayConfigPath(t *testing.T) {
	t.Parallel()

	cfg := ProjectConfig{
		Artifacts: ArtifactsConfig{
			SingboxConfigPath: "/tmp/generated/sing-box_freedom.json",
		},
	}

	if got, want := cfg.EngineType(), EngineSingbox; got != want {
		t.Fatalf("EngineType() = %q, want %q", got, want)
	}
	if got, want := cfg.XrayExecutable(), "xray"; got != want {
		t.Fatalf("XrayExecutable() = %q, want %q", got, want)
	}
	if got, want := cfg.XraySocksListen(), "127.0.0.1"; got != want {
		t.Fatalf("XraySocksListen() = %q, want %q", got, want)
	}
	if got, want := cfg.XraySocksPort(), 20808; got != want {
		t.Fatalf("XraySocksPort() = %d, want %d", got, want)
	}
	if got, want := cfg.XrayConfigPath(), "/tmp/generated/xray_freedom.json"; got != want {
		t.Fatalf("XrayConfigPath() = %q, want %q", got, want)
	}
	if got, want := cfg.XrayProcessNames(), []string{"xray"}; !equalStrings(got, want) {
		t.Fatalf("XrayProcessNames() = %v, want %v", got, want)
	}
}

func TestLoadPreferredSchemaUsesPreferredFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "cache_dir": "/tmp/vless-cache",
  "source": {
    "mode": "proxy",
    "url": "https://example.com/subscription"
  },
  "network": {
    "mode": "tun",
    "tun": {
      "interface_name": "utun233",
      "addresses": ["172.19.0.1/30"]
    }
  },
  "routing": {
    "bypass_suffixes": [".ru"]
  },
  "dns": {
    "proxy_resolver": {
      "address": "1.1.1.1",
      "port": 853,
      "tls_server_name": "cloudflare-dns.com"
    }
  },
  "logging": {
    "level": "INFO",
    "max_lines": 500
  },
  "artifacts": {
    "singbox_config_path": "/tmp/generated/sing-box.json"
  }
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := cfg.NetworkMode(), RenderModeTun; got != want {
		t.Fatalf("NetworkMode() = %q, want %q", got, want)
	}
	if got, want := cfg.SingboxConfigPath(), "/tmp/generated/sing-box.json"; got != want {
		t.Fatalf("SingboxConfigPath() = %q, want %q", got, want)
	}
	if got, want := cfg.TunInterfaceName(), "utun233"; got != want {
		t.Fatalf("TunInterfaceName() = %q, want %q", got, want)
	}
	if got, want := cfg.LogLevel(), "info"; got != want {
		t.Fatalf("LogLevel() = %q, want %q", got, want)
	}
	if got, want := cfg.LogMaxLines(), 500; got != want {
		t.Fatalf("LogMaxLines() = %d, want %d", got, want)
	}
}

func TestSetupWritesPreferredFields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	cfg, err := Setup(path, SetupOptions{
		SourceURL:       "vless://uuid@example.com:443?security=reality#demo",
		ProfileSelector: "demo",
	}, false)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	if got, want := cfg.SourceMode(), SourceModeDirect; got != want {
		t.Fatalf("SourceMode() = %q, want %q", got, want)
	}
	if got, want := cfg.NetworkMode(), RenderModeTun; got != want {
		t.Fatalf("NetworkMode() = %q, want %q", got, want)
	}
	if cfg.Current == nil {
		t.Fatal("Current = nil, want server/profile selection")
	}
	if got, want := cfg.Current.Server, "default"; got != want {
		t.Fatalf("Current.Server = %q, want %q", got, want)
	}
	if got, want := cfg.Current.Profile, "default"; got != want {
		t.Fatalf("Current.Profile = %q, want %q", got, want)
	}
	if cfg.Servers["default"].Profiles["default"].Selector != "demo" {
		t.Fatalf("default profile selector = %q, want demo", cfg.Servers["default"].Profiles["default"].Selector)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := loaded.SourceURL(), "vless://uuid@example.com:443?security=reality#demo"; got != want {
		t.Fatalf("SourceURL() = %q, want %q", got, want)
	}
	if got, want := loaded.DefaultProfileSelector(), "demo"; got != want {
		t.Fatalf("DefaultProfileSelector() = %q, want %q", got, want)
	}
	if got, want := loaded.NetworkMode(), RenderModeTun; got != want {
		t.Fatalf("NetworkMode() = %q, want %q", got, want)
	}
	if got, want := loaded.LogMaxLines(), DefaultLogMaxLines; got != want {
		t.Fatalf("LogMaxLines() = %d, want %d", got, want)
	}
}

func TestEffectiveServerProfileMergesRoutingOverrides(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Current = &CurrentConfig{
		Server:  "fortinetz",
		Profile: "de",
	}
	cfg.Servers = map[string]ServerConfig{
		"fortinetz": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/fortinetz",
			},
			CacheDir: "/tmp/fortinetz-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/fortinetz.json",
			},
			Routing: &RoutingConfig{
				BypassSuffixes: []string{".ru"},
				Routes:         []string{"10.0.0.0/8"},
			},
			Profiles: map[string]ProfileConfig{
				"de": {
					Selector: "Germany",
					Routing: &RoutingConfig{
						BypassExcludes: []string{"t.me"},
						Routes:         []string{"172.16.0.0/12"},
					},
				},
			},
		},
	}

	effective, selection, err := cfg.Effective(SelectionOptions{})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if !selection.UsesServerModel {
		t.Fatal("UsesServerModel = false, want true")
	}
	if got, want := selection.Server, "fortinetz"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "de"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}
	if got, want := effective.SourceURL(), "https://example.com/fortinetz"; got != want {
		t.Fatalf("SourceURL() = %q, want %q", got, want)
	}
	if got, want := effective.CacheDir, "/tmp/fortinetz-cache"; got != want {
		t.Fatalf("CacheDir = %q, want %q", got, want)
	}
	if got, want := effective.SingboxConfigPath(), "/tmp/fortinetz.json"; got != want {
		t.Fatalf("SingboxConfigPath() = %q, want %q", got, want)
	}
	if got, want := effective.DefaultProfileSelector(), "Germany"; got != want {
		t.Fatalf("DefaultProfileSelector() = %q, want %q", got, want)
	}
	if got, want := effective.NormalizedBypassSuffixes(), []string{".ru"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedBypassSuffixes() = %v, want %v", got, want)
	}
	if got, want := effective.NormalizedBypassExcludes(), []string{"t.me"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedBypassExcludes() = %v, want %v", got, want)
	}
	if got, want := effective.NormalizedRoutes(), []string{"172.16.0.0/12"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedRoutes() = %v, want %v", got, want)
	}
}

func TestEffectiveServerProfileMergesSingboxOverrides(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Singbox = &SingboxConfig{
		Sniff: &SniffConfig{
			Enabled: boolPtr(false),
		},
		TLS: TLSClientConfig{
			Fragment:              boolPtr(true),
			FragmentFallbackDelay: "250ms",
			CurvePreferences:      []string{"X25519"},
		},
	}
	cfg.Current = &CurrentConfig{
		Server:  "freedom",
		Profile: "default",
	}
	cfg.Servers = map[string]ServerConfig{
		"freedom": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/freedom",
			},
			CacheDir: "/tmp/freedom-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/freedom.json",
			},
			Singbox: &SingboxConfig{
				Sniff: &SniffConfig{
					Enabled:  boolPtr(true),
					Sniffers: []string{"tls", "http"},
					Timeout:  "1s",
				},
			},
			Profiles: map[string]ProfileConfig{
				"default": {
					Singbox: &SingboxConfig{
						TLS: TLSClientConfig{
							RecordFragment:   boolPtr(true),
							CurvePreferences: []string{"X25519MLKEM768"},
						},
					},
				},
			},
		},
	}

	effective, _, err := cfg.Effective(SelectionOptions{})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if !effective.SniffEnabled() {
		t.Fatal("SniffEnabled() = false, want true")
	}
	if got, want := effective.NormalizedSniffers(), []string{"tls", "http"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedSniffers() = %v, want %v", got, want)
	}
	if got, want := effective.SniffTimeout(), "1s"; got != want {
		t.Fatalf("SniffTimeout() = %q, want %q", got, want)
	}
	tls := effective.TLSOptions()
	if tls.Fragment == nil || !*tls.Fragment {
		t.Fatalf("TLSOptions().Fragment = %#v, want true", tls.Fragment)
	}
	if tls.RecordFragment == nil || !*tls.RecordFragment {
		t.Fatalf("TLSOptions().RecordFragment = %#v, want true", tls.RecordFragment)
	}
	if got, want := tls.FragmentFallbackDelay, "250ms"; got != want {
		t.Fatalf("TLSOptions().FragmentFallbackDelay = %q, want %q", got, want)
	}
	if got, want := effective.NormalizedCurvePreferences(), []string{"X25519MLKEM768"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedCurvePreferences() = %v, want %v", got, want)
	}
}

func TestEffectiveServerProfileMergesEngineOverrides(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Engine = &EngineConfig{
		Type: EngineSingbox,
		Xray: &XrayEngineConfig{
			Executable:   "/opt/bin/root-xray",
			SocksListen:  "127.0.0.1",
			SocksPort:    20808,
			ProcessNames: []string{"root-xray"},
		},
	}
	cfg.Current = &CurrentConfig{
		Server:  "freedom",
		Profile: "default",
	}
	cfg.Servers = map[string]ServerConfig{
		"freedom": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/freedom",
			},
			CacheDir: "/tmp/freedom-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/sing-box_freedom.json",
			},
			Engine: &EngineConfig{
				Type: EngineXray,
				Xray: &XrayEngineConfig{
					Executable: "/opt/homebrew/bin/xray",
				},
			},
			Profiles: map[string]ProfileConfig{
				"default": {
					Engine: &EngineConfig{
						Xray: &XrayEngineConfig{
							SocksPort:    21808,
							ProcessNames: []string{"xray", "xray"},
						},
					},
				},
			},
		},
	}

	effective, _, err := cfg.Effective(SelectionOptions{})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got, want := effective.EngineType(), EngineXray; got != want {
		t.Fatalf("EngineType() = %q, want %q", got, want)
	}
	if got, want := effective.XrayExecutable(), "/opt/homebrew/bin/xray"; got != want {
		t.Fatalf("XrayExecutable() = %q, want %q", got, want)
	}
	if got, want := effective.XraySocksListen(), "127.0.0.1"; got != want {
		t.Fatalf("XraySocksListen() = %q, want %q", got, want)
	}
	if got, want := effective.XraySocksPort(), 21808; got != want {
		t.Fatalf("XraySocksPort() = %d, want %d", got, want)
	}
	if got, want := effective.XrayConfigPath(), "/tmp/xray_freedom.json"; got != want {
		t.Fatalf("XrayConfigPath() = %q, want %q", got, want)
	}
	if got, want := effective.XrayProcessNames(), []string{"xray"}; !equalStrings(got, want) {
		t.Fatalf("XrayProcessNames() = %v, want %v", got, want)
	}
}

func TestEffectiveServerOverrideDoesNotReuseCurrentProfileFromDifferentServer(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Current = &CurrentConfig{
		Server:  "fortinetz",
		Profile: "nl",
	}
	cfg.Servers = map[string]ServerConfig{
		"dance": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/dance",
			},
			CacheDir: "/tmp/dance-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/dance.json",
			},
			Profiles: map[string]ProfileConfig{
				"default": {
					Selector: "Sweden",
				},
			},
		},
		"fortinetz": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/fortinetz",
			},
			CacheDir: "/tmp/fortinetz-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/fortinetz.json",
			},
			Profiles: map[string]ProfileConfig{
				"nl": {
					Selector: "Netherlands",
				},
			},
		},
	}

	effective, selection, err := cfg.Effective(SelectionOptions{Server: "dance"})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got, want := selection.Server, "dance"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "default"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}
	if got, want := effective.DefaultProfileSelector(), "Sweden"; got != want {
		t.Fatalf("DefaultProfileSelector() = %q, want %q", got, want)
	}
}

func TestEffectiveUsesConfiguredProfileTransport(t *testing.T) {
	t.Parallel()

	cfg := multiProfileServerSelectionConfig()
	dance := cfg.Servers["dance"]
	dance.Profiles["default"] = ProfileConfig{
		Transport: "grpc",
	}
	cfg.Servers["dance"] = dance

	effective, selection, err := cfg.Effective(SelectionOptions{Server: "dance"})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got, want := selection.Transport, "grpc"; got != want {
		t.Fatalf("selection.Transport = %q, want %q", got, want)
	}
	if got, want := effective.DefaultProfileTransport(), "grpc"; got != want {
		t.Fatalf("DefaultProfileTransport() = %q, want %q", got, want)
	}
}

func TestEffectiveTransportOverrideWinsOverConfiguredProfileTransport(t *testing.T) {
	t.Parallel()

	cfg := multiProfileServerSelectionConfig()
	dance := cfg.Servers["dance"]
	dance.Profiles["default"] = ProfileConfig{
		Transport: "grpc",
	}
	cfg.Servers["dance"] = dance

	effective, selection, err := cfg.Effective(SelectionOptions{Server: "dance", Transport: "tcp"})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got, want := selection.Transport, "tcp"; got != want {
		t.Fatalf("selection.Transport = %q, want %q", got, want)
	}
	if got, want := effective.DefaultProfileTransport(), "tcp"; got != want {
		t.Fatalf("DefaultProfileTransport() = %q, want %q", got, want)
	}
}

func TestLoadRejectsUnknownProfileTransport(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {"server": "dance", "profile": "default"},
  "servers": {
    "dance": {
      "source": {"mode": "proxy", "url": "https://example.com/dance"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "engine": {"type": "sing-box"},
      "profiles": {"default": {"transport": "grcp"}}
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

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want transport validation error")
	}
	if !strings.Contains(err.Error(), "servers.dance.profiles.default.transport must be one of: tcp, grpc") {
		t.Fatalf("Load() error = %q, want transport validation", err)
	}
}

func TestEffectiveServerOverrideRequiresProfileForMultiProfileByDefault(t *testing.T) {
	t.Parallel()

	cfg := multiProfileServerSelectionConfig()

	_, _, err := cfg.Effective(SelectionOptions{Server: "fortinetz"})
	if err == nil {
		t.Fatal("Effective() error = nil, want profile requirement")
	}
	if !strings.Contains(err.Error(), "current.profile is required") {
		t.Fatalf("Effective() error = %q, want profile requirement", err)
	}
}

func TestEffectiveServerOverrideAllowsMissingProfileForServerLevelCommands(t *testing.T) {
	t.Parallel()

	cfg := multiProfileServerSelectionConfig()

	effective, selection, err := cfg.Effective(SelectionOptions{
		Server:              "fortinetz",
		AllowMissingProfile: true,
	})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got, want := selection.Server, "fortinetz"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if selection.Profile != "" {
		t.Fatalf("selection.Profile = %q, want empty profile for server-level selection", selection.Profile)
	}
	if got, want := effective.CacheDir, "/tmp/fortinetz-cache"; got != want {
		t.Fatalf("CacheDir = %q, want %q", got, want)
	}
	if got, want := effective.SingboxConfigPath(), "/tmp/fortinetz.json"; got != want {
		t.Fatalf("SingboxConfigPath() = %q, want %q", got, want)
	}
	if got := effective.DefaultProfileSelector(); got != "" {
		t.Fatalf("DefaultProfileSelector() = %q, want empty selector", got)
	}
}

func TestSetCurrentUsesDefaultProfileWhenProfileOmitted(t *testing.T) {
	t.Parallel()

	path := writeSetCurrentConfig(t)

	_, selection, resolvedPath, err := SetCurrent(path, SelectionOptions{Server: "dance"})
	if err != nil {
		t.Fatalf("SetCurrent() error = %v", err)
	}
	if resolvedPath != path {
		t.Fatalf("resolvedPath = %q, want %q", resolvedPath, path)
	}
	if got, want := selection.Server, "dance"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "default"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Current == nil {
		t.Fatal("Current = nil")
	}
	if got, want := loaded.Current.Server, "dance"; got != want {
		t.Fatalf("Current.Server = %q, want %q", got, want)
	}
	if got, want := loaded.Current.Profile, "default"; got != want {
		t.Fatalf("Current.Profile = %q, want %q", got, want)
	}
}

func TestLoadRequiresExplicitEngineTypeForEachConfiguredServer(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
  "current": {"server": "dance", "profile": "default"},
  "servers": {
    "dance": {
      "source": {"mode": "proxy", "url": "https://example.com/dance"},
      "cache_dir": "/tmp/vless-dance",
      "artifacts": {"singbox_config_path": "/tmp/dance.json"},
      "profiles": {"default": {"selector": "Sweden"}}
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

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() error = nil, want missing engine error")
	}
	for _, want := range []string{"servers.dance.engine.type is required", "sing-box", "xray", `"engine": { "type": "sing-box" }`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Load() error = %q, want substring %q", err, want)
		}
	}
}

func TestSetCurrentUsesOnlyProfileWhenProfileOmitted(t *testing.T) {
	t.Parallel()

	path := writeSetCurrentConfig(t)

	_, selection, _, err := SetCurrent(path, SelectionOptions{Server: "freedom"})
	if err != nil {
		t.Fatalf("SetCurrent() error = %v", err)
	}
	if got, want := selection.Server, "freedom"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "fr"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}
}

func TestSetCurrentRequiresProfileForMultiProfileServer(t *testing.T) {
	t.Parallel()

	path := writeSetCurrentConfig(t)

	_, _, _, err := SetCurrent(path, SelectionOptions{Server: "fortinetz"})
	if err == nil {
		t.Fatal("SetCurrent() error = nil, want profile required")
	}
	if !strings.Contains(err.Error(), "profile is required") {
		t.Fatalf("SetCurrent() error = %q, want profile required", err)
	}
}

func TestSetCurrentStoresExplicitProfile(t *testing.T) {
	t.Parallel()

	path := writeSetCurrentConfig(t)

	_, selection, _, err := SetCurrent(path, SelectionOptions{Server: "fortinetz", Profile: "de"})
	if err != nil {
		t.Fatalf("SetCurrent() error = %v", err)
	}
	if got, want := selection.Server, "fortinetz"; got != want {
		t.Fatalf("selection.Server = %q, want %q", got, want)
	}
	if got, want := selection.Profile, "de"; got != want {
		t.Fatalf("selection.Profile = %q, want %q", got, want)
	}
}

func equalStrings(got []string, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for idx := range got {
		if got[idx] != want[idx] {
			return false
		}
	}
	return true
}

func boolPtr(value bool) *bool {
	return &value
}

func writeSetCurrentConfig(t *testing.T) string {
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

func multiProfileServerSelectionConfig() ProjectConfig {
	cfg := Default()
	cfg.Current = &CurrentConfig{
		Server:  "dance",
		Profile: "default",
	}
	cfg.Servers = map[string]ServerConfig{
		"dance": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/dance",
			},
			CacheDir: "/tmp/dance-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/dance.json",
			},
			Engine: &EngineConfig{
				Type: EngineSingbox,
			},
			Profiles: map[string]ProfileConfig{
				"default": {
					Selector: "Sweden",
				},
			},
		},
		"fortinetz": {
			Source: SourceConfig{
				Mode: SourceModeProxy,
				URL:  "https://example.com/fortinetz",
			},
			CacheDir: "/tmp/fortinetz-cache",
			Artifacts: &ArtifactsConfig{
				SingboxConfigPath: "/tmp/fortinetz.json",
			},
			Engine: &EngineConfig{
				Type: EngineSingbox,
			},
			Profiles: map[string]ProfileConfig{
				"nl": {
					Selector: "Netherlands",
				},
				"de": {
					Selector: "Germany",
				},
			},
		},
	}
	return cfg
}

func TestValidateRejectsLegacySystemProxyMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Network.Mode = "system_proxy"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}
