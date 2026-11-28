package config

import (
	"encoding/json"
	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAmneziaSourceValidation(t *testing.T) {
	for _, tc := range []struct {
		name, mode, sourceURL, legacyURL string
		keychain                         *SourceKeychainConfig
		want                             string
	}{
		{name: "defaults", mode: SourceModeAmnezia},
		{name: "custom names", mode: SourceModeAmnezia, keychain: &SourceKeychainConfig{Service: "test-service", FallbackService: "test-fallback", Account: "test/key"}},
		{name: "plaintext", mode: SourceModeAmnezia, sourceURL: "vpn://synthetic-secret", want: "macOS Keychain"},
		{name: "legacy plaintext", mode: SourceModeAmnezia, legacyURL: "synthetic-secret", want: "macOS Keychain"},
		{name: "service control", mode: SourceModeAmnezia, keychain: &SourceKeychainConfig{Service: "bad\nname"}, want: "control characters"},
		{name: "fallback control", mode: SourceModeAmnezia, keychain: &SourceKeychainConfig{FallbackService: "bad\x00name"}, want: "control characters"},
		{name: "account control", mode: SourceModeAmnezia, keychain: &SourceKeychainConfig{Account: "bad\u0085name"}, want: "control characters"},
		{name: "proxy keychain", mode: SourceModeProxy, sourceURL: "https://example.com/sub", keychain: &SourceKeychainConfig{}, want: "only supported"},
		{name: "direct keychain", mode: SourceModeDirect, sourceURL: "vless://id@example.com:443", keychain: &SourceKeychainConfig{}, want: "only supported"},
		{name: "proxy missing URL", mode: SourceModeProxy, want: "source.url is required"},
		{name: "direct missing URL", mode: SourceModeDirect, want: "source.url is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Source = SourceConfig{Mode: tc.mode, URL: tc.sourceURL, Keychain: tc.keychain}
			cfg.SubscriptionURL = tc.legacyURL
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("validation disclosed plaintext credential")
			}
		})
	}
}

func TestSourceKeychainStrictJSON(t *testing.T) {
	for _, raw := range []string{
		`{"source":{"mode":"amnezia","keychain":{"secret":"forbidden"}}}`,
		`{"servers":{"test":{"source":{"mode":"amnezia","keychain":{"unknown":true}}}}}`,
		`{"source":{"keychain":{"service":42}}}`,
	} {
		var cfg ProjectConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err == nil {
			t.Fatalf("invalid keychain document was accepted: %s", raw)
		}
	}
	var cfg ProjectConfig
	if err := json.Unmarshal([]byte(`{"source":{"mode":"amnezia","keychain":{"service":"test","fallback_service":"fallback","account":"test/key"}}}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.SourceKeychain(); got != (SourceKeychainConfig{Service: "test", FallbackService: "fallback", Account: "test/key"}) {
		t.Fatalf("keychain = %+v", got)
	}
	if got := (ProjectConfig{}).SourceKeychain(); got != (SourceKeychainConfig{Service: "tun-wave", FallbackService: "multi-tun", Account: "amnezia/key"}) {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestMergeSourceKeychainCopiesAndInherits(t *testing.T) {
	base := SourceConfig{Keychain: &SourceKeychainConfig{Service: "base", FallbackService: "fallback", Account: "base/key"}}
	override := SourceConfig{Keychain: &SourceKeychainConfig{Account: "override/key"}}
	merged := mergeSourceConfig(base, override)
	if *merged.Keychain != (SourceKeychainConfig{Service: "base", FallbackService: "fallback", Account: "override/key"}) {
		t.Fatalf("merged = %+v", merged.Keychain)
	}
	merged.Keychain.Service = "mutated"
	merged.Keychain.Account = "mutated"
	if base.Keychain.Service != "base" || override.Keychain.Account != "override/key" {
		t.Fatal("merge aliases input metadata")
	}
	for _, pair := range [][2]SourceConfig{{base, {}}, {{}, override}} {
		merged := mergeSourceConfig(pair[0], pair[1])
		if merged.Keychain == pair[0].Keychain || merged.Keychain == pair[1].Keychain {
			t.Fatal("single-sided merge aliases input metadata")
		}
	}
	cfg := Default()
	cfg.Source = base
	cfg.Source.Mode, cfg.Source.URL = SourceModeAmnezia, ""
	cfg.Servers = map[string]ServerConfig{"test": {Source: override}}
	if got := cfg.SourceKeychain(); got.Service != "base" || got.Account != "override/key" {
		t.Fatalf("effective metadata = %+v", got)
	}
}

func TestSetupAmneziaRoundTrip(t *testing.T) {
	for _, selector := range []string{"", "chosen"} {
		t.Run("selector-"+selector, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			cfg, err := Setup(path, SetupOptions{SourceMode: SourceModeAmnezia, ProfileSelector: selector}, false)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Current.Server != "amnezia" || cfg.Current.Profile != "us" {
				t.Fatalf("current = %+v", cfg.Current)
			}
			loaded, err := Load(path)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			for _, candidate := range []ProjectConfig{cfg, loaded} {
				if candidate.SourceMode() != SourceModeAmnezia || candidate.SourceURL() != "" {
					t.Fatal("Amnezia source inherited a URL")
				}
				_, selection, err := candidate.Effective(SelectionOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if selector == "" {
					if selection.Match == nil || selection.Match.Country != "US" || selection.Pick != "probe" || selection.Selector != "" {
						t.Fatalf("selection = %+v", selection)
					}
				} else if selection.Selector != selector || selection.Match != nil || selection.Pick != "" {
					t.Fatalf("selection = %+v", selection)
				}
			}
		})
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := Setup(path, SetupOptions{SourceMode: SourceModeAmnezia, SourceURL: "vpn://synthetic"}, false); err == nil {
		t.Fatal("setup accepted plaintext key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("refused setup wrote a config")
	}
	cfg, err := Setup(path, SetupOptions{SourceMode: SourceModeAmnezia, ServerName: "custom", ConfigProfile: "region"}, false)
	if err != nil || cfg.Current.Server != "custom" || cfg.Current.Profile != "region" {
		t.Fatalf("custom setup error = %v", err)
	}
}

func TestLoadFlatAmneziaDoesNotInheritTemplateURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"source":{"mode":"amnezia"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.SourceURL() != "" {
		t.Fatalf("Load() URL = %q, error = %v", cfg.SourceURL(), err)
	}
	if err := os.WriteFile(path, []byte(`{"source":{"mode":"amnezia","url":"vpn://synthetic"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted explicit plaintext URL")
	}
}

func TestAmneziaConfigPathPrecedence(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(root, "cache"))
	t.Setenv(EnvConfigPath, "")
	t.Setenv(LegacyEnvConfigPath, "")
	t.Chdir(root)
	canonical := filepath.Join(root, "config", "tun-wave", "config.json")
	legacy := filepath.Join(root, "config", "vless-tun", "config.json")
	local := filepath.Join(root, "configs", "local.json")
	if DefaultPath() != canonical || LegacyGlobalConfigPath() != legacy || ResolveInitPath("") != canonical {
		t.Fatal("unexpected default config paths")
	}
	assertPath := func(want string) {
		t.Helper()
		got, err := ResolveLoadPath("")
		if err != nil || got != want {
			t.Fatalf("ResolveLoadPath() = %q, %v, want %q", got, err, want)
		}
	}
	write := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertPath(canonical)
	write(local)
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(nested)
	assertPath(local)
	write(legacy)
	assertPath(legacy)
	write(canonical)
	assertPath(canonical)
	t.Setenv(LegacyEnvConfigPath, "legacy-env.json")
	assertPath(filepath.Join(nested, "legacy-env.json"))
	t.Setenv(EnvConfigPath, "canonical-env.json")
	assertPath(filepath.Join(nested, "canonical-env.json"))
	if got, err := ResolveLoadPath("explicit.json"); err != nil || got != filepath.Join(nested, "explicit.json") {
		t.Fatalf("explicit path = %q, %v", got, err)
	}
	for path, dir := range map[string]string{canonical: "tun-wave", legacy: "vless-tun"} {
		cfg := DefaultForPath(path)
		if cfg.CacheDir != filepath.Join(root, "cache", dir) || cfg.Artifacts.SingboxConfigPath != filepath.Join(filepath.Dir(path), "generated", "sing-box.json") {
			t.Fatalf("global defaults for %s = %+v", path, cfg.Artifacts)
		}
	}
}

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
    "bypass_suffixes": [".ru"],
    "routes": ["198.51.100.7/32"],
    "route_descriptions": {
      "198.51.100.7/32": "Dedicated SSH egress"
    }
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
	if got, want := cfg.Routing.RouteDescriptions["198.51.100.7/32"], "Dedicated SSH egress"; got != want {
		t.Fatalf("Routing.RouteDescriptions = %q, want %q", got, want)
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

func TestEffectiveServerProfileMergesRoutingBypasses(t *testing.T) {
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
				BypassSuffixes: []string{".ru", ".server.example"},
				Routes:         []string{"10.0.0.0/8"},
			},
			Profiles: map[string]ProfileConfig{
				"de": {
					Selector: "Germany",
					Routing: &RoutingConfig{
						BypassSuffixes: []string{"profile.example", ".SERVER.EXAMPLE"},
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
	if got, want := effective.NormalizedBypassSuffixes(), []string{".ru", ".xn--p1ai", ".server.example", "profile.example"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedBypassSuffixes() = %v, want %v", got, want)
	}
	if got, want := effective.NormalizedBypassExcludes(), []string{"t.me"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedBypassExcludes() = %v, want %v", got, want)
	}
	if got, want := effective.NormalizedRoutes(), []string{"172.16.0.0/12"}; !equalStrings(got, want) {
		t.Fatalf("NormalizedRoutes() = %v, want %v", got, want)
	}
}

func TestEffectiveServerProfileAllowsExplicitEmptyBypassesForFullTunnel(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Current = &CurrentConfig{Server: "dance", Profile: "default"}
	cfg.Servers = map[string]ServerConfig{
		"dance": {
			Source:  SourceConfig{Mode: SourceModeProxy, URL: "https://example.com/dance"},
			Routing: &RoutingConfig{BypassSuffixes: []string{"server.example"}},
			Profiles: map[string]ProfileConfig{
				"default": {
					Routing: &RoutingConfig{BypassSuffixes: []string{}},
				},
			},
		},
	}

	effective, _, err := cfg.Effective(SelectionOptions{})
	if err != nil {
		t.Fatalf("Effective() error = %v", err)
	}
	if got := effective.NormalizedBypassSuffixes(); len(got) != 0 {
		t.Fatalf("NormalizedBypassSuffixes() = %v, want explicit full-tunnel reset", got)
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

// Match configuration accepts a non-empty criterion but rejects selector conflicts and empty match objects.
func TestValidateProfileMatchRequiresExclusiveNonEmptyCriteria(t *testing.T) {
	makeConfig := func(profile ProfileConfig) ProjectConfig {
		cfg := multiProfileServerSelectionConfig()
		server := cfg.Servers["dance"]
		server.Profiles["default"] = profile
		cfg.Servers["dance"] = server
		return cfg
	}

	valid := makeConfig(ProfileConfig{Match: &ProfileMatch{Country: "us"}, Pick: "probe"})
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid match Validate() error = %v", err)
	}
	_, selection, err := valid.Effective(SelectionOptions{})
	if err != nil || selection.Match == nil || selection.Match.Country != "us" || selection.Pick != "probe" {
		t.Fatalf("Effective() selection = %+v, error = %v, want propagated match/pick", selection, err)
	}

	conflicting := makeConfig(ProfileConfig{Selector: "USA", Match: &ProfileMatch{Country: "US"}})
	if err := conflicting.Validate(); err == nil || !strings.Contains(err.Error(), "match and") {
		t.Fatalf("conflicting Validate() error = %v, want match/selector conflict", err)
	}

	empty := makeConfig(ProfileConfig{Match: &ProfileMatch{}})
	if err := empty.Validate(); err == nil || !strings.Contains(err.Error(), "must set at least one") {
		t.Fatalf("empty Validate() error = %v, want non-empty match error", err)
	}

	invalidCountry := makeConfig(ProfileConfig{Match: &ProfileMatch{Country: "ZZ"}})
	if err := invalidCountry.Validate(); err == nil || !strings.Contains(err.Error(), "assigned ISO 3166-1") {
		t.Fatalf("invalid-country Validate() error = %v, want assigned ISO code error", err)
	}
}

// Claim: each supported TUN stack and the empty default validate, and TunStack trims whitespace.
func TestValidateAcceptsSupportedTunStacks(t *testing.T) {
	t.Parallel()

	for _, stack := range []string{"", "system", "gvisor", "mixed", " gvisor "} {
		cfg := Default()
		cfg.Network.Mode = RenderModeTun
		cfg.Network.TUN.Stack = stack
		if err := cfg.Validate(); err != nil {
			t.Fatalf("stack %q: Validate() error = %v", stack, err)
		}
		if got, want := cfg.TunStack(), strings.TrimSpace(stack); got != want {
			t.Fatalf("TunStack() = %q, want %q", got, want)
		}
	}
}

// Claim: an unknown or differently cased stack is refused with a message naming the field and
// the accepted values, instead of being passed to sing-box.
func TestValidateRejectsUnknownTunStack(t *testing.T) {
	t.Parallel()

	for _, stack := range []string{"lwip", "GVISOR", "system,gvisor"} {
		cfg := Default()
		cfg.Network.Mode = RenderModeTun
		cfg.Network.TUN.Stack = stack
		err := cfg.Validate()
		if err == nil {
			t.Fatalf("stack %q: Validate() error = nil", stack)
		}
		for _, want := range []string{"network.tun.stack", "system, gvisor, mixed"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("stack %q: error %q lacks %q", stack, err, want)
			}
		}
	}
}

func TestMergeSourceConfigIsolatesAmneziaAndProxyFields(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Source = SourceConfig{
		Mode: SourceModeProxy,
		URL:  "https://example.com/base-subscription",
	}
	cfg.Current = &CurrentConfig{Server: "amnezia", Profile: "us"}
	cfg.Servers = map[string]ServerConfig{
		"amnezia": {
			Source: SourceConfig{Mode: SourceModeAmnezia},
			Engine: &EngineConfig{Type: EngineSingbox},
			Profiles: map[string]ProfileConfig{
				"us": DefaultAmneziaUSProfile(),
			},
		},
		"phantombot": {
			Source: SourceConfig{Mode: SourceModeProxy, URL: "https://example.com/phantombot"},
			Engine: &EngineConfig{Type: EngineSingbox},
			Profiles: map[string]ProfileConfig{
				"us": DefaultAmneziaUSProfile(),
			},
		},
	}

	effective, _, err := cfg.Effective(SelectionOptions{Server: "amnezia", Profile: "us"})
	if err != nil {
		t.Fatalf("Effective(amnezia) error = %v", err)
	}
	if err := effective.Validate(); err != nil {
		t.Fatalf("Validate(amnezia) error = %v", err)
	}
	if effective.SourceURL() != "" {
		t.Fatalf("effective.SourceURL() = %q, want empty for amnezia server", effective.SourceURL())
	}

	cfg.Source = SourceConfig{
		Mode:     SourceModeAmnezia,
		Keychain: &SourceKeychainConfig{Service: "tun-wave", Account: "amnezia/key"},
	}
	effectiveProxy, _, err := cfg.Effective(SelectionOptions{Server: "phantombot", Profile: "us"})
	if err != nil {
		t.Fatalf("Effective(phantombot) error = %v", err)
	}
	if err := effectiveProxy.Validate(); err != nil {
		t.Fatalf("Validate(phantombot) error = %v", err)
	}
	if effectiveProxy.Source.Keychain != nil {
		t.Fatalf("effectiveProxy.Source.Keychain = %+v, want nil for proxy server", effectiveProxy.Source.Keychain)
	}
}

func TestAWGEngineDefaultsAndArtifacts(t *testing.T) {
	cfg := Default()
	cfg.Engine = &EngineConfig{Type: EngineAWG}
	cfg.Source = SourceConfig{Mode: SourceModeAmnezia}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.EngineType() != EngineAWG || cfg.AWGSocksListen() != "127.0.0.1" || cfg.AWGSocksPort() != 20809 || cfg.AWGMTU() != 1280 {
		t.Fatal("incorrect AWG defaults")
	}
	if got := strings.Join(cfg.AWGProcessNames(), ","); got != "tun-wave,vless-tun" {
		t.Fatalf("process names = %s", got)
	}
	for _, tc := range []struct{ input, want string }{{"/tmp/sing-box.json", "/tmp/awg.json"}, {"/tmp/singbox-us.json", "/tmp/awg-us.json"}, {"/tmp/frontend.json", "/tmp/frontend-awg.json"}} {
		cfg.Artifacts.SingboxConfigPath = tc.input
		if got := cfg.AWGConfigPath(); got != tc.want {
			t.Fatalf("AWGConfigPath = %s, want %s", got, tc.want)
		}
	}
	cfg.Artifacts.AWGConfigPath = "custom/awg.json"
	cfg.resolveRelativePaths("/tmp/config")
	if cfg.AWGConfigPath() != "/tmp/config/custom/awg.json" {
		t.Fatal("relative AWG path not resolved")
	}
}

func TestAWGEngineMergingAndCloneIsolation(t *testing.T) {
	base := &EngineConfig{Type: EngineAWG, AWG: &AWGEngineConfig{SocksListen: "127.0.0.1", SocksPort: 21809, MTU: 1400, ProcessNames: []string{"base"}}}
	override := &EngineConfig{AWG: &AWGEngineConfig{SocksListen: "::1", SocksPort: 22809, MTU: 1280, ProcessNames: []string{"custom"}}}
	merged := mergeEngineConfig(base, override)
	cfg := Default()
	cfg.Engine = merged
	if cfg.AWGSocksListen() != "::1" || cfg.AWGSocksPort() != 22809 || cfg.AWGMTU() != 1280 || strings.Join(cfg.AWGProcessNames(), ",") != "custom" {
		t.Fatal("AWG overrides not merged")
	}
	merged.AWG.ProcessNames[0] = "mutated"
	if base.AWG.ProcessNames[0] != "base" || override.AWG.ProcessNames[0] != "custom" {
		t.Fatal("merge aliases input process names")
	}
	inherited := mergeEngineConfig(base, &EngineConfig{AWG: &AWGEngineConfig{}})
	if inherited.AWG.SocksPort != 21809 || inherited.AWG.MTU != 1400 {
		t.Fatal("zero overrides erased inherited values")
	}
	cloned := cloneEngineConfig(base)
	cloned.AWG.ProcessNames[0] = "changed"
	if base.AWG.ProcessNames[0] != "base" {
		t.Fatal("clone aliases process names")
	}
	artifacts := mergeArtifactsConfig(ArtifactsConfig{AWGConfigPath: "base.json"}, &ArtifactsConfig{AWGConfigPath: "override.json"})
	if artifacts.AWGConfigPath != "override.json" {
		t.Fatal("artifact override lost")
	}
	if got := mergeArtifactsConfig(artifacts, &ArtifactsConfig{}); got.AWGConfigPath != "override.json" {
		t.Fatal("empty artifact override erased path")
	}
	// Invalid nonzero overrides must survive merging so validation can refuse them.
	invalid := mergeEngineConfig(base, &EngineConfig{AWG: &AWGEngineConfig{SocksPort: -1, MTU: -1}})
	if invalid.AWG.SocksPort != -1 || invalid.AWG.MTU != -1 {
		t.Fatal("merge silently repaired invalid settings")
	}
}

func TestAWGEngineValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value AWGEngineConfig
		valid bool
	}{
		{"defaults", AWGEngineConfig{}, true}, {"IPv6", AWGEngineConfig{SocksListen: "::1", SocksPort: 65535, MTU: 576}, true},
		{"wildcard", AWGEngineConfig{SocksListen: "0.0.0.0"}, false}, {"LAN", AWGEngineConfig{SocksListen: "192.168.1.1"}, false},
		{"IPv6 wildcard", AWGEngineConfig{SocksListen: "::"}, false}, {"hostname", AWGEngineConfig{SocksListen: "localhost"}, false},
		{"negative port", AWGEngineConfig{SocksPort: -1}, false}, {"large port", AWGEngineConfig{SocksPort: 65536}, false},
		{"small MTU", AWGEngineConfig{MTU: 575}, false}, {"large MTU", AWGEngineConfig{MTU: 65536}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Source = SourceConfig{Mode: SourceModeAmnezia}
			cfg.Engine = &EngineConfig{Type: EngineAWG, AWG: &tc.value}
			err := cfg.Validate()
			if (err == nil) != tc.valid {
				t.Fatalf("Validate = %v, valid=%v", err, tc.valid)
			}
		})
	}
	cfg := Default()
	cfg.Servers = map[string]ServerConfig{"synthetic": {Engine: &EngineConfig{Type: EngineAWG}, Artifacts: &ArtifactsConfig{AWGConfigPath: "awg.json"}}}
	if err := cfg.validateExplicitServerEngines(); err != nil {
		t.Fatal(err)
	}
	cfg.resolveRelativePaths("/tmp/config")
	if cfg.Servers["synthetic"].Artifacts.AWGConfigPath != "/tmp/config/awg.json" {
		t.Fatal("server AWG artifact path not resolved")
	}
	cfg.Servers["synthetic"].Engine.AWG = &AWGEngineConfig{SocksListen: "0.0.0.0"}
	if err := cfg.validateExplicitServerEngines(); err == nil {
		t.Fatal("server non-loopback settings admitted")
	}
}

func unifiedConfigFixture() ProjectConfig {
	cfg := Default()
	cfg.Current = &CurrentConfig{Server: "amnezia", Profile: "us"}
	cfg.Servers = map[string]ServerConfig{
		"amnezia": {Engine: &EngineConfig{Type: EngineVLESSReality}, Source: SourceConfig{Mode: SourceModeDirect, URL: "vless://id@203.0.113.2:443"}, Profiles: map[string]ProfileConfig{"us": {Selector: "US"}, "de": {Selector: "DE"}}},
		"mts":     {Engine: &EngineConfig{Type: EngineOpenConnect}, Source: SourceConfig{Mode: SourceModeOpenConnect}, OpenConnect: &OpenConnectServerConfig{ServerURL: "https://vpn.example", PAC: &openconnectcfg.PACConfig{Rewrites: []openconnectcfg.PACRewriteRule{{Host: "mybonus.mts.ru", Return: "DIRECT"}}}}, Profiles: map[string]ProfileConfig{"outside": {OpenConnect: &OpenConnectProfileConfig{Name: "Native Outside", Mode: "split-include"}}}},
	}
	return cfg
}
func TestUnifiedStackConfigValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stack []string
		bad   bool
	}{{"single", []string{"amnezia/us"}, false}, {"dual", []string{"mts/outside", "amnezia/us"}, false}, {"server", []string{"mts"}, false}, {"duplicate", []string{"amnezia/us", "amnezia/de"}, true}, {"unknown", []string{"unknown/us"}, true}, {"unknown profile", []string{"amnezia/missing"}, true}, {"empty", []string{""}, true}, {"space", []string{" "}, true}, {"control", []string{"mts/outside\n"}, true}, {"bad separator", []string{"mts//outside"}, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := unifiedConfigFixture()
			cfg.Stack = tc.stack
			cfg.OpenConnectConfigPath = "/tmp/legacy.json"
			err := cfg.Validate()
			if (err != nil) != tc.bad {
				t.Fatalf("Validate %v: %v", tc.stack, err)
			}
		})
	}
}
func TestUnifiedMixedServerEffectiveAndEngineLabels(t *testing.T) {
	cfg := unifiedConfigFixture()
	for _, current := range []CurrentConfig{{Server: "amnezia", Profile: "us"}, {Server: "mts", Profile: "outside"}} {
		cfg.Current = &current
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		effective, selection, err := cfg.Effective(SelectionOptions{})
		if err != nil || selection.Server != current.Server {
			t.Fatalf("Effective: %+v %v", selection, err)
		}
		if current.Server == "mts" {
			if effective.EngineType() != EngineOpenConnect || effective.SourceMode() != SourceModeOpenConnect || effective.OpenConnect == nil || effective.OpenConnect.ServerURL == "" {
				t.Fatalf("bad OC effective: %+v", effective)
			}
		} else if effective.EngineType() != EngineSingbox {
			t.Fatalf("alias was not normalized: %s", effective.EngineType())
		}
	}
	for _, engine := range []string{EngineVLESS, EngineVLESSReality} {
		cfg := unifiedConfigFixture()
		srv := cfg.Servers["amnezia"]
		srv.Engine.Type = engine
		cfg.Servers["amnezia"] = srv
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		if cfg.EngineType() != EngineSingbox || cfg.Servers["amnezia"].Engine.Type != engine {
			t.Fatal("normalization lost the provider label")
		}
	}
	// Every server is validated even when a different server is current.
	cfg = unifiedConfigFixture()
	srv := cfg.Servers["mts"]
	srv.OpenConnect.PAC.Rewrites[0].Return = "DIRECT; evil()"
	cfg.Servers["mts"] = srv
	if err := cfg.Validate(); err == nil {
		t.Fatal("inactive server's unsafe PAC was ignored")
	}
}
func TestUnifiedOpenConnectRelativePaths(t *testing.T) {
	dir := t.TempDir()
	cfg := unifiedConfigFixture()
	cfg.OpenConnectConfigPath = "legacy.json"
	srv := cfg.Servers["mts"]
	srv.OpenConnect.CacheDir = "cache/overlay"
	srv.OpenConnect.PAC = &openconnectcfg.PACConfig{File: "server.pac"}
	srv.Profiles["outside"] = ProfileConfig{OpenConnect: &OpenConnectProfileConfig{PAC: &openconnectcfg.PACConfig{File: "profile.pac"}}}
	cfg.Servers["mts"] = srv
	cfg.resolveRelativePaths(dir)
	got := cfg.Servers["mts"]
	if cfg.OpenConnectConfigPath != filepath.Join(dir, "legacy.json") || got.OpenConnect.CacheDir != filepath.Join(dir, "cache/overlay") || got.OpenConnect.PAC.File != filepath.Join(dir, "server.pac") || got.Profiles["outside"].OpenConnect.PAC.File != filepath.Join(dir, "profile.pac") {
		t.Fatal("relative OpenConnect paths unresolved")
	}
}
func TestUnifiedSourceAuthValidation(t *testing.T) {
	for _, mode := range []string{SourceModeDirect, SourceModeProxy, SourceModeAmnezia} {
		for _, tc := range []struct {
			auth SourceAuthConfig
			bad  bool
		}{{SourceAuthConfig{Mode: "keychain", Record: "sample/key"}, false}, {SourceAuthConfig{Mode: "file", Path: "/tmp/secret"}, false}, {SourceAuthConfig{Mode: "keychain"}, true}, {SourceAuthConfig{Mode: "file"}, true}, {SourceAuthConfig{Mode: "unknown", Record: "sample/key"}, true}, {SourceAuthConfig{Mode: "keychain", Record: "bad\nrecord"}, true}} {
			cfg := Default()
			cfg.Source = SourceConfig{Mode: mode, Auth: &tc.auth}
			cfg.SubscriptionURL = ""
			if err := cfg.Validate(); (err != nil) != tc.bad {
				t.Fatalf("mode=%s auth=%+v err=%v", mode, tc.auth, err)
			}
		}
	}
}

func TestConfiguredStackDoesNotRequireCurrentSelection(t *testing.T) {
	cfg := unifiedConfigFixture()
	cfg.Current = nil
	cfg.Stack = []string{"mts/outside", "amnezia/us"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("stack without legacy current selection: %v", err)
	}
	effective, sel, err := cfg.Effective(SelectionOptions{})
	if err != nil || sel.Server != "mts" || sel.Profile != "outside" || effective.EngineType() != EngineOpenConnect {
		t.Fatalf("effective stack default %+v %v", sel, err)
	}
}
