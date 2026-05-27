package config

import (
	"os"
	"path/filepath"
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
    "level": "info"
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

func TestValidateRejectsLegacySystemProxyMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Network.Mode = "system_proxy"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}
