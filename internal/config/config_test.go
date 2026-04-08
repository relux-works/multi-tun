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
	if cfg.Default == nil {
		t.Fatal("Default = nil, want profile selector")
	}
	if got, want := cfg.Default.ProfileSelector, "demo"; got != want {
		t.Fatalf("Default.ProfileSelector = %q, want %q", got, want)
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

func TestValidateRejectsLegacySystemProxyMode(t *testing.T) {
	t.Parallel()

	cfg := Default()
	cfg.Network.Mode = "system_proxy"

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() returned nil error")
	}
}
