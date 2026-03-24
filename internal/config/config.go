package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const legacyRepoConfigPath = "configs/local.json"

const (
	RenderModeTun         = "tun"
	RenderModeSystemProxy = "system_proxy"

	LaunchModeAuto    = "auto"
	LaunchModeSudo    = "sudo"
	LaunchModeDirect  = "direct"
	LaunchModeLaunchd = "launchd"

	defaultLaunchdLabel     = "works.relux.vless-tun"
	defaultLaunchdPlistPath = "/Library/LaunchDaemons/works.relux.vless-tun.plist"
)

type ProjectConfig struct {
	SubscriptionURL string       `json:"subscription_url"`
	SelectedProfile string       `json:"selected_profile"`
	CacheDir        string       `json:"cache_dir"`
	Render          RenderConfig `json:"render"`
}

type RenderConfig struct {
	Mode               string                  `json:"mode"`
	OutputPath         string                  `json:"output_path"`
	InterfaceName      string                  `json:"interface_name"`
	TunAddresses       []string                `json:"tun_addresses"`
	ProxyListenAddress string                  `json:"proxy_listen_address"`
	ProxyListenPort    int                     `json:"proxy_listen_port"`
	LogLevel           string                  `json:"log_level"`
	BypassSuffixes     []string                `json:"bypass_suffixes"`
	BypassExcludes     []string                `json:"bypass_exclude_suffixes"`
	ProxyDNS           ProxyDNSConfig          `json:"proxy_dns"`
	PrivilegedLaunch   *PrivilegedLaunchConfig `json:"privileged_launch,omitempty"`
}

type ProxyDNSConfig struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	TLSServerName string `json:"tls_server_name"`
}

type PrivilegedLaunchConfig struct {
	Mode      string `json:"mode,omitempty"`
	Label     string `json:"label,omitempty"`
	PlistPath string `json:"plist_path,omitempty"`
}

func DefaultPath() string {
	if dir := userConfigRoot(); dir != "" {
		return filepath.Join(dir, "vless-tun", "config.json")
	}
	return legacyRepoConfigPath
}

func LegacyRepoConfigPath() string {
	return legacyRepoConfigPath
}

func DefaultForPath(path string) ProjectConfig {
	cfg := ProjectConfig{
		SubscriptionURL: "https://key.vpn.dance/connect?key=REPLACE_ME",
		SelectedProfile: "",
		CacheDir:        ".cache/vpn-config",
		Render: RenderConfig{
			Mode:          defaultRenderMode(),
			OutputPath:    "configs/generated/dancevpn-sing-box.json",
			InterfaceName: "utun233",
			TunAddresses: []string{
				"172.19.0.1/30",
				"fdfe:dcba:9876::1/126",
			},
			ProxyListenAddress: "127.0.0.1",
			ProxyListenPort:    2080,
			LogLevel:           "info",
			BypassSuffixes: []string{
				".ru",
				".рф",
			},
			BypassExcludes: []string{
				".telegram.org",
				"t.me",
				".telegram.me",
				".telegra.ph",
				".telesco.pe",
			},
			ProxyDNS: ProxyDNSConfig{
				Address:       "1.1.1.1",
				Port:          853,
				TLSServerName: "cloudflare-dns.com",
			},
		},
	}

	if absPath, err := filepath.Abs(path); err == nil && absPath == defaultPathAbs() {
		if cacheDir := userCacheRoot(); cacheDir != "" {
			cfg.CacheDir = filepath.Join(cacheDir, "vless-tun")
		}
		cfg.Render.OutputPath = filepath.Join(filepath.Dir(absPath), "generated", "dancevpn-sing-box.json")
	}

	return cfg
}

func Default() ProjectConfig {
	return DefaultForPath(legacyRepoConfigPath)
}

func Load(path string) (ProjectConfig, error) {
	resolvedPath, err := ResolveLoadPath(path)
	if err != nil {
		return ProjectConfig{}, err
	}

	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		return ProjectConfig{}, err
	}

	cfg := DefaultForPath(resolvedPath)
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return ProjectConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return ProjectConfig{}, err
	}
	cfg.resolveRelativePaths(filepath.Dir(resolvedPath))
	return cfg, nil
}

func Init(path, subscriptionURL string, force bool) (ProjectConfig, error) {
	path = ResolveInitPath(path)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ProjectConfig{}, errors.New("config already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return ProjectConfig{}, err
		}
	}

	cfg := DefaultForPath(path)
	if subscriptionURL != "" {
		cfg.SubscriptionURL = subscriptionURL
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ProjectConfig{}, err
	}
	if err := writeJSON(path, cfg); err != nil {
		return ProjectConfig{}, err
	}
	return cfg, nil
}

func ResolveLoadPath(path string) (string, error) {
	if path != "" {
		return filepath.Abs(path)
	}

	if envPath := os.Getenv("VLESS_TUN_CONFIG"); envPath != "" {
		return filepath.Abs(envPath)
	}

	globalPath := ResolveInitPath("")
	if _, err := os.Stat(globalPath); err == nil {
		return globalPath, nil
	}

	if legacyPath, ok := findUpward(legacyRepoConfigPath); ok {
		return legacyPath, nil
	}

	return globalPath, nil
}

func ResolveInitPath(path string) string {
	if path != "" {
		if abs, err := filepath.Abs(path); err == nil {
			return abs
		}
		return path
	}
	return defaultPathAbs()
}

func (c ProjectConfig) Validate() error {
	if c.SubscriptionURL == "" {
		return errors.New("subscription_url is required")
	}
	if c.CacheDir == "" {
		return errors.New("cache_dir is required")
	}
	if c.Render.OutputPath == "" {
		return errors.New("render.output_path is required")
	}
	if c.Render.ProxyDNS.Address == "" {
		return errors.New("render.proxy_dns.address is required")
	}
	if c.Render.ProxyDNS.Port <= 0 {
		return errors.New("render.proxy_dns.port must be positive")
	}
	if c.Render.ProxyDNS.TLSServerName == "" {
		return errors.New("render.proxy_dns.tls_server_name is required")
	}
	switch c.Render.ModeOrDefault() {
	case RenderModeTun:
		if c.Render.InterfaceName == "" {
			return errors.New("render.interface_name is required in tun mode")
		}
		if len(c.Render.TunAddresses) == 0 {
			return errors.New("render.tun_addresses is required in tun mode")
		}
	case RenderModeSystemProxy:
		if c.Render.ProxyListenAddress == "" {
			return errors.New("render.proxy_listen_address is required in system_proxy mode")
		}
		if c.Render.ProxyListenPort <= 0 {
			return errors.New("render.proxy_listen_port must be positive in system_proxy mode")
		}
	default:
		return errors.New("render.mode must be one of: tun, system_proxy")
	}

	switch c.Render.PrivilegedLaunchOrDefault().Mode {
	case LaunchModeAuto, LaunchModeSudo, LaunchModeDirect, LaunchModeLaunchd:
	default:
		return errors.New("render.privileged_launch.mode must be one of: auto, sudo, direct, launchd")
	}
	return nil
}

func (c *ProjectConfig) resolveRelativePaths(baseDir string) {
	if !filepath.IsAbs(c.CacheDir) {
		c.CacheDir = filepath.Join(baseDir, c.CacheDir)
	}
	if !filepath.IsAbs(c.Render.OutputPath) {
		c.Render.OutputPath = filepath.Join(baseDir, c.Render.OutputPath)
	}
}

func (c RenderConfig) NormalizedBypassSuffixes() []string {
	return normalizeSuffixes(c.BypassSuffixes)
}

func (c RenderConfig) NormalizedBypassExcludes() []string {
	return normalizeSuffixes(c.BypassExcludes)
}

func normalizeSuffixes(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := normalizeSuffix(raw)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeSuffix(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "", ".":
		return ""
	case ".рф", "рф":
		return ".xn--p1ai"
	}
	return value
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func defaultPathAbs() string {
	path := DefaultPath()
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func findUpward(relativePath string) (string, bool) {
	current, err := os.Getwd()
	if err != nil {
		return "", false
	}

	for {
		candidate := filepath.Join(current, relativePath)
		if _, err := os.Stat(candidate); err == nil {
			if abs, absErr := filepath.Abs(candidate); absErr == nil {
				return abs, true
			}
			return candidate, true
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		current = parent
	}
}

func userConfigRoot() string {
	if value := os.Getenv("XDG_CONFIG_HOME"); value != "" {
		return value
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config")
	}
	return ""
}

func userCacheRoot() string {
	if value := os.Getenv("XDG_CACHE_HOME"); value != "" {
		return value
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache")
	}
	return ""
}

func (c RenderConfig) ModeOrDefault() string {
	mode := strings.TrimSpace(c.Mode)
	if mode == "" {
		return defaultRenderMode()
	}
	return mode
}

func (c RenderConfig) PrivilegedLaunchOrDefault() PrivilegedLaunchConfig {
	cfg := PrivilegedLaunchConfig{
		Mode:      LaunchModeAuto,
		Label:     defaultLaunchdLabel,
		PlistPath: defaultLaunchdPlistPath,
	}
	if c.PrivilegedLaunch == nil {
		return cfg
	}
	if mode := strings.TrimSpace(c.PrivilegedLaunch.Mode); mode != "" {
		cfg.Mode = mode
	}
	if label := strings.TrimSpace(c.PrivilegedLaunch.Label); label != "" {
		cfg.Label = label
	}
	if plistPath := strings.TrimSpace(c.PrivilegedLaunch.PlistPath); plistPath != "" {
		cfg.PlistPath = plistPath
	}
	return cfg
}

func defaultRenderMode() string {
	if runtime.GOOS == "darwin" {
		return RenderModeSystemProxy
	}
	return RenderModeTun
}
