package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const legacyRepoConfigPath = "configs/local.json"

const (
	SourceModeProxy  = "proxy"
	SourceModeDirect = "direct"

	RenderModeTun = "tun"

	LaunchModeAuto    = "auto"
	LaunchModeSudo    = "sudo"
	LaunchModeDirect  = "direct"
	LaunchModeHelper  = "helper"
	LaunchModeLaunchd = "launchd"

	defaultLaunchdLabel     = "works.relux.vless-tun"
	defaultLaunchdPlistPath = "/Library/LaunchDaemons/works.relux.vless-tun.plist"
)

type ProjectConfig struct {
	CacheDir  string          `json:"cache_dir"`
	Source    SourceConfig    `json:"source,omitempty"`
	Default   *DefaultConfig  `json:"default,omitempty"`
	Network   NetworkConfig   `json:"network,omitempty"`
	Launch    *LaunchConfig   `json:"launch,omitempty"`
	Routing   RoutingConfig   `json:"routing,omitempty"`
	DNS       DNSConfig       `json:"dns,omitempty"`
	Logging   LoggingConfig   `json:"logging,omitempty"`
	Artifacts ArtifactsConfig `json:"artifacts,omitempty"`

	SubscriptionURL string        `json:"subscription_url,omitempty"`
	SelectedProfile string        `json:"selected_profile,omitempty"`
	Render          *RenderConfig `json:"render,omitempty"`
}

type SetupOptions struct {
	SourceURL       string
	SourceMode      string
	ProfileSelector string
}

type SourceConfig struct {
	Mode string `json:"mode,omitempty"`
	URL  string `json:"url,omitempty"`
}

type DefaultConfig struct {
	ProfileSelector string `json:"profile_selector,omitempty"`
}

type NetworkConfig struct {
	Mode string    `json:"mode,omitempty"`
	TUN  TUNConfig `json:"tun,omitempty"`
}

type TUNConfig struct {
	InterfaceName string   `json:"interface_name,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
}

type RoutingConfig struct {
	BypassSuffixes []string `json:"bypass_suffixes,omitempty"`
	BypassExcludes []string `json:"bypass_exclude_suffixes,omitempty"`
}

type DNSConfig struct {
	ProxyResolver ProxyDNSConfig `json:"proxy_resolver,omitempty"`
}

type LoggingConfig struct {
	Level string `json:"level,omitempty"`
}

type ArtifactsConfig struct {
	SingboxConfigPath string `json:"singbox_config_path,omitempty"`
}

type LaunchConfig struct {
	Mode      string `json:"mode,omitempty"`
	Label     string `json:"label,omitempty"`
	PlistPath string `json:"plist_path,omitempty"`
}

type RenderConfig struct {
	Mode             string                  `json:"mode,omitempty"`
	OutputPath       string                  `json:"output_path,omitempty"`
	InterfaceName    string                  `json:"interface_name,omitempty"`
	TunAddresses     []string                `json:"tun_addresses,omitempty"`
	LogLevel         string                  `json:"log_level,omitempty"`
	BypassSuffixes   []string                `json:"bypass_suffixes,omitempty"`
	BypassExcludes   []string                `json:"bypass_exclude_suffixes,omitempty"`
	ProxyDNS         ProxyDNSConfig          `json:"proxy_dns,omitempty"`
	PrivilegedLaunch *PrivilegedLaunchConfig `json:"privileged_launch,omitempty"`
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
		CacheDir: ".cache/vpn-config",
		Source: SourceConfig{
			Mode: SourceModeProxy,
			URL:  "https://key.vpn.dance/connect?key=REPLACE_ME",
		},
		Network: NetworkConfig{
			Mode: defaultRenderMode(),
			TUN: TUNConfig{
				InterfaceName: "utun233",
				Addresses: []string{
					"172.19.0.1/30",
					"fdfe:dcba:9876::1/126",
				},
			},
		},
		Routing: RoutingConfig{
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
		},
		DNS: DNSConfig{
			ProxyResolver: ProxyDNSConfig{
				Address:       "1.1.1.1",
				Port:          853,
				TLSServerName: "cloudflare-dns.com",
			},
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Artifacts: ArtifactsConfig{
			SingboxConfigPath: "configs/generated/sing-box.json",
		},
	}

	if absPath, err := filepath.Abs(path); err == nil && absPath == defaultPathAbs() {
		if cacheDir := userCacheRoot(); cacheDir != "" {
			cfg.CacheDir = filepath.Join(cacheDir, "vless-tun")
		}
		cfg.Artifacts.SingboxConfigPath = filepath.Join(filepath.Dir(absPath), "generated", "sing-box.json")
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
	return Setup(path, SetupOptions{SourceURL: subscriptionURL}, force)
}

func Setup(path string, options SetupOptions, force bool) (ProjectConfig, error) {
	path = ResolveInitPath(path)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ProjectConfig{}, errors.New("config already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return ProjectConfig{}, err
		}
	}

	cfg := DefaultForPath(path)
	if options.SourceURL != "" {
		cfg.Source.URL = strings.TrimSpace(options.SourceURL)
		if strings.TrimSpace(options.SourceMode) != "" {
			cfg.Source.Mode = strings.TrimSpace(options.SourceMode)
		} else {
			cfg.Source.Mode = inferSourceMode(options.SourceURL)
		}
	} else if strings.TrimSpace(options.SourceMode) != "" {
		cfg.Source.Mode = strings.TrimSpace(options.SourceMode)
	}
	if selector := strings.TrimSpace(options.ProfileSelector); selector != "" {
		cfg.Default = &DefaultConfig{ProfileSelector: selector}
	}
	if err := cfg.Validate(); err != nil {
		return ProjectConfig{}, err
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
	if c.SourceURL() == "" {
		return errors.New("source.url is required")
	}
	switch c.SourceMode() {
	case SourceModeProxy, SourceModeDirect:
	default:
		return errors.New("source.mode must be one of: proxy, direct")
	}
	if c.CacheDir == "" {
		return errors.New("cache_dir is required")
	}
	if c.SourceMode() == SourceModeDirect && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.SourceURL())), "vless://") {
		return errors.New("source.url must be a vless:// URI in direct mode")
	}
	if c.SingboxConfigPath() == "" {
		return errors.New("artifacts.singbox_config_path is required")
	}
	proxyResolver := c.ProxyResolver()
	if proxyResolver.Address == "" {
		return errors.New("dns.proxy_resolver.address is required")
	}
	if proxyResolver.Port <= 0 {
		return errors.New("dns.proxy_resolver.port must be positive")
	}
	if proxyResolver.TLSServerName == "" {
		return errors.New("dns.proxy_resolver.tls_server_name is required")
	}
	switch c.NetworkMode() {
	case RenderModeTun:
		if c.TunInterfaceName() == "" {
			return errors.New("network.tun.interface_name is required in tun mode")
		}
		if len(c.TunAddresses()) == 0 {
			return errors.New("network.tun.addresses is required in tun mode")
		}
	default:
		return errors.New("network.mode must be tun")
	}

	switch c.LaunchOrDefault().Mode {
	case LaunchModeAuto, LaunchModeSudo, LaunchModeDirect, LaunchModeHelper, LaunchModeLaunchd:
	default:
		return errors.New("launch.mode must be one of: auto, sudo, direct, helper, launchd")
	}
	return nil
}

func (c *ProjectConfig) resolveRelativePaths(baseDir string) {
	if !filepath.IsAbs(c.CacheDir) {
		c.CacheDir = filepath.Join(baseDir, c.CacheDir)
	}
	if path := strings.TrimSpace(c.Artifacts.SingboxConfigPath); path != "" && !filepath.IsAbs(path) {
		c.Artifacts.SingboxConfigPath = filepath.Join(baseDir, path)
	}
	if c.Render != nil {
		if path := strings.TrimSpace(c.Render.OutputPath); path != "" && !filepath.IsAbs(path) {
			c.Render.OutputPath = filepath.Join(baseDir, path)
		}
	}
}

func (c ProjectConfig) SourceURL() string {
	return firstNonEmpty(strings.TrimSpace(c.Source.URL), strings.TrimSpace(c.SubscriptionURL))
}

func (c ProjectConfig) SourceMode() string {
	mode := strings.TrimSpace(strings.ToLower(c.Source.Mode))
	if mode != "" {
		return mode
	}
	return inferSourceMode(c.SourceURL())
}

func (c ProjectConfig) DefaultProfileSelector() string {
	if c.Default != nil {
		if selector := strings.TrimSpace(c.Default.ProfileSelector); selector != "" {
			return selector
		}
	}
	return strings.TrimSpace(c.SelectedProfile)
}

func (c ProjectConfig) NetworkMode() string {
	if mode := strings.TrimSpace(c.Network.Mode); mode != "" {
		return mode
	}
	if c.Render != nil {
		return c.Render.ModeOrDefault()
	}
	return defaultRenderMode()
}

func (c ProjectConfig) SingboxConfigPath() string {
	return firstNonEmpty(strings.TrimSpace(c.Artifacts.SingboxConfigPath), c.legacyRenderOutputPath())
}

func (c ProjectConfig) TunInterfaceName() string {
	return firstNonEmpty(strings.TrimSpace(c.Network.TUN.InterfaceName), c.legacyRenderInterfaceName())
}

func (c ProjectConfig) TunAddresses() []string {
	if c.Network.TUN.Addresses != nil {
		return cloneStrings(c.Network.TUN.Addresses)
	}
	if c.Render != nil {
		return cloneStrings(c.Render.TunAddresses)
	}
	return nil
}

func (c ProjectConfig) LogLevel() string {
	return firstNonEmpty(strings.TrimSpace(c.Logging.Level), c.legacyRenderLogLevel())
}

func (c ProjectConfig) BypassSuffixes() []string {
	if c.Routing.BypassSuffixes != nil {
		return cloneStrings(c.Routing.BypassSuffixes)
	}
	if c.Render != nil {
		return cloneStrings(c.Render.BypassSuffixes)
	}
	return nil
}

func (c ProjectConfig) BypassExcludes() []string {
	if c.Routing.BypassExcludes != nil {
		return cloneStrings(c.Routing.BypassExcludes)
	}
	if c.Render != nil {
		return cloneStrings(c.Render.BypassExcludes)
	}
	return nil
}

func (c ProjectConfig) NormalizedBypassSuffixes() []string {
	return normalizeSuffixes(c.BypassSuffixes())
}

func (c ProjectConfig) NormalizedBypassExcludes() []string {
	return normalizeSuffixes(c.BypassExcludes())
}

func (c ProjectConfig) ProxyResolver() ProxyDNSConfig {
	if c.DNS.ProxyResolver.Address != "" || c.DNS.ProxyResolver.Port > 0 || c.DNS.ProxyResolver.TLSServerName != "" {
		return c.DNS.ProxyResolver
	}
	if c.Render != nil {
		return c.Render.ProxyDNS
	}
	return ProxyDNSConfig{}
}

func (c ProjectConfig) LaunchOrDefault() PrivilegedLaunchConfig {
	cfg := PrivilegedLaunchConfig{
		Mode:      LaunchModeAuto,
		Label:     defaultLaunchdLabel,
		PlistPath: defaultLaunchdPlistPath,
	}
	if c.Launch != nil {
		if mode := strings.TrimSpace(c.Launch.Mode); mode != "" {
			cfg.Mode = mode
		}
		if label := strings.TrimSpace(c.Launch.Label); label != "" {
			cfg.Label = label
		}
		if plistPath := strings.TrimSpace(c.Launch.PlistPath); plistPath != "" {
			cfg.PlistPath = plistPath
		}
		return cfg
	}
	if c.Render != nil {
		return c.Render.PrivilegedLaunchOrDefault()
	}
	return cfg
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

func (c RenderConfig) ModeOrDefault() string {
	mode := strings.TrimSpace(c.Mode)
	if mode == "" {
		return defaultRenderMode()
	}
	return mode
}

func (c ProjectConfig) legacyRenderOutputPath() string {
	if c.Render == nil {
		return ""
	}
	return strings.TrimSpace(c.Render.OutputPath)
}

func (c ProjectConfig) legacyRenderInterfaceName() string {
	if c.Render == nil {
		return ""
	}
	return strings.TrimSpace(c.Render.InterfaceName)
}

func (c ProjectConfig) legacyRenderLogLevel() string {
	if c.Render == nil {
		return ""
	}
	return strings.TrimSpace(c.Render.LogLevel)
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func inferSourceMode(sourceURL string) string {
	value := strings.TrimSpace(strings.ToLower(sourceURL))
	if strings.HasPrefix(value, "vless://") {
		return SourceModeDirect
	}
	return SourceModeProxy
}

func defaultRenderMode() string {
	return RenderModeTun
}
