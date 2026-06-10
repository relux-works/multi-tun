package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const legacyRepoConfigPath = "configs/local.json"

const (
	SourceModeProxy  = "proxy"
	SourceModeDirect = "direct"

	RenderModeTun = "tun"

	EngineSingbox = "sing-box"
	EngineXray    = "xray"

	LaunchModeAuto    = "auto"
	LaunchModeSudo    = "sudo"
	LaunchModeDirect  = "direct"
	LaunchModeHelper  = "helper"
	LaunchModeLaunchd = "launchd"

	defaultLaunchdLabel     = "works.relux.vless-tun"
	defaultLaunchdPlistPath = "/Library/LaunchDaemons/works.relux.vless-tun.plist"
)

type ProjectConfig struct {
	Current   *CurrentConfig          `json:"current,omitempty"`
	Servers   map[string]ServerConfig `json:"servers,omitempty"`
	CacheDir  string                  `json:"cache_dir,omitempty"`
	Source    SourceConfig            `json:"source,omitempty"`
	Default   *DefaultConfig          `json:"default,omitempty"`
	Network   NetworkConfig           `json:"network,omitempty"`
	Launch    *LaunchConfig           `json:"launch,omitempty"`
	Routing   RoutingConfig           `json:"routing,omitempty"`
	Engine    *EngineConfig           `json:"engine,omitempty"`
	Singbox   *SingboxConfig          `json:"singbox,omitempty"`
	DNS       DNSConfig               `json:"dns,omitempty"`
	Logging   LoggingConfig           `json:"logging,omitempty"`
	Artifacts ArtifactsConfig         `json:"artifacts,omitempty"`

	SubscriptionURL string        `json:"subscription_url,omitempty"`
	SelectedProfile string        `json:"selected_profile,omitempty"`
	Render          *RenderConfig `json:"render,omitempty"`
}

type SetupOptions struct {
	SourceURL       string
	SourceMode      string
	ProfileSelector string
	ServerName      string
	ConfigProfile   string
}

type SelectionOptions struct {
	Server   string
	Profile  string
	Selector string
}

type EffectiveSelection struct {
	Server          string
	Profile         string
	Selector        string
	UsesServerModel bool
}

type CurrentConfig struct {
	Server  string `json:"server,omitempty"`
	Profile string `json:"profile,omitempty"`
}

type ServerConfig struct {
	Source    SourceConfig             `json:"source,omitempty"`
	CacheDir  string                   `json:"cache_dir,omitempty"`
	Artifacts *ArtifactsConfig         `json:"artifacts,omitempty"`
	Routing   *RoutingConfig           `json:"routing,omitempty"`
	Engine    *EngineConfig            `json:"engine,omitempty"`
	Singbox   *SingboxConfig           `json:"singbox,omitempty"`
	Profiles  map[string]ProfileConfig `json:"profiles,omitempty"`
}

type ProfileConfig struct {
	Selector        string         `json:"selector,omitempty"`
	ProfileSelector string         `json:"profile_selector,omitempty"`
	Routing         *RoutingConfig `json:"routing,omitempty"`
	Engine          *EngineConfig  `json:"engine,omitempty"`
	Singbox         *SingboxConfig `json:"singbox,omitempty"`
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
	Routes         []string `json:"routes,omitempty"`
}

type EngineConfig struct {
	Type string            `json:"type,omitempty"`
	Xray *XrayEngineConfig `json:"xray,omitempty"`
}

type XrayEngineConfig struct {
	Executable   string   `json:"executable,omitempty"`
	SocksListen  string   `json:"socks_listen,omitempty"`
	SocksPort    int      `json:"socks_port,omitempty"`
	ProcessNames []string `json:"process_names,omitempty"`
}

type SingboxConfig struct {
	Sniff *SniffConfig    `json:"sniff,omitempty"`
	TLS   TLSClientConfig `json:"tls,omitempty"`
}

type SniffConfig struct {
	Enabled  *bool    `json:"enabled,omitempty"`
	Sniffers []string `json:"sniffers,omitempty"`
	Timeout  string   `json:"timeout,omitempty"`
}

type TLSClientConfig struct {
	Fragment              *bool    `json:"fragment,omitempty"`
	FragmentFallbackDelay string   `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        *bool    `json:"record_fragment,omitempty"`
	CurvePreferences      []string `json:"curve_preferences,omitempty"`
}

type DNSConfig struct {
	ProxyResolver ProxyDNSConfig `json:"proxy_resolver,omitempty"`
}

type LoggingConfig struct {
	Level string `json:"level,omitempty"`
}

type ArtifactsConfig struct {
	SingboxConfigPath string `json:"singbox_config_path,omitempty"`
	XrayConfigPath    string `json:"xray_config_path,omitempty"`
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
			Level: "warn",
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
	cfg = cfg.withDefaultServerProfile(options)
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

func SetCurrent(path string, options SelectionOptions) (ProjectConfig, EffectiveSelection, string, error) {
	resolvedPath, err := ResolveLoadPath(path)
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, "", err
	}

	cfg, err := Load(resolvedPath)
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, "", err
	}
	serverName, profileName, err := cfg.resolveCurrentUpdate(options)
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, "", err
	}

	cfg.Current = &CurrentConfig{
		Server:  serverName,
		Profile: profileName,
	}
	effective, selection, err := cfg.Effective(SelectionOptions{})
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, "", err
	}
	if err := writeJSON(resolvedPath, cfg); err != nil {
		return ProjectConfig{}, EffectiveSelection{}, "", err
	}
	return effective, selection, resolvedPath, nil
}

func (c ProjectConfig) withDefaultServerProfile(options SetupOptions) ProjectConfig {
	serverName := firstNonEmpty(options.ServerName, "default")
	profileName := firstNonEmpty(options.ConfigProfile, "default")
	selector := c.legacyDefaultProfileSelector()

	artifacts := c.Artifacts
	routing := c.Routing
	engine := cloneEngineConfig(c.Engine)
	if engine == nil || strings.TrimSpace(engine.Type) == "" {
		engine = &EngineConfig{Type: EngineSingbox}
	}
	singbox := cloneSingboxConfig(c.Singbox)
	profile := ProfileConfig{
		Selector: selector,
	}

	c.Current = &CurrentConfig{
		Server:  serverName,
		Profile: profileName,
	}
	c.Servers = map[string]ServerConfig{
		serverName: {
			Source:    c.Source,
			CacheDir:  c.CacheDir,
			Artifacts: &artifacts,
			Routing:   &routing,
			Engine:    engine,
			Singbox:   singbox,
			Profiles: map[string]ProfileConfig{
				profileName: profile,
			},
		},
	}
	c.CacheDir = ""
	c.Source = SourceConfig{}
	c.Default = nil
	c.Routing = RoutingConfig{}
	c.Engine = nil
	c.Singbox = nil
	c.Artifacts = ArtifactsConfig{}
	c.SubscriptionURL = ""
	c.SelectedProfile = ""
	c.Render = nil
	return c
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
	if err := c.validateExplicitServerEngines(); err != nil {
		return err
	}
	effective, _, err := c.Effective(SelectionOptions{})
	if err != nil {
		return err
	}
	return effective.validateFlat()
}

func (c ProjectConfig) validateExplicitServerEngines() error {
	if len(c.Servers) == 0 {
		return nil
	}

	for name, server := range c.Servers {
		if server.Engine == nil || strings.TrimSpace(server.Engine.Type) == "" {
			return fmt.Errorf("servers.%s.engine.type is required; set it to one of: %s, %s. Example: \"servers\": { %q: { \"engine\": { \"type\": %q } } }. Use %q for the Xray sidecar engine", name, EngineSingbox, EngineXray, name, EngineSingbox, EngineXray)
		}
		switch normalizeEngineType(server.Engine.Type) {
		case EngineSingbox, EngineXray:
		default:
			return fmt.Errorf("servers.%s.engine.type must be one of: %s, %s", name, EngineSingbox, EngineXray)
		}
	}
	return nil
}

func (c ProjectConfig) validateFlat() error {
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
	switch c.EngineType() {
	case EngineSingbox, EngineXray:
	default:
		return errors.New("engine.type must be one of: sing-box, xray")
	}
	if c.EngineType() == EngineXray && c.XraySocksPort() <= 0 {
		return errors.New("engine.xray.socks_port must be positive")
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

func (c ProjectConfig) Effective(options SelectionOptions) (ProjectConfig, EffectiveSelection, error) {
	if len(c.Servers) == 0 {
		effective := c
		selector := firstNonEmpty(options.Selector, options.Profile, c.legacyDefaultProfileSelector())
		effective.setDefaultProfileSelector(selector)
		return effective, EffectiveSelection{
			Selector: selector,
		}, nil
	}

	serverOverride := strings.TrimSpace(options.Server)
	serverName, serverCfg, err := c.resolveServerConfig(serverOverride)
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, err
	}
	useCurrentProfile := serverOverride == "" || serverOverride == currentServerName(c.Current)
	profileName, profileCfg, hasProfile, err := c.resolveProfileConfig(serverCfg, options.Profile, useCurrentProfile)
	if err != nil {
		return ProjectConfig{}, EffectiveSelection{}, err
	}

	effective := c
	effective.Current = nil
	effective.Servers = nil
	effective.Source = mergeSourceConfig(c.Source, serverCfg.Source)
	effective.CacheDir = firstNonEmpty(serverCfg.CacheDir, c.CacheDir)
	effective.Artifacts = mergeArtifactsConfig(c.Artifacts, serverCfg.Artifacts)
	effective.Routing = mergeRoutingConfig(c.Routing, serverCfg.Routing)
	effective.Engine = mergeEngineConfig(c.Engine, serverCfg.Engine)
	effective.Singbox = mergeSingboxConfig(c.Singbox, serverCfg.Singbox)

	selector := firstNonEmpty(options.Selector, c.legacyDefaultProfileSelector())
	if hasProfile {
		effective.Routing = mergeRoutingConfig(effective.Routing, profileCfg.Routing)
		effective.Engine = mergeEngineConfig(effective.Engine, profileCfg.Engine)
		effective.Singbox = mergeSingboxConfig(effective.Singbox, profileCfg.Singbox)
		selector = firstNonEmpty(options.Selector, profileCfg.Selector, profileCfg.ProfileSelector, c.legacyDefaultProfileSelector())
	}
	effective.setDefaultProfileSelector(selector)

	return effective, EffectiveSelection{
		Server:          serverName,
		Profile:         profileName,
		Selector:        selector,
		UsesServerModel: true,
	}, nil
}

func (c ProjectConfig) resolveServerConfig(override string) (string, ServerConfig, error) {
	name := firstNonEmpty(override, currentServerName(c.Current))
	if name != "" {
		server, ok := c.Servers[name]
		if !ok {
			return "", ServerConfig{}, errors.New("selected server " + name + " is not configured")
		}
		return name, server, nil
	}
	if len(c.Servers) == 1 {
		for onlyName, server := range c.Servers {
			return onlyName, server, nil
		}
	}
	return "", ServerConfig{}, errors.New("current.server is required when multiple vless servers are configured")
}

func (c ProjectConfig) resolveCurrentUpdate(options SelectionOptions) (string, string, error) {
	if len(c.Servers) == 0 {
		return "", "", errors.New("set-current requires a config with servers")
	}

	serverName := strings.TrimSpace(options.Server)
	if serverName == "" {
		serverName = currentServerName(c.Current)
	}
	if serverName == "" {
		if len(c.Servers) == 1 {
			for onlyName := range c.Servers {
				serverName = onlyName
			}
		}
	}
	if serverName == "" {
		return "", "", errors.New("server is required")
	}

	serverCfg, ok := c.Servers[serverName]
	if !ok {
		return "", "", errors.New("selected server " + serverName + " is not configured")
	}
	if len(serverCfg.Profiles) == 0 {
		if strings.TrimSpace(options.Profile) != "" {
			return "", "", errors.New("selected server " + serverName + " has no configured profiles")
		}
		return serverName, "", nil
	}

	profileName := strings.TrimSpace(options.Profile)
	if profileName == "" {
		if _, ok := serverCfg.Profiles["default"]; ok {
			profileName = "default"
		} else if len(serverCfg.Profiles) == 1 {
			for onlyName := range serverCfg.Profiles {
				profileName = onlyName
			}
		}
	}
	if profileName == "" {
		return "", "", errors.New("profile is required when selected vless server has multiple profiles and no default profile")
	}
	if _, ok := serverCfg.Profiles[profileName]; !ok {
		return "", "", errors.New("selected profile " + profileName + " is not configured for selected server")
	}
	return serverName, profileName, nil
}

func (c ProjectConfig) resolveProfileConfig(server ServerConfig, override string, useCurrent bool) (string, ProfileConfig, bool, error) {
	if len(server.Profiles) == 0 {
		return "", ProfileConfig{}, false, nil
	}

	name := strings.TrimSpace(override)
	if name == "" && useCurrent {
		name = currentProfileName(c.Current)
	}
	if name != "" {
		profile, ok := server.Profiles[name]
		if !ok {
			return "", ProfileConfig{}, false, errors.New("selected profile " + name + " is not configured for selected server")
		}
		return name, profile, true, nil
	}
	if len(server.Profiles) == 1 {
		for onlyName, profile := range server.Profiles {
			return onlyName, profile, true, nil
		}
	}
	return "", ProfileConfig{}, false, errors.New("current.profile is required when selected vless server has multiple profiles")
}

func currentServerName(current *CurrentConfig) string {
	if current == nil {
		return ""
	}
	return strings.TrimSpace(current.Server)
}

func currentProfileName(current *CurrentConfig) string {
	if current == nil {
		return ""
	}
	return strings.TrimSpace(current.Profile)
}

func mergeSourceConfig(base SourceConfig, override SourceConfig) SourceConfig {
	result := base
	if mode := strings.TrimSpace(override.Mode); mode != "" {
		result.Mode = mode
	}
	if url := strings.TrimSpace(override.URL); url != "" {
		result.URL = url
	}
	return result
}

func mergeArtifactsConfig(base ArtifactsConfig, override *ArtifactsConfig) ArtifactsConfig {
	if override == nil {
		return base
	}
	result := base
	if path := strings.TrimSpace(override.SingboxConfigPath); path != "" {
		result.SingboxConfigPath = path
	}
	if path := strings.TrimSpace(override.XrayConfigPath); path != "" {
		result.XrayConfigPath = path
	}
	return result
}

func mergeRoutingConfig(base RoutingConfig, override *RoutingConfig) RoutingConfig {
	if override == nil {
		return base
	}
	result := base
	if override.BypassSuffixes != nil {
		result.BypassSuffixes = cloneStrings(override.BypassSuffixes)
	}
	if override.BypassExcludes != nil {
		result.BypassExcludes = cloneStrings(override.BypassExcludes)
	}
	if override.Routes != nil {
		result.Routes = cloneStrings(override.Routes)
	}
	return result
}

func mergeEngineConfig(base *EngineConfig, override *EngineConfig) *EngineConfig {
	if base == nil && override == nil {
		return nil
	}

	result := cloneEngineConfig(base)
	if result == nil {
		result = &EngineConfig{}
	}
	if override == nil {
		return result
	}

	if engineType := strings.TrimSpace(override.Type); engineType != "" {
		result.Type = engineType
	}
	result.Xray = mergeXrayEngineConfig(result.Xray, override.Xray)
	return result
}

func mergeXrayEngineConfig(base *XrayEngineConfig, override *XrayEngineConfig) *XrayEngineConfig {
	if base == nil && override == nil {
		return nil
	}

	result := cloneXrayEngineConfig(base)
	if result == nil {
		result = &XrayEngineConfig{}
	}
	if override == nil {
		return result
	}

	if executable := strings.TrimSpace(override.Executable); executable != "" {
		result.Executable = executable
	}
	if listen := strings.TrimSpace(override.SocksListen); listen != "" {
		result.SocksListen = listen
	}
	if override.SocksPort > 0 {
		result.SocksPort = override.SocksPort
	}
	if override.ProcessNames != nil {
		result.ProcessNames = cloneStrings(override.ProcessNames)
	}
	return result
}

func mergeSingboxConfig(base *SingboxConfig, override *SingboxConfig) *SingboxConfig {
	if base == nil && override == nil {
		return nil
	}

	result := cloneSingboxConfig(base)
	if result == nil {
		result = &SingboxConfig{}
	}
	if override == nil {
		return result
	}

	if override.Sniff != nil {
		result.Sniff = mergeSniffConfig(result.Sniff, override.Sniff)
	}
	result.TLS = mergeTLSClientConfig(result.TLS, override.TLS)
	return result
}

func mergeSniffConfig(base *SniffConfig, override *SniffConfig) *SniffConfig {
	result := cloneSniffConfig(base)
	if result == nil {
		result = &SniffConfig{}
	}
	if override.Enabled != nil {
		enabled := *override.Enabled
		result.Enabled = &enabled
	}
	if override.Sniffers != nil {
		result.Sniffers = cloneStrings(override.Sniffers)
	}
	if timeout := strings.TrimSpace(override.Timeout); timeout != "" {
		result.Timeout = timeout
	}
	return result
}

func mergeTLSClientConfig(base TLSClientConfig, override TLSClientConfig) TLSClientConfig {
	result := cloneTLSClientConfig(base)
	if override.Fragment != nil {
		fragment := *override.Fragment
		result.Fragment = &fragment
	}
	if fallbackDelay := strings.TrimSpace(override.FragmentFallbackDelay); fallbackDelay != "" {
		result.FragmentFallbackDelay = fallbackDelay
	}
	if override.RecordFragment != nil {
		recordFragment := *override.RecordFragment
		result.RecordFragment = &recordFragment
	}
	if override.CurvePreferences != nil {
		result.CurvePreferences = cloneStrings(override.CurvePreferences)
	}
	return result
}

func (c ProjectConfig) legacyDefaultProfileSelector() string {
	if c.Default != nil {
		if selector := strings.TrimSpace(c.Default.ProfileSelector); selector != "" {
			return selector
		}
	}
	return strings.TrimSpace(c.SelectedProfile)
}

func (c *ProjectConfig) setDefaultProfileSelector(selector string) {
	selector = strings.TrimSpace(selector)
	c.SelectedProfile = ""
	if selector == "" {
		if c.Default != nil {
			c.Default.ProfileSelector = ""
		}
		return
	}
	if c.Default == nil {
		c.Default = &DefaultConfig{}
	}
	c.Default.ProfileSelector = selector
}

func (c *ProjectConfig) resolveRelativePaths(baseDir string) {
	if !filepath.IsAbs(c.CacheDir) {
		c.CacheDir = filepath.Join(baseDir, c.CacheDir)
	}
	if path := strings.TrimSpace(c.Artifacts.SingboxConfigPath); path != "" && !filepath.IsAbs(path) {
		c.Artifacts.SingboxConfigPath = filepath.Join(baseDir, path)
	}
	if path := strings.TrimSpace(c.Artifacts.XrayConfigPath); path != "" && !filepath.IsAbs(path) {
		c.Artifacts.XrayConfigPath = filepath.Join(baseDir, path)
	}
	if c.Render != nil {
		if path := strings.TrimSpace(c.Render.OutputPath); path != "" && !filepath.IsAbs(path) {
			c.Render.OutputPath = filepath.Join(baseDir, path)
		}
	}
	for name, server := range c.Servers {
		if server.CacheDir != "" && !filepath.IsAbs(server.CacheDir) {
			server.CacheDir = filepath.Join(baseDir, server.CacheDir)
		}
		if server.Artifacts != nil {
			if path := strings.TrimSpace(server.Artifacts.SingboxConfigPath); path != "" && !filepath.IsAbs(path) {
				server.Artifacts.SingboxConfigPath = filepath.Join(baseDir, path)
			}
			if path := strings.TrimSpace(server.Artifacts.XrayConfigPath); path != "" && !filepath.IsAbs(path) {
				server.Artifacts.XrayConfigPath = filepath.Join(baseDir, path)
			}
		}
		c.Servers[name] = server
	}
}

func (c ProjectConfig) SourceURL() string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.SourceURL()
	}
	return firstNonEmpty(strings.TrimSpace(c.Source.URL), strings.TrimSpace(c.SubscriptionURL))
}

func (c ProjectConfig) SourceMode() string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.SourceMode()
	}
	mode := strings.TrimSpace(strings.ToLower(c.Source.Mode))
	if mode != "" {
		return mode
	}
	return inferSourceMode(c.SourceURL())
}

func (c ProjectConfig) DefaultProfileSelector() string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.DefaultProfileSelector()
	}
	return c.legacyDefaultProfileSelector()
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
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.SingboxConfigPath()
	}
	return firstNonEmpty(strings.TrimSpace(c.Artifacts.SingboxConfigPath), c.legacyRenderOutputPath())
}

func (c ProjectConfig) XrayConfigPath() string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.XrayConfigPath()
	}
	if path := strings.TrimSpace(c.Artifacts.XrayConfigPath); path != "" {
		return path
	}
	return deriveXrayConfigPath(c.SingboxConfigPath())
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
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.BypassSuffixes()
	}
	if c.Routing.BypassSuffixes != nil {
		return cloneStrings(c.Routing.BypassSuffixes)
	}
	if c.Render != nil {
		return cloneStrings(c.Render.BypassSuffixes)
	}
	return nil
}

func (c ProjectConfig) BypassExcludes() []string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.BypassExcludes()
	}
	if c.Routing.BypassExcludes != nil {
		return cloneStrings(c.Routing.BypassExcludes)
	}
	if c.Render != nil {
		return cloneStrings(c.Render.BypassExcludes)
	}
	return nil
}

func (c ProjectConfig) Routes() []string {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.Routes()
	}
	if c.Routing.Routes != nil {
		return cloneStrings(c.Routing.Routes)
	}
	return nil
}

func (c ProjectConfig) Sniff() SniffConfig {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.Sniff()
	}
	if c.Singbox == nil || c.Singbox.Sniff == nil {
		return SniffConfig{}
	}
	return *cloneSniffConfig(c.Singbox.Sniff)
}

func (c ProjectConfig) TLSOptions() TLSClientConfig {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.TLSOptions()
	}
	if c.Singbox == nil {
		return TLSClientConfig{}
	}
	return cloneTLSClientConfig(c.Singbox.TLS)
}

func (c ProjectConfig) EngineConfig() EngineConfig {
	if effective, ok := c.effectiveFromServers(); ok {
		return effective.EngineConfig()
	}
	if c.Engine == nil {
		return EngineConfig{}
	}
	return *cloneEngineConfig(c.Engine)
}

func (c ProjectConfig) EngineType() string {
	engineType := normalizeEngineType(c.EngineConfig().Type)
	switch engineType {
	case "":
		return EngineSingbox
	default:
		return engineType
	}
}

func (c ProjectConfig) XrayExecutable() string {
	engine := c.EngineConfig()
	if engine.Xray == nil {
		return "xray"
	}
	return firstNonEmpty(engine.Xray.Executable, "xray")
}

func (c ProjectConfig) XraySocksListen() string {
	engine := c.EngineConfig()
	if engine.Xray == nil {
		return "127.0.0.1"
	}
	return firstNonEmpty(engine.Xray.SocksListen, "127.0.0.1")
}

func (c ProjectConfig) XraySocksPort() int {
	engine := c.EngineConfig()
	if engine.Xray != nil && engine.Xray.SocksPort > 0 {
		return engine.Xray.SocksPort
	}
	return 20808
}

func (c ProjectConfig) XrayProcessNames() []string {
	engine := c.EngineConfig()
	if engine.Xray != nil && engine.Xray.ProcessNames != nil {
		return normalizeStrings(engine.Xray.ProcessNames)
	}
	executable := filepath.Base(c.XrayExecutable())
	if executable == "" || executable == "." || executable == string(filepath.Separator) {
		return []string{"xray"}
	}
	return []string{executable}
}

func (c ProjectConfig) effectiveFromServers() (ProjectConfig, bool) {
	if len(c.Servers) == 0 {
		return ProjectConfig{}, false
	}
	effective, _, err := c.Effective(SelectionOptions{})
	if err != nil {
		return ProjectConfig{}, false
	}
	return effective, true
}

func (c ProjectConfig) NormalizedBypassSuffixes() []string {
	return normalizeSuffixes(c.BypassSuffixes())
}

func (c ProjectConfig) NormalizedBypassExcludes() []string {
	return normalizeSuffixes(c.BypassExcludes())
}

func (c ProjectConfig) NormalizedRoutes() []string {
	return normalizeRoutes(c.Routes())
}

func (c ProjectConfig) NormalizedSniffers() []string {
	return normalizeStrings(c.Sniff().Sniffers)
}

func (c ProjectConfig) NormalizedCurvePreferences() []string {
	return normalizeStrings(c.TLSOptions().CurvePreferences)
}

func (c ProjectConfig) SniffEnabled() bool {
	sniff := c.Sniff()
	if sniff.Enabled == nil {
		return true
	}
	return *sniff.Enabled
}

func (c ProjectConfig) SniffTimeout() string {
	return strings.TrimSpace(c.Sniff().Timeout)
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

func normalizeRoutes(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
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

func normalizeStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
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

func normalizeEngineType(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "singbox" {
		return EngineSingbox
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

func deriveXrayConfigPath(singboxPath string) string {
	singboxPath = strings.TrimSpace(singboxPath)
	if singboxPath == "" {
		return ""
	}

	dir := filepath.Dir(singboxPath)
	base := filepath.Base(singboxPath)
	switch {
	case strings.HasPrefix(base, "sing-box"):
		base = "xray" + strings.TrimPrefix(base, "sing-box")
	case strings.HasPrefix(base, "singbox"):
		base = "xray" + strings.TrimPrefix(base, "singbox")
	default:
		ext := filepath.Ext(base)
		base = strings.TrimSuffix(base, ext) + "-xray" + ext
	}
	return filepath.Join(dir, base)
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func cloneEngineConfig(value *EngineConfig) *EngineConfig {
	if value == nil {
		return nil
	}
	return &EngineConfig{
		Type: strings.TrimSpace(value.Type),
		Xray: cloneXrayEngineConfig(value.Xray),
	}
}

func cloneXrayEngineConfig(value *XrayEngineConfig) *XrayEngineConfig {
	if value == nil {
		return nil
	}
	return &XrayEngineConfig{
		Executable:   strings.TrimSpace(value.Executable),
		SocksListen:  strings.TrimSpace(value.SocksListen),
		SocksPort:    value.SocksPort,
		ProcessNames: cloneStrings(value.ProcessNames),
	}
}

func cloneSingboxConfig(value *SingboxConfig) *SingboxConfig {
	if value == nil {
		return nil
	}
	return &SingboxConfig{
		Sniff: cloneSniffConfig(value.Sniff),
		TLS:   cloneTLSClientConfig(value.TLS),
	}
}

func cloneSniffConfig(value *SniffConfig) *SniffConfig {
	if value == nil {
		return nil
	}
	result := &SniffConfig{
		Sniffers: cloneStrings(value.Sniffers),
		Timeout:  strings.TrimSpace(value.Timeout),
	}
	if value.Enabled != nil {
		enabled := *value.Enabled
		result.Enabled = &enabled
	}
	return result
}

func cloneTLSClientConfig(value TLSClientConfig) TLSClientConfig {
	result := TLSClientConfig{
		FragmentFallbackDelay: strings.TrimSpace(value.FragmentFallbackDelay),
		CurvePreferences:      cloneStrings(value.CurvePreferences),
	}
	if value.Fragment != nil {
		fragment := *value.Fragment
		result.Fragment = &fragment
	}
	if value.RecordFragment != nil {
		recordFragment := *value.RecordFragment
		result.RecordFragment = &recordFragment
	}
	return result
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
