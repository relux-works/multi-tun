package openconnectcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Config struct {
	CacheDir       string                  `json:"cache_dir,omitempty"`
	Default        DefaultSelection        `json:"default,omitempty"`
	DefaultServer  string                  `json:"default_server,omitempty"`
	DefaultProfile string                  `json:"default_profile,omitempty"`
	DefaultMode    string                  `json:"default_mode,omitempty"`
	SplitInclude   *SplitIncludeConfig     `json:"split_include,omitempty"`
	Profiles       map[string]VPNConfig    `json:"profiles,omitempty"`
	Servers        map[string]ServerConfig `json:"servers,omitempty"`
	Auth           AuthConfig              `json:"auth,omitempty"`
}

type SetupOptions struct {
	ServerURL string
	Profile   string
	Force     bool
	Auth      AuthConfig
}

type DefaultSelection struct {
	ServerURL string `json:"server_url,omitempty"`
	Profile   string `json:"profile,omitempty"`
}

type SplitIncludeConfig struct {
	Routes         []string `json:"routes,omitempty"`
	VPNDomains     []string `json:"vpn_domains,omitempty"`
	BypassSuffixes []string `json:"bypass_suffixes,omitempty"`
	Nameservers    []string `json:"nameservers,omitempty"`
}

type VPNConfig struct {
	SplitInclude *SplitIncludeConfig `json:"split_include,omitempty"`
}

type ServerConfig struct {
	SplitInclude *SplitIncludeConfig      `json:"split_include,omitempty"`
	Profiles     map[string]ProfileConfig `json:"profiles,omitempty"`
}

type ProfileConfig struct {
	Mode         string              `json:"mode,omitempty"`
	SplitInclude *SplitIncludeConfig `json:"split_include,omitempty"`
}

type AuthConfig struct {
	UsernameKeychainAccount string `json:"username_keychain_account,omitempty"`
	Username                string `json:"username,omitempty"`
	PasswordKeychainAccount string `json:"password_keychain_account,omitempty"`
	TOTPKeychainAccount     string `json:"totp_secret_keychain_account,omitempty"`
}

func DefaultPath() string {
	if dir := userConfigRoot(); dir != "" {
		return filepath.Join(dir, "openconnect-tun", "config.json")
	}
	return filepath.Join("configs", "openconnect-tun.local.json")
}

func ResolveInitPath(path string) string {
	if strings.TrimSpace(path) != "" {
		return absOrOriginal(path)
	}
	return DefaultPath()
}

func DefaultForPath(path string) Config {
	cfg := Config{
		CacheDir: ".cache/openconnect-tun",
	}

	if absPath := absOrOriginal(path); absPath == DefaultPath() {
		if cacheRoot := userCacheRoot(); cacheRoot != "" {
			cfg.CacheDir = filepath.Join(cacheRoot, "openconnect-tun")
		}
	}

	return cfg
}

func Init(path string, options SetupOptions) (Config, string, error) {
	resolved := ResolveInitPath(path)
	if !options.Force {
		if _, err := os.Stat(resolved); err == nil {
			return Config{}, resolved, errors.New("config already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Config{}, resolved, err
		}
	}

	serverURL := strings.TrimSpace(options.ServerURL)
	profile := strings.TrimSpace(options.Profile)
	if serverURL == "" {
		return Config{}, resolved, errors.New("server_url is required")
	}
	if profile == "" {
		return Config{}, resolved, errors.New("profile is required")
	}

	cfg := DefaultForPath(resolved)
	cfg.Default = DefaultSelection{
		ServerURL: serverURL,
		Profile:   profile,
	}
	cfg.Servers = map[string]ServerConfig{
		serverURL: {
			Profiles: map[string]ProfileConfig{
				profile: {
					Mode: "full",
				},
			},
		},
	}
	cfg.Auth = options.Auth

	if err := os.MkdirAll(filepath.Dir(resolved), 0o755); err != nil {
		return Config{}, resolved, err
	}
	if err := writeJSON(resolved, cfg); err != nil {
		return Config{}, resolved, err
	}
	return cfg, resolved, nil
}

func ResolveLoadPath(path string) string {
	if strings.TrimSpace(path) != "" {
		return absOrOriginal(path)
	}
	if envPath := os.Getenv("OPENCONNECT_TUN_CONFIG"); envPath != "" {
		return absOrOriginal(envPath)
	}
	return DefaultPath()
}

func LoadOptional(path string) (Config, string, error) {
	resolved := ResolveLoadPath(path)
	raw, err := os.ReadFile(resolved)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, resolved, nil
	}
	if err != nil {
		return Config{}, resolved, err
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, resolved, err
	}
	cfg.resolveRelativePaths(filepath.Dir(resolved))
	return cfg, resolved, nil
}

func (c Config) CacheDirOrDefault() string {
	if strings.TrimSpace(c.CacheDir) != "" {
		return c.CacheDir
	}
	return ""
}

func (c Config) DefaultSelection() DefaultSelection {
	return DefaultSelection{
		ServerURL: firstNonEmpty(strings.TrimSpace(c.Default.ServerURL), strings.TrimSpace(c.DefaultServer)),
		Profile:   firstNonEmpty(strings.TrimSpace(c.Default.Profile), strings.TrimSpace(c.DefaultProfile)),
	}
}

func (c Config) EffectiveMode(server string, profile string) string {
	server = strings.TrimSpace(server)
	profile = strings.TrimSpace(profile)
	if server != "" && profile != "" {
		if serverCfg, ok := c.Servers[server]; ok {
			if profileCfg, ok := serverCfg.Profiles[profile]; ok {
				if mode := strings.TrimSpace(profileCfg.Mode); mode != "" {
					return mode
				}
			}
		}
	}
	return strings.TrimSpace(c.DefaultMode)
}

func (c Config) EffectiveSplitInclude(server string, profile string) SplitIncludeConfig {
	result := mergeSplitIncludeOverride(SplitIncludeConfig{}, c.SplitInclude)
	server = strings.TrimSpace(server)
	profile = strings.TrimSpace(profile)
	if override, ok := c.Servers[server]; ok {
		result = mergeSplitIncludeOverride(result, override.SplitInclude)
		if profileOverride, ok := override.Profiles[profile]; ok {
			result = mergeSplitIncludeOverride(result, profileOverride.SplitInclude)
		}
	}
	if override, ok := c.Profiles[profile]; ok {
		result = mergeSplitIncludeOverride(result, override.SplitInclude)
	}
	return result
}

func (c Config) ResolveServerURLForProfile(profile string) (string, bool, error) {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return "", false, nil
	}

	matches := make([]string, 0, 1)
	for serverURL, serverCfg := range c.Servers {
		if _, ok := serverCfg.Profiles[profile]; ok {
			matches = append(matches, serverURL)
		}
	}
	sort.Strings(matches)

	switch len(matches) {
	case 0:
		return "", false, nil
	case 1:
		return matches[0], true, nil
	default:
		return "", false, fmt.Errorf("profile %q matched multiple configured servers: %s", profile, strings.Join(matches, ", "))
	}
}

func (c *Config) resolveRelativePaths(baseDir string) {
	if c.CacheDir != "" && !filepath.IsAbs(c.CacheDir) {
		c.CacheDir = filepath.Join(baseDir, c.CacheDir)
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

func absOrOriginal(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

func cloneSplitIncludeConfig(value SplitIncludeConfig) SplitIncludeConfig {
	return SplitIncludeConfig{
		Routes:         cloneStrings(value.Routes),
		VPNDomains:     cloneStrings(value.VPNDomains),
		BypassSuffixes: cloneStrings(value.BypassSuffixes),
		Nameservers:    cloneStrings(value.Nameservers),
	}
}

func mergeSplitIncludeOverride(base SplitIncludeConfig, override *SplitIncludeConfig) SplitIncludeConfig {
	if override == nil {
		return base
	}
	result := cloneSplitIncludeConfig(base)
	if override.Routes != nil {
		result.Routes = cloneStrings(override.Routes)
	}
	if override.VPNDomains != nil {
		result.VPNDomains = cloneStrings(override.VPNDomains)
	}
	if override.BypassSuffixes != nil {
		result.BypassSuffixes = cloneStrings(override.BypassSuffixes)
	}
	if override.Nameservers != nil {
		result.Nameservers = cloneStrings(override.Nameservers)
	}
	return result
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
			return value
		}
	}
	return ""
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
