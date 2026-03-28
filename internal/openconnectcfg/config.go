package openconnectcfg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	CacheDir       string             `json:"cache_dir,omitempty"`
	DefaultServer  string             `json:"default_server,omitempty"`
	DefaultProfile string             `json:"default_profile,omitempty"`
	DefaultMode    string             `json:"default_mode,omitempty"`
	SplitInclude   SplitIncludeConfig `json:"split_include,omitempty"`
	Auth           AuthConfig         `json:"auth,omitempty"`
}

type SplitIncludeConfig struct {
	Routes      []string `json:"routes,omitempty"`
	VPNDomains  []string `json:"vpn_domains,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
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

func absOrOriginal(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}
