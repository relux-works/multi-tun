package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultListenAddress = "127.0.0.1"
	defaultSocksPort     = 1080
	defaultSSHExecutable = "/usr/bin/ssh"
)

type Config struct {
	Current string                  `json:"current,omitempty"`
	Servers map[string]ServerConfig `json:"servers"`
}

type ServerConfig struct {
	Host          string `json:"host"`
	Account       string `json:"account,omitempty"`
	ListenAddress string `json:"listen_address,omitempty"`
	SocksPort     int    `json:"socks_port,omitempty"`
	CacheDir      string `json:"cache_dir,omitempty"`
	SSHExecutable string `json:"ssh_executable,omitempty"`
}

type SetupOptions struct {
	ServerName    string
	Host          string
	Account       string
	ListenAddress string
	SocksPort     int
}

type ResolvedServer struct {
	Name          string
	Host          string
	Account       string
	ListenAddress string
	SocksPort     int
	CacheDir      string
	SSHExecutable string
}

func DefaultPath() string {
	return filepath.Join(userConfigRoot(), "ssh-proxy", "config.json")
}

func ResolvePath(path string) string {
	if path = strings.TrimSpace(path); path != "" {
		return path
	}
	return DefaultPath()
}

func DefaultCacheDir(serverName string) string {
	return filepath.Join(userCacheRoot(), "ssh-proxy", serverName)
}

func Setup(path string, options SetupOptions, force bool) (Config, string, error) {
	path = ResolvePath(path)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return Config{}, "", errors.New("config already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return Config{}, "", err
		}
	}

	serverName := strings.TrimSpace(options.ServerName)
	if serverName == "" {
		serverName = "default"
	}
	server := ServerConfig{
		Host:          strings.TrimSpace(options.Host),
		Account:       strings.TrimSpace(options.Account),
		ListenAddress: strings.TrimSpace(options.ListenAddress),
		SocksPort:     options.SocksPort,
		CacheDir:      DefaultCacheDir(serverName),
		SSHExecutable: defaultSSHExecutable,
	}
	if server.ListenAddress == "" {
		server.ListenAddress = defaultListenAddress
	}
	if server.SocksPort == 0 {
		server.SocksPort = defaultSocksPort
	}

	cfg := Config{
		Current: serverName,
		Servers: map[string]ServerConfig{serverName: server},
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Config{}, "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Config{}, "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return Config{}, "", err
	}
	return cfg, path, nil
}

func Load(path string) (Config, string, error) {
	path = ResolvePath(path)
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, "", err
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, "", err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, "", err
	}
	return cfg, path, nil
}

func (c Config) Validate() error {
	if len(c.Servers) == 0 {
		return errors.New("servers must contain at least one SSH proxy profile")
	}
	if current := strings.TrimSpace(c.Current); current != "" {
		if _, ok := c.Servers[current]; !ok {
			return fmt.Errorf("current server %q is not configured", current)
		}
	}
	for name, server := range c.Servers {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t\n") {
			return fmt.Errorf("server name %q must be a single non-empty token", name)
		}
		if err := validateServer(name, server); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) Resolve(serverName string) (ResolvedServer, error) {
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		serverName = strings.TrimSpace(c.Current)
	}
	if serverName == "" && len(c.Servers) == 1 {
		for name := range c.Servers {
			serverName = name
		}
	}
	if serverName == "" {
		return ResolvedServer{}, errors.New("select a server with --server because config.current is empty")
	}
	server, ok := c.Servers[serverName]
	if !ok {
		return ResolvedServer{}, fmt.Errorf("configured server %q was not found", serverName)
	}
	if err := validateServer(serverName, server); err != nil {
		return ResolvedServer{}, err
	}

	resolved := ResolvedServer{
		Name:          serverName,
		Host:          strings.TrimSpace(server.Host),
		Account:       strings.TrimSpace(server.Account),
		ListenAddress: strings.TrimSpace(server.ListenAddress),
		SocksPort:     server.SocksPort,
		CacheDir:      strings.TrimSpace(server.CacheDir),
		SSHExecutable: strings.TrimSpace(server.SSHExecutable),
	}
	if resolved.ListenAddress == "" {
		resolved.ListenAddress = defaultListenAddress
	}
	if resolved.SocksPort == 0 {
		resolved.SocksPort = defaultSocksPort
	}
	if resolved.CacheDir == "" {
		resolved.CacheDir = DefaultCacheDir(serverName)
	}
	if resolved.SSHExecutable == "" {
		resolved.SSHExecutable = defaultSSHExecutable
	}
	return resolved, nil
}

func (s ResolvedServer) ListenEndpoint() string {
	return net.JoinHostPort(s.ListenAddress, fmt.Sprintf("%d", s.SocksPort))
}

func (s ResolvedServer) SSHArgs() []string {
	args := []string{
		"-N",
		"-C",
		"-D", s.ListenEndpoint(),
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=15",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
	}
	if s.Account != "" {
		args = append(args, "-l", s.Account)
	}
	return append(args, s.Host)
}

func validateServer(name string, server ServerConfig) error {
	host := strings.TrimSpace(server.Host)
	if host == "" || len(strings.Fields(host)) != 1 {
		return fmt.Errorf("servers.%s.host must be one SSH host or alias", name)
	}
	listenAddress := strings.TrimSpace(server.ListenAddress)
	if listenAddress != "" && net.ParseIP(listenAddress) == nil {
		return fmt.Errorf("servers.%s.listen_address must be an IP address", name)
	}
	if server.SocksPort < 0 || server.SocksPort > 65535 {
		return fmt.Errorf("servers.%s.socks_port must be between 1 and 65535", name)
	}
	return nil
}

func userConfigRoot() string {
	if value := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); value != "" {
		return value
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".config")
	}
	return ".config"
}

func userCacheRoot() string {
	if value := strings.TrimSpace(os.Getenv("XDG_CACHE_HOME")); value != "" {
		return value
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".cache")
	}
	return ".cache"
}
