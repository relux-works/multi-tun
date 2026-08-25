package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestSetupLoadResolveAndBuildSSHCommand(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	_, writtenPath, err := Setup(path, SetupOptions{
		ServerName: "dedicated",
		Host:       "relux-works-dedicated-macmini",
		SocksPort:  1081,
	}, false)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	if writtenPath != path {
		t.Fatalf("writtenPath = %q, want %q", writtenPath, path)
	}

	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	server, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if got, want := server.ListenEndpoint(), "127.0.0.1:1081"; got != want {
		t.Fatalf("ListenEndpoint() = %q, want %q", got, want)
	}
	wantArgs := []string{
		"-N", "-C", "-D", "127.0.0.1:1081",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ConnectTimeout=15",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		"relux-works-dedicated-macmini",
	}
	if got := server.SSHArgs(); !reflect.DeepEqual(got, wantArgs) {
		t.Fatalf("SSHArgs() = %q, want %q", got, wantArgs)
	}
}

func TestResolveAddsAccountOverride(t *testing.T) {
	t.Parallel()

	cfg := Config{Current: "dedicated", Servers: map[string]ServerConfig{
		"dedicated": {Host: "dedicated.example", Account: "administrator"},
	}}
	server, err := cfg.Resolve("")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	args := server.SSHArgs()
	if got, want := args[len(args)-3:], []string{"-l", "administrator", "dedicated.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("SSHArgs() tail = %q, want %q", got, want)
	}
}

func TestResolveRejectsMissingCurrentServer(t *testing.T) {
	t.Parallel()

	cfg := Config{Current: "missing", Servers: map[string]ServerConfig{
		"dedicated": {Host: "dedicated.example"},
	}}
	if _, err := cfg.Resolve(""); err == nil {
		t.Fatal("Resolve() error = nil, want missing current server error")
	}
}

func TestDefaultPathsUseSSHProxyXDGRoots(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/ssh-proxy-config")
	t.Setenv("XDG_CACHE_HOME", "/tmp/ssh-proxy-cache")

	if got, want := DefaultPath(), "/tmp/ssh-proxy-config/ssh-proxy/config.json"; got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
	if got, want := DefaultCacheDir("dedicated"), "/tmp/ssh-proxy-cache/ssh-proxy/dedicated"; got != want {
		t.Fatalf("DefaultCacheDir() = %q, want %q", got, want)
	}
}
