package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartAlias_UsesStartFailurePrefix(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	missingConfig := filepath.Join(t.TempDir(), "missing.json")
	exitCode := app.Run([]string{"start", "--config", missingConfig})
	if exitCode != 1 {
		t.Fatalf("Run(start) exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "start failed:") {
		t.Fatalf("stderr = %q, want start failure prefix", stderr.String())
	}
}

func TestStartAlias_UsesPositionalConfigName(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"start", "dance"})
	if exitCode != 1 {
		t.Fatalf("Run(start) exitCode = %d, want 1", exitCode)
	}
	expectedPath := filepath.Join(configRoot, "vless-tun", "dance.json")
	if !strings.Contains(stderr.String(), expectedPath+" does not exist") {
		t.Fatalf("stderr = %q, want resolved config path %q", stderr.String(), expectedPath)
	}
}

func TestCommandConfigPathResolvesRelativeNameUnderConfigDir(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)

	got, err := commandConfigPath("", []string{"fortinet"})
	if err != nil {
		t.Fatalf("commandConfigPath() error = %v", err)
	}

	want := filepath.Join(configRoot, "vless-tun", "fortinet.json")
	if got != want {
		t.Fatalf("commandConfigPath() = %q, want %q", got, want)
	}
}

func TestCommandConfigPathPreservesAbsolutePath(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "custom.json")

	got, err := commandConfigPath("", []string{absolute})
	if err != nil {
		t.Fatalf("commandConfigPath() error = %v", err)
	}
	if got != absolute {
		t.Fatalf("commandConfigPath() = %q, want %q", got, absolute)
	}
}

func TestCommandConfigPathRejectsFlagAndPositionalConfig(t *testing.T) {
	_, err := commandConfigPath("/tmp/config.json", []string{"dance"})
	if err == nil {
		t.Fatal("commandConfigPath() error = nil, want error")
	}
	if !strings.Contains(err.Error(), "both with --config and positional argument") {
		t.Fatalf("commandConfigPath() error = %q", err)
	}
}

func TestSetupWritesConfigAndReportsPath(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	configPath := filepath.Join(t.TempDir(), "vless.json")
	exitCode := app.Run([]string{
		"setup",
		"--config", configPath,
		"--source-url", "vless://uuid@example.com:443?security=reality#demo",
		"--profile", "demo",
	})
	if exitCode != 0 {
		t.Fatalf("Run(setup) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "config: "+configPath) {
		t.Fatalf("stdout = %q, want config path", stdout.String())
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("Stat(configPath) error = %v", err)
	}
}
