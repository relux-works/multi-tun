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
