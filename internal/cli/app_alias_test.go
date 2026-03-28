package cli

import (
	"bytes"
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
