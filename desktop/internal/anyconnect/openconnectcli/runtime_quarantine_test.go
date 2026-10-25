package openconnectcli

import (
	"bytes"
	"strings"
	"testing"
)

func TestHiddenRuntimeQuarantineCommandDispatch(t *testing.T) {
	// The compatibility CLI can route its own privileged quarantine invocation; malformed arguments fail without host operations.
	var stdout, stderr bytes.Buffer
	app := New(&stdout, &stderr)
	if code := app.Run([]string{"_quarantine-runtime"}); code != 1 || !strings.Contains(stderr.String(), "quarantine move requires [known-label] device inode; no path arguments") {
		t.Fatalf("code=%d stderr=%q, want quarantine validation failure", code, stderr.String())
	}
	stdout.Reset()
	if code := app.Run([]string{"help"}); code != 0 || strings.Contains(stdout.String(), "_quarantine-runtime") {
		t.Fatalf("help code=%d output=%q, want hidden command omitted", code, stdout.String())
	}
}
