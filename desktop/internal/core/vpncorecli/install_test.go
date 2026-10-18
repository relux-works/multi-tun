package vpncorecli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"multi-tun/desktop/internal/core/vpncore"
)

func TestInstallRequiresExpectedDigestAndNoPositionalArguments(t *testing.T) {
	// This proves missing, malformed, uppercase, and stray install inputs are refused before the install API is called.
	previous := installServiceVPNCoreCLI
	called := false
	installServiceVPNCoreCLI = func(vpncore.ServiceConfig, string, int, int, string) error {
		called = true
		return nil
	}
	t.Cleanup(func() { installServiceVPNCoreCLI = previous })

	cases := [][]string{
		{"install"},
		{"install", "--expect-sha256", "abc"},
		{"install", "--expect-sha256", strings.Repeat("A", 64)},
		{"install", "--expect-sha256", strings.Repeat("a", 64), "stray"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := New(&stdout, &stderr).Run(args); code != 2 {
			t.Fatalf("Run(%v) code = %d, want 2; stderr=%q", args, code, stderr.String())
		}
	}
	if called {
		t.Fatal("invalid install arguments reached InstallService")
	}
}

func TestInstallDigestPrintsComputedDigest(t *testing.T) {
	// This proves install-digest emits one lowercase digest and rejects positional ambiguity.
	previous := installDigestVPNCoreCLI
	installDigestVPNCoreCLI = func(string) (string, error) { return strings.Repeat("b", 64), nil }
	t.Cleanup(func() { installDigestVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 0 {
		t.Fatalf("install-digest code = %d, stderr=%q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != strings.Repeat("b", 64) {
		t.Fatalf("install-digest output = %q", got)
	}
	stdout.Reset()
	stderr.Reset()
	if code := New(&stdout, &stderr).Run([]string{"install-digest", "stray"}); code != 2 {
		t.Fatalf("install-digest stray code = %d", code)
	}
}

func TestInstallDigestFailureIsReported(t *testing.T) {
	// This proves digest computation failures cannot fall through to installation.
	previous := installDigestVPNCoreCLI
	installDigestVPNCoreCLI = func(string) (string, error) { return "", errors.New("hash failed") }
	t.Cleanup(func() { installDigestVPNCoreCLI = previous })
	var stdout, stderr bytes.Buffer
	if code := New(&stdout, &stderr).Run([]string{"install-digest"}); code != 1 {
		t.Fatalf("install-digest code = %d, want 1", code)
	}
}
