package vpncorecli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestInspectVLESSURLDirectPrintsSafeProfileMetadata(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	raw := "vless://11111111-1111-1111-1111-111111111111@fr.example:443?security=reality&type=tcp&sni=www.example.com&fp=chrome&pbk=secret-public-key&sid=secret-short-id&flow=xtls-rprx-vision#France"
	exitCode := app.Run([]string{"inspect-vless-url", raw})
	if exitCode != 0 {
		t.Fatalf("Run(inspect-vless-url) exitCode = %d, want 0, stderr=%s", exitCode, stderr.String())
	}

	output := stdout.String()
	for _, want := range []string{
		"source_mode: direct",
		"attempts:",
		"- direct-uri: ok",
		"selected_attempt: direct-uri",
		"payload_format: plain",
		"profile_count: 1",
		"name=\"France\"",
		"endpoint=fr.example:443",
		"security=reality",
		"network=tcp",
		"public_key=present",
		"short_id=present",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("stdout = %q, want %q", output, want)
		}
	}
	for _, secret := range []string{
		"11111111-1111-1111-1111-111111111111",
		"secret-public-key",
		"secret-short-id",
		"vless://",
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("stdout leaked %q: %q", secret, output)
		}
	}
}

func TestInspectVLESSURLProxyChainReportsAttemptFailure(t *testing.T) {
	t.Parallel()

	report, err := inspectVLESSURL(t.Context(), "proxy", "://bad-url", vlessFetchOptions{})
	if err == nil {
		t.Fatal("inspectVLESSURL() error = nil, want error")
	}
	if got, want := report.SuccessIndex, -1; got != want {
		t.Fatalf("report.SuccessIndex = %d, want %d", got, want)
	}
	if len(report.Attempts) == 0 {
		t.Fatal("report.Attempts is empty")
	}
	if got, want := report.Attempts[0].Name, "proxy-default"; got != want {
		t.Fatalf("first attempt name = %q, want %q", got, want)
	}
}

func TestInspectVLESSURLRequiresOneURL(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	exitCode := app.Run([]string{"inspect-vless-url"})
	if exitCode != 2 {
		t.Fatalf("Run(inspect-vless-url) exitCode = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "pass exactly one URL") {
		t.Fatalf("stderr = %q, want URL count error", stderr.String())
	}
}

// A malformed direct URI must not be echoed back on stderr: it carries the
// account UUID and REALITY keys.
func TestInspectVLESSURLMalformedDirectURIDoesNotLeakIt(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	raw := "vless://SECRET-UUID-0000@bad host.example:443?pbk=SECRET-PBK#x"
	exitCode := app.Run([]string{"inspect-vless-url", raw})
	if exitCode == 0 {
		t.Fatalf("exitCode = 0, want failure for malformed URI")
	}
	for _, out := range []string{stdout.String(), stderr.String()} {
		if strings.Contains(out, "SECRET-UUID") || strings.Contains(out, "SECRET-PBK") {
			t.Fatalf("output leaks the URI: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
	if !strings.Contains(stderr.String(), "inspect-vless-url failed") {
		t.Fatalf("stderr = %q, want failure line", stderr.String())
	}
}

// Go escapes a backslash when quoting a malformed URL; secrets after it must
// still be redacted, and the error cause must survive.
func TestRedactVLESSProbeTextHandlesEscapedBackslash(t *testing.T) {
	t.Parallel()

	raw := `vless://SECRET-UUID@bad\host:443?pbk=SECRET-PBK&sid=SECRET-SID`
	single := fmt.Sprintf("parse %q: invalid character", raw)
	double := fmt.Sprintf("error=%q", single)
	for _, text := range []string{single, double} {
		got := redactVLESSProbeText(text, raw)
		for _, secret := range []string{"SECRET-UUID", "SECRET-PBK", "SECRET-SID"} {
			if strings.Contains(got, secret) {
				t.Fatalf("redactVLESSProbeText(%q) = %q, leaks %s", text, got, secret)
			}
		}
	}
	if got := redactVLESSProbeText(single, raw); !strings.Contains(got, "invalid character") {
		t.Fatalf("redactVLESSProbeText() = %q, lost the error cause", got)
	}
}
