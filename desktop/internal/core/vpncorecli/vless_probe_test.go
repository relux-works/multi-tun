package vpncorecli

import (
	"bytes"
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
