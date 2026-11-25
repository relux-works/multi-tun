package cli

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/core/vpncore"
)

type fcFakes struct {
	applied   [][]string
	ifaces    []string
	clears    int
	applyErr  error
	statusOut vpncore.FailClosedStatus
}

func withFailClosedFakes(t *testing.T, f *fcFakes, ifs []ifaceInfo, lookup map[string][]string) {
	t.Helper()
	prev := []any{failClosedApplyCLI, failClosedClearCLI, failClosedStatusCLI, failClosedLookupCLI, failClosedInterfacesCLI, failClosedNowCLI, failClosedTablePathCLI}
	tablePath := filepath.Join(t.TempDir(), "table.json")
	failClosedApplyCLI = func(_ vpncore.ServiceConfig, ifaces, table []string) error {
		f.ifaces = ifaces
		f.applied = append(f.applied, table)
		return f.applyErr
	}
	failClosedClearCLI = func(vpncore.ServiceConfig) error { f.clears++; return nil }
	failClosedStatusCLI = func(vpncore.ServiceConfig) (vpncore.FailClosedStatus, error) { return f.statusOut, nil }
	failClosedLookupCLI = func(_ context.Context, host string) ([]netip.Addr, error) {
		raw, ok := lookup[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, r := range raw {
			out = append(out, netip.MustParseAddr(r))
		}
		return out, nil
	}
	failClosedInterfacesCLI = func() ([]ifaceInfo, error) { return ifs, nil }
	failClosedNowCLI = func() time.Time { return time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC) }
	failClosedTablePathCLI = func() string { return tablePath }
	t.Cleanup(func() {
		failClosedApplyCLI = prev[0].(func(vpncore.ServiceConfig, []string, []string) error)
		failClosedClearCLI = prev[1].(func(vpncore.ServiceConfig) error)
		failClosedStatusCLI = prev[2].(func(vpncore.ServiceConfig) (vpncore.FailClosedStatus, error))
		failClosedLookupCLI = prev[3].(func(context.Context, string) ([]netip.Addr, error))
		failClosedInterfacesCLI = prev[4].(func() ([]ifaceInfo, error))
		failClosedNowCLI = prev[5].(func() time.Time)
		failClosedTablePathCLI = prev[6].(func() string)
	})
}

func writeFailClosedConfig(t *testing.T, failClosed string) string {
	t.Helper()
	cfgPath, _ := writeReconnectConfig(t, "us")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if failClosed != "" {
		s := strings.TrimSpace(string(data))
		s = strings.TrimSuffix(s, "}") + `, "fail_closed": ` + failClosed + "}"
		data = []byte(s)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

var upIfs = []ifaceInfo{{"lo0", true}, {"en0", true}, {"en5", false}, {"utun233", true}, {"utun4", true}, {"bridge0", true}}

// Claim: apply with the default policy resolves only codex domains, sends the helper the up physical
// interfaces (no utun, no down interface) and the public addresses (private ones dropped).
func TestFailClosedApplyDefaultCodex(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, map[string][]string{
		"chatgpt.com": {"104.18.32.47", "10.0.0.1"}, "api.openai.com": {"162.159.140.245"}, "anthropic.com": {"160.79.104.10"},
	})
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, "")})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Join(f.ifaces, ",") != "bridge0,en0" {
		t.Fatalf("interfaces = %v", f.ifaces)
	}
	if got := strings.Join(f.applied[0], ","); got != "104.18.32.47/32,162.159.140.245/32" {
		t.Fatalf("table = %s (anthropic must not be included in the codex-only default)", got)
	}
}

// Claim: enabled=false makes apply clear the anchor instead of applying anything.
func TestFailClosedApplyDisabledClears(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, nil)
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, `{"enabled":false}`)})
	if code != 0 || f.clears != 1 || len(f.applied) != 0 {
		t.Fatalf("exit %d clears %d applied %v: %s", code, f.clears, f.applied, errb.String())
	}
}

// Claim: when nothing resolves and no cidrs exist, apply refuses rather than loading an empty table.
func TestFailClosedApplyRefusesEmptyTable(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, map[string][]string{})
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, "")}); code == 0 || len(f.applied) != 0 {
		t.Fatalf("exit %d applied %v", code, f.applied)
	}
}

// Claim: a helper refusal is reported as a failure that names the untouched tunnel.
func TestFailClosedApplyHelperFailure(t *testing.T) {
	f := &fcFakes{applyErr: errors.New("pfctl failed")}
	withFailClosedFakes(t, f, upIfs, map[string][]string{"chatgpt.com": {"104.18.32.47"}})
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, "")})
	if code != 1 || !strings.Contains(errb.String(), "tunnel was not touched") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}

// Claim: off needs no config, calls only the helper clear, and prints how to keep it off.
func TestFailClosedOff(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, nil)
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"failclosed", "off"}); code != 0 || f.clears != 1 || len(f.applied) != 0 {
		t.Fatalf("exit %d clears %d", code, f.clears)
	}
	if !strings.Contains(out.String(), `"enabled": false`) {
		t.Fatalf("off output lacks the keep-off hint: %s", out.String())
	}
}

// Claim: status reports blocking=true only when the helper is enabled and the tunnel interface is down.
func TestFailClosedStatusBlocking(t *testing.T) {
	for _, tc := range []struct {
		ifs  []ifaceInfo
		want string
	}{
		{upIfs, "blocking: false"},
		{[]ifaceInfo{{"en0", true}}, "blocking: true"},
	} {
		f := &fcFakes{statusOut: vpncore.FailClosedStatus{Enabled: true, TableEntries: 3, TokenHeld: true}}
		withFailClosedFakes(t, f, tc.ifs, nil)
		var out, errb bytes.Buffer
		if code := New(&out, &errb).Run([]string{"failclosed", "status", "--config", writeFailClosedConfig(t, "")}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Fatalf("status = %s, want %q", out.String(), tc.want)
		}
	}
}

// Claim: an unknown subcommand is a usage error that calls nothing.
func TestFailClosedUnknownSubcommand(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, nil)
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"failclosed", "enable"}); code != 2 || f.clears != 0 || len(f.applied) != 0 {
		t.Fatalf("exit %d", code)
	}
}
