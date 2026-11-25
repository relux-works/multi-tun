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
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/subscription"
)

type fcFakes struct {
	applied   [][]string
	ifaces    []string
	clears    int
	applyErr  error
	statusOut vpncore.FailClosedStatus

	tunnelServer netip.AddrPort
}

func withFailClosedFakes(t *testing.T, f *fcFakes, ifs []ifaceInfo, lookup map[string][]string) {
	t.Helper()
	prev := []any{failClosedApplyCLI, failClosedClearCLI, failClosedStatusCLI, failClosedLookupCLI, failClosedInterfacesCLI, failClosedNowCLI, failClosedTablePathCLI, failClosedTunnelLookupCLI}
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
	failClosedTunnelLookupCLI = func(_ context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
		f.tunnelServer = server
		raw, ok := lookup["tunnel:"+host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, r := range raw {
			out = append(out, netip.MustParseAddr(r))
		}
		return out, nil
	}
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
		failClosedTunnelLookupCLI = prev[7].(func(context.Context, netip.AddrPort, string) ([]netip.Addr, error))
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

// Usage and a failed durable clear both retain the emergency flush followed by
// the durable off command. The successful control reports off without advice.
func TestFailClosedEmergencyFollowup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		clearErr error
		code     int
	}{
		{"usage", []string{"failclosed"}, nil, 2},
		{"failed off", []string{"failclosed", "off"}, errors.New("helper unavailable"), 1},
		{"off", []string{"failclosed", "off"}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fcFakes{}
			withFailClosedFakes(t, f, nil, nil)
			failClosedClearCLI = func(vpncore.ServiceConfig) error { f.clears++; return tc.clearErr }
			var out, errb bytes.Buffer
			if code := New(&out, &errb).Run(tc.args); code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, errb.String())
			}
			if tc.code != 0 {
				flush := "sudo pfctl -a com.apple/works.relux.vpn-core.failclosed -F all"
				parts := strings.SplitN(errb.String(), flush, 2)
				if len(parts) != 2 || !strings.Contains(parts[1], "vless-tun failclosed off") {
					t.Fatalf("emergency advice lacks durable follow-up: %q", errb.String())
				}
			} else if errb.Len() != 0 || !strings.Contains(out.String(), "fail_closed: off") {
				t.Fatalf("successful off: stdout=%q stderr=%q", out.String(), errb.String())
			}
			wantClears := 1
			if tc.name == "usage" {
				wantClears = 0
			}
			if f.clears != wantClears || len(f.applied) != 0 {
				t.Fatalf("helper calls: clears=%d applied=%v", f.clears, f.applied)
			}
		})
	}
}

// README emergency advice must put durable off in the same paragraph as the
// manual flush so an owner is told to persist the change after recovery.
func TestFailClosedReadmeEmergencyFollowup(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "sudo pfctl -a com.apple/works.relux.vpn-core.failclosed -F all") {
			if !strings.Contains(line, "once it answers again, run `vless-tun failclosed off`") {
				t.Fatalf("emergency paragraph lacks durable follow-up: %s", line)
			}
			return
		}
	}
	t.Fatal("README emergency flush advice missing")
}

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

// Claim: status reports blocking=true only when the helper is live-enforcing (pf enabled, anchor and
// table loaded) and the tunnel interface is down; a stored enabled policy that pf no longer enforces
// reports enforcing=false and blocking=false. The coverage limit line is always printed.
func TestFailClosedStatusBlocking(t *testing.T) {
	live := vpncore.FailClosedStatus{Enabled: true, TableEntries: 3, TokenHeld: true, LiveChecked: true, PFEnabled: true, AnchorLoaded: true, LiveTableEntries: 3, Enforcing: true}
	stale := vpncore.FailClosedStatus{Enabled: true, TableEntries: 3, TokenHeld: true, LiveChecked: true, PFEnabled: false}
	for _, tc := range []struct {
		st   vpncore.FailClosedStatus
		ifs  []ifaceInfo
		want []string
	}{
		{live, upIfs, []string{"enforcing: true", "blocking: false"}},
		{live, []ifaceInfo{{"en0", true}}, []string{"enforcing: true", "blocking: true"}},
		{stale, []ifaceInfo{{"en0", true}}, []string{"pf_enabled: false", "enforcing: false", "blocking: false"}},
	} {
		f := &fcFakes{statusOut: tc.st}
		withFailClosedFakes(t, f, tc.ifs, nil)
		var out, errb bytes.Buffer
		if code := New(&out, &errb).Run([]string{"failclosed", "status", "--config", writeFailClosedConfig(t, "")}); code != 0 {
			t.Fatalf("exit %d: %s", code, errb.String())
		}
		for _, w := range append(tc.want, "limit: unknown subdomains on other addresses are not blocked") {
			if !strings.Contains(out.String(), w) {
				t.Fatalf("status = %s, want %q", out.String(), w)
			}
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

func reconnectWithLaunchMode(t *testing.T, launchMode string) (int, string, string) {
	t.Helper()
	path, cacheDir := writeStableAliasReconnectConfig(t, "vless://00000000-0000-0000-0000-000000000003@203.0.113.10:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA")
	if _, err := subscription.Refresh(t.Context(), "direct", "vless://00000000-0000-0000-0000-000000000004@203.0.113.99:8443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA", cacheDir); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	installRefreshFailure(t, transientFetchError("temporary timeout"))
	installReconnectHarness(t)
	prev := startSessionFunc
	startSessionFunc = func(cacheDir, configPath string, profile model.Profile, options session.StartOptions) (session.CurrentSession, error) {
		return session.CurrentSession{ID: "replacement", PID: 4343, LaunchMode: launchMode}, nil
	}
	t.Cleanup(func() { startSessionFunc = prev })
	var out, errb bytes.Buffer
	code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
	return code, out.String(), errb.String()
}

// Claim: after a helper-launched reconnect, the fail-closed table is refreshed with the tunnel up and
// the summary is printed; a helper apply failure is only a warning and the reconnect still succeeds.
func TestFailClosedRefreshAfterReconnect(t *testing.T) {
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, map[string][]string{"chatgpt.com": {"104.18.32.47"}})
	code, out, errs := reconnectWithLaunchMode(t, "helper")
	if code != 0 || len(f.applied) != 1 || !strings.Contains(out, "fail_closed: active services=codex") || !strings.Contains(out, "tunnel=up") {
		t.Fatalf("code %d applied %v out=%q err=%q", code, f.applied, out, errs)
	}
	f2 := &fcFakes{applyErr: errors.New("unsupported vpn core action")}
	withFailClosedFakes(t, f2, upIfs, map[string][]string{"chatgpt.com": {"104.18.32.47"}})
	code, _, errs = reconnectWithLaunchMode(t, "helper")
	if code != 0 || !strings.Contains(errs, "tunnel is unaffected") {
		t.Fatalf("apply failure: code %d err=%q", code, errs)
	}
}

// Claim: a session not launched through the helper makes no fail-closed call at all (the guard fakes
// installed by init would fail the run if one were made).
func TestFailClosedNoRefreshWithoutHelper(t *testing.T) {
	code, out, errs := reconnectWithLaunchMode(t, "sudo")
	if code != 0 || strings.Contains(out, "fail_closed") || strings.Contains(errs, "fail_closed") {
		t.Fatalf("code %d out=%q err=%q", code, out, errs)
	}
}

// Claim: with the tunnel up, the table is the union of the system resolver and the tunnel DNS (the
// TUN peer address, 172.19.0.2:53 for 172.19.0.1/30); with the tunnel down only the system answer is
// used and the tunnel resolver is not asked.
func TestFailClosedResolvesUnionOfSystemAndTunnelDNS(t *testing.T) {
	lookup := map[string][]string{"chatgpt.com": {"104.18.32.47"}, "tunnel:chatgpt.com": {"8.6.112.0"}}
	f := &fcFakes{}
	withFailClosedFakes(t, f, upIfs, lookup)
	var out, errb bytes.Buffer
	if code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, "")}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if got := strings.Join(f.applied[0], ","); got != "104.18.32.47/32,8.6.112.0/32" || f.tunnelServer.String() != "172.19.0.2:53" {
		t.Fatalf("tunnel up: table %s server %v", got, f.tunnelServer)
	}
	f2 := &fcFakes{}
	withFailClosedFakes(t, f2, []ifaceInfo{{"en0", true}}, lookup)
	if code := New(&out, &errb).Run([]string{"failclosed", "apply", "--config", writeFailClosedConfig(t, "")}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if got := strings.Join(f2.applied[0], ","); got != "104.18.32.47/32" || f2.tunnelServer.IsValid() {
		t.Fatalf("tunnel down: table %s server %v", got, f2.tunnelServer)
	}
}

// Claim: diagnose prints a read-only fail_closed line with live enforcement and the limit, and makes
// no apply or clear call.
func TestDiagnoseShowsFailClosed(t *testing.T) {
	f := &fcFakes{statusOut: vpncore.FailClosedStatus{Enabled: true, LiveChecked: true, PFEnabled: true, AnchorLoaded: true, Enforcing: true}}
	withFailClosedFakes(t, f, upIfs, nil)
	var out, errb bytes.Buffer
	New(&out, &errb).Run([]string{"diagnose", "--config", writeFailClosedConfig(t, "")})
	if !strings.Contains(out.String(), "fail_closed: services=codex enforcing=true pf_enabled=true anchor_loaded=true (unknown subdomains") {
		t.Fatalf("diagnose output lacks fail_closed line:\n%s", out.String())
	}
	if len(f.applied) != 0 || f.clears != 0 {
		t.Fatalf("diagnose changed fail-closed state: applied %v clears %d", f.applied, f.clears)
	}
}

// Claim: with the helper installed, reconnect applies the policy before the new tunnel starts (so a
// first start is already fail closed) and refreshes it after: the call order is apply, start, apply.
// Without the helper the pre-start apply is skipped and makes no call.
func TestFailClosedAppliedBeforeStart(t *testing.T) {
	for _, tc := range []struct {
		ready bool
		want  string
	}{{true, "apply,start,apply"}, {false, "start,apply"}} {
		f := &fcFakes{}
		withFailClosedFakes(t, f, upIfs, map[string][]string{"chatgpt.com": {"104.18.32.47"}})
		var order []string
		prevApply := failClosedApplyCLI
		failClosedApplyCLI = func(c vpncore.ServiceConfig, i, tb []string) error {
			order = append(order, "apply")
			return prevApply(c, i, tb)
		}
		prevReady := failClosedHelperReadyCLI
		failClosedHelperReadyCLI = func() bool { return tc.ready }
		path, cacheDir := writeStableAliasReconnectConfig(t, "vless://00000000-0000-0000-0000-000000000003@203.0.113.10:443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA")
		if _, err := subscription.Refresh(t.Context(), "direct", "vless://00000000-0000-0000-0000-000000000004@203.0.113.99:8443?type=tcp&security=reality&pbk=abc&fp=chrome&sni=example.com&sid=1#%F0%9F%87%BA%F0%9F%87%B8%20USA", cacheDir); err != nil {
			t.Fatal(err)
		}
		installRefreshFailure(t, transientFetchError("temporary timeout"))
		installReconnectHarness(t)
		prevStart := startSessionFunc
		startSessionFunc = func(string, string, model.Profile, session.StartOptions) (session.CurrentSession, error) {
			order = append(order, "start")
			return session.CurrentSession{ID: "r", PID: 1, LaunchMode: "helper"}, nil
		}
		var out, errb bytes.Buffer
		code := New(&out, &errb).Run([]string{"reconnect", "--config", path})
		startSessionFunc, failClosedApplyCLI, failClosedHelperReadyCLI = prevStart, prevApply, prevReady
		if code != 0 || strings.Join(order, ",") != tc.want {
			t.Fatalf("ready=%v: exit %d order %v want %s: %s", tc.ready, code, order, tc.want, errb.String())
		}
	}
}
