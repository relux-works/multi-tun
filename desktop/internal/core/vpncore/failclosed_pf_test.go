package vpncore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"multi-tun/desktop/internal/core/failclosed"
)

// fakePF records every pfctl call and models the enable token and the anchor.
type fakePF struct {
	calls     []string
	stdin     []string
	nextToken int
	held      map[string]bool
	failOn    string // substring of the joined args that fails
}

func (f *fakePF) run(args []string, stdin string) ([]byte, error) {
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, joined)
	f.stdin = append(f.stdin, stdin)
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return []byte("pfctl: simulated failure"), errors.New("exit status 1")
	}
	if f.held == nil {
		f.held = map[string]bool{}
	}
	switch {
	case joined == "-E":
		f.nextToken++
		tok := strings.Repeat("1", 1) + string(rune('0'+f.nextToken))
		f.held[tok] = true
		return []byte("No ALTQ support in kernel\npf enabled\nToken : " + tok + "\n"), nil
	case strings.HasPrefix(joined, "-X "):
		tok := strings.TrimPrefix(joined, "-X ")
		if !f.held[tok] {
			return []byte("pfctl: invalid token"), errors.New("exit status 1")
		}
		delete(f.held, tok)
	}
	return nil, nil
}

func newTestManager(t *testing.T, f *fakePF) *failClosedManager {
	t.Helper()
	return &failClosedManager{
		statePath: filepath.Join(t.TempDir(), "state", "failclosed.json"),
		pfctl:     f.run,
		now:       func() time.Time { return time.Date(2026, 11, 25, 13, 0, 0, 0, time.UTC) },
	}
}

var goodReq = FailClosedRequest{Interfaces: []string{"en0"}, Table: []string{"104.18.32.47/32", "160.79.104.0/23"}}

// Claim: Apply acquires one pf token, loads only our anchor and replaces only its table, never calls
// a pf.conf reload (-f /etc/pf.conf), never disables pf (-d) and never names another anchor; the
// anchor text sent is the rendered one, with no utun interface.
func TestFailClosedApplyTouchesOnlyOwnAnchor(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	if err := m.Apply(goodReq); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-E",
		"-a " + failclosed.AnchorName + " -f -",
		"-a " + failclosed.AnchorName + " -t failclosed -T replace -f -",
	}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", f.calls, want)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "/etc/pf.conf") || c == "-d" || strings.Contains(c, "cisco") || strings.Contains(c, "vpn_slice") {
			t.Fatalf("forbidden pfctl call %q", c)
		}
	}
	if strings.Contains(f.stdin[1], "utun") || !strings.Contains(f.stdin[1], "on { en0 }") {
		t.Fatalf("anchor text = %q", f.stdin[1])
	}
	if f.stdin[2] != "104.18.32.47/32\n160.79.104.0/23\n" {
		t.Fatalf("table stdin = %q", f.stdin[2])
	}
	st, _ := m.Status()
	if !st.Enabled || !st.TokenHeld || st.TableEntries != 2 {
		t.Fatalf("status = %+v", st)
	}
}

// Claim: a second Apply reuses the held token (no pf reference leak).
func TestFailClosedReapplyReusesToken(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	_ = m.Apply(goodReq)
	_ = m.Apply(goodReq)
	enables := 0
	for _, c := range f.calls {
		if c == "-E" {
			enables++
		}
	}
	if enables != 1 || len(f.held) != 1 {
		t.Fatalf("enables=%d held=%v", enables, f.held)
	}
}

// Claim: invalid requests are refused before any pfctl call (no token taken, no state written).
func TestFailClosedApplyRefusesBeforePF(t *testing.T) {
	for name, req := range map[string]FailClosedRequest{
		"utun interface":    {Interfaces: []string{"utun233"}, Table: goodReq.Table},
		"no interfaces":     {Table: goodReq.Table},
		"private table":     {Interfaces: []string{"en0"}, Table: []string{"192.168.0.0/16"}},
		"malformed table":   {Interfaces: []string{"en0"}, Table: []string{"1.2.3.4"}},
		"injected ifname":   {Interfaces: []string{"en0 } pass all {"}, Table: goodReq.Table},
		"empty table":       {Interfaces: []string{"en0"}, Table: nil},
		"empty table slice": {Interfaces: []string{"en0"}, Table: []string{}},
	} {
		f := &fakePF{}
		m := newTestManager(t, f)
		if err := m.Apply(req); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(f.calls) != 0 {
			t.Errorf("%s: pfctl called %q", name, f.calls)
		}
		if _, err := os.Stat(m.statePath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: state written", name)
		}
	}
}

// Claim: when loading the table fails after the token was taken, the token is recorded (so it can be
// released), the error is reported in status, and nothing is flushed.
func TestFailClosedApplyFailureKeepsTokenAndRules(t *testing.T) {
	f := &fakePF{failOn: "-T replace"}
	m := newTestManager(t, f)
	if err := m.Apply(goodReq); err == nil {
		t.Fatal("expected failure")
	}
	for _, c := range f.calls {
		if strings.Contains(c, "-F") {
			t.Fatalf("flushed on failure: %q", c)
		}
	}
	st, _ := m.Status()
	if !st.TokenHeld || st.LastError == "" || st.Enabled {
		t.Fatalf("status after failure = %+v", st)
	}
}

// Claim: Clear flushes only our anchor, releases our token, and persists enabled=false so a later
// daemon start does not re-apply.
func TestFailClosedClearPersistsOff(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	_ = m.Apply(goodReq)
	f.calls = nil
	if err := m.Clear(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, "|") != "-a "+failclosed.AnchorName+" -F all|-X 11" {
		t.Fatalf("clear calls = %q", f.calls)
	}
	if len(f.held) != 0 {
		t.Fatalf("token still held: %v", f.held)
	}
	f.calls = nil
	if err := m.ReapplyAtStart(); err != nil || len(f.calls) != 0 {
		t.Fatalf("reapply after off: err=%v calls=%q", err, f.calls)
	}
}

// Claim: at daemon start an enabled state is re-applied with a fresh token after releasing the stale
// one, so a daemon restart does not leak a pf reference.
func TestFailClosedReapplyAtStart(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	_ = m.Apply(goodReq)
	f.calls = nil
	m2 := &failClosedManager{statePath: m.statePath, pfctl: f.run, now: m.now}
	if err := m2.ReapplyAtStart(); err != nil {
		t.Fatal(err)
	}
	if f.calls[0] != "-X 11" || f.calls[1] != "-E" || len(f.held) != 1 {
		t.Fatalf("calls=%q held=%v", f.calls, f.held)
	}
}

// Claim: a corrupt state file makes the start-time re-apply report an error without any pfctl call
// (rules already loaded are left alone). Clear still flushes the anchor so the owner can roll back:
// it releases a token it can still read from the raw bytes and reports success; when no token can be
// recovered it reports an error instead of success, so token ownership is never lost silently.
func TestFailClosedCorruptState(t *testing.T) {
	for name, tc := range map[string]struct {
		raw         string
		wantRelease bool
		wantErr     bool
	}{
		"token recoverable":   {raw: `{"enabled":true,"token":"11",`, wantRelease: true},
		"token unrecoverable": {raw: "{not json", wantErr: true},
	} {
		f := &fakePF{held: map[string]bool{"11": true}}
		m := newTestManager(t, f)
		os.MkdirAll(filepath.Dir(m.statePath), 0o755)
		os.WriteFile(m.statePath, []byte(tc.raw), 0o600)
		if err := m.ReapplyAtStart(); err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("%s: reapply err = %v", name, err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("%s: pfctl called on corrupt state: %q", name, f.calls)
		}
		err := m.Clear()
		if f.calls[0] != "-a "+failclosed.AnchorName+" -F all" {
			t.Fatalf("%s: clear calls = %q", name, f.calls)
		}
		released := strings.Contains(strings.Join(f.calls, "|"), "-X 11")
		if released != tc.wantRelease || (err != nil) != tc.wantErr {
			t.Fatalf("%s: released=%v err=%v", name, released, err)
		}
		if tc.wantErr && !strings.Contains(err.Error(), "could not be recovered") {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

// Claim: when the token was acquired but cannot be recorded (state not writable), Apply gives the
// token back and fails, so no pf reference is orphaned.
func TestFailClosedApplyReleasesTokenWhenStateUnwritable(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	dir := filepath.Dir(m.statePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
	err := m.Apply(goodReq)
	if err == nil || !strings.Contains(err.Error(), "released") {
		t.Fatalf("apply err = %v", err)
	}
	if len(f.held) != 0 || strings.Join(f.calls, "|") != "-E|-X 11" {
		t.Fatalf("calls %q held %v", f.calls, f.held)
	}
}

// Claim: the three fail-closed actions are known; failclosed.apply needs its payload and accepts no
// other field; clear and status accept no payload; no other action may carry a fail_closed payload.
func TestFailClosedRequestShape(t *testing.T) {
	for _, a := range []string{"failclosed.apply", "failclosed.clear", "failclosed.status"} {
		if !knownAction(a) {
			t.Fatalf("%s not known", a)
		}
	}
	payload := &FailClosedRequest{Interfaces: []string{"en0"}, Table: []string{"1.1.1.1/32"}}
	if err := validateRequestShape(Request{Action: "failclosed.apply", FailClosed: payload}); err != nil {
		t.Fatalf("valid apply refused: %v", err)
	}
	for _, a := range []string{"failclosed.clear", "failclosed.status"} {
		if err := validateRequestShape(Request{Action: a}); err != nil {
			t.Fatalf("valid %s refused: %v", a, err)
		}
	}
	bad := map[string]Request{
		"apply without payload": {Action: "failclosed.apply"},
		"apply empty table":     {Action: "failclosed.apply", FailClosed: &FailClosedRequest{Interfaces: []string{"en0"}}},
		"apply no interfaces":   {Action: "failclosed.apply", FailClosed: &FailClosedRequest{Table: []string{"1.1.1.1/32"}}},
		"apply with stdin":      {Action: "failclosed.apply", FailClosed: payload, Stdin: "x"},
		"apply with interface":  {Action: "failclosed.apply", FailClosed: payload, Interface: "en0"},
		"clear with payload":    {Action: "failclosed.clear", FailClosed: payload},
		"status with handle":    {Action: "failclosed.status", Handle: "h"},
		"ping with payload":     {Action: "ping", FailClosed: payload},
		"singbox with payload":  {Action: "singbox.start", ConfigJSON: []byte("{}"), FailClosed: payload},
		"apply oversized table": {Action: "failclosed.apply", FailClosed: &FailClosedRequest{Interfaces: []string{"en0"}, Table: make([]string, 4097)}},
	}
	for name, r := range bad {
		if err := validateRequestShape(r); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if safeRequestAction("failclosed.apply") != "failclosed.apply" {
		t.Error("diagnostics hides the fail-closed action name")
	}
}

// statefulPF models pf enough for the watchdog: enable references, our anchor's rules and table, and
// what other parties do to them.
type statefulPF struct {
	enabled bool
	tokens  map[string]bool
	next    int
	rules   string
	table   string
	calls   []string
}

func (p *statefulPF) run(args []string, stdin string) ([]byte, error) {
	j := strings.Join(args, " ")
	p.calls = append(p.calls, j)
	if p.tokens == nil {
		p.tokens = map[string]bool{}
	}
	switch {
	case j == "-E":
		p.next++
		tok := "7" + string(rune('0'+p.next))
		p.tokens[tok], p.enabled = true, true
		return []byte("Token : " + tok + "\n"), nil
	case strings.HasPrefix(j, "-X "):
		delete(p.tokens, strings.TrimPrefix(j, "-X "))
		if len(p.tokens) == 0 {
			p.enabled = false
		}
	case j == "-s info":
		if p.enabled {
			return []byte("Status: Enabled for 0 days 00:01:00\n"), nil
		}
		return []byte("Status: Disabled\n"), nil
	case strings.HasSuffix(j, " -f -") && !strings.Contains(j, "-T"):
		p.rules = stdin
	case strings.Contains(j, "-T replace"):
		p.table = stdin
	case strings.HasSuffix(j, "-s rules"):
		return []byte(pfNormalizedRules(p.rules)), nil
	case strings.HasSuffix(j, "-T show"):
		return []byte(pfShownTable(p.table)), nil
	case strings.HasSuffix(j, "-F all"):
		p.rules, p.table = "", ""
	}
	return nil, nil
}

// pfNormalizedRules mimics pfctl -s rules: no comments or table definitions,
// one "block return out quick on IF from any to <t>" line per interface, and
// any other rule line passed through.
func pfNormalizedRules(loaded string) string {
	var out []string
	for _, line := range strings.Split(loaded, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, "table "):
		case strings.HasPrefix(line, "block return out quick on { "):
			rest := strings.TrimPrefix(line, "block return out quick on { ")
			ifs := strings.Fields(rest[:strings.Index(rest, "}")])
			for _, i := range ifs {
				out = append(out, "block return out quick on "+i+" from any to <failclosed>")
			}
		default:
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// pfShownTable mimics pfctl -T show: host entries without a prefix length.
func pfShownTable(loaded string) string {
	var out []string
	for _, l := range strings.Split(loaded, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, "   "+strings.TrimSuffix(strings.TrimSuffix(l, "/32"), "/128"))
	}
	return strings.Join(out, "\n") + "\n"
}

// Other parties' acts (not our calls).
func (p *statefulPF) reloadPFConf()      { p.rules, p.table = "", "" }
func (p *statefulPF) reloadAppleAnchor() { p.rules = "" }
func (p *statefulPF) disableByOther()    { p.enabled = false; p.tokens = map[string]bool{} }

// Claim: after each external act (pf.conf reload, com.apple anchor reload, pfctl -d by another party)
// one Check detects it, re-applies so the anchor rules, table and pf enable are back, re-enables pf
// only through a fresh token of its own, and status names the finding. Negative control: without a
// Check, the same act leaves the block missing, so the restore comes from the watchdog.
func TestFailClosedWatchdogRecovers(t *testing.T) {
	acts := map[string]func(*statefulPF){
		"anchor table missing or altered": (*statefulPF).reloadPFConf,
		"anchor rules missing or altered": (*statefulPF).reloadAppleAnchor,
		"pf disabled by another party":    (*statefulPF).disableByOther,
	}
	for want, act := range acts {
		p := &statefulPF{}
		m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: func() time.Time { return time.Date(2026, 11, 25, 14, 0, 0, 0, time.UTC) }}
		if err := m.Apply(goodReq); err != nil {
			t.Fatal(err)
		}
		if finding, err := m.Check(); finding != "" || err != nil {
			t.Fatalf("%s: healthy check = %q, %v", want, finding, err)
		}
		act(p)
		// Negative control: the act really removed the block.
		if p.enabled && strings.Contains(p.rules, "block return") && p.table != "" {
			t.Fatalf("%s: simulated act did not remove the block", want)
		}
		if want == "anchor table missing or altered" {
			// pf.conf reload empties rules too; the check reports the first missing piece.
			want = "anchor rules missing or altered"
		}
		finding, err := m.Check()
		if err != nil || finding != want {
			t.Fatalf("check after act = %q, %v; want %q", finding, err, want)
		}
		if !p.enabled || !strings.Contains(p.rules, "block return out quick") || p.table == "" {
			t.Fatalf("%s: not restored: enabled=%v rules=%q table=%q", want, p.enabled, p.rules, p.table)
		}
		if len(p.tokens) != 1 {
			t.Fatalf("%s: tokens = %v, want exactly our one", want, p.tokens)
		}
		st, _ := m.Status()
		if st.LastRecovery != want || st.RecoveredAt.IsZero() {
			t.Fatalf("%s: status = %+v", want, st)
		}
	}
}

// Claim: Check does nothing when the policy is off (no pf calls), so 'off' is never undone by the watchdog.
func TestFailClosedWatchdogIdleWhenOff(t *testing.T) {
	p := &statefulPF{}
	m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now}
	_ = m.Apply(goodReq)
	_ = m.Clear()
	p.calls = nil
	if finding, err := m.Check(); finding != "" || err != nil || len(p.calls) != 0 {
		t.Fatalf("check while off = %q, %v, calls %q", finding, err, p.calls)
	}
}

// Claim: the watch loop runs Check on its interval and stops when told; a disable is repaired within
// one interval.
func TestFailClosedWatchLoopBounded(t *testing.T) {
	p := &statefulPF{}
	m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now}
	_ = m.Apply(goodReq)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.watch(20*time.Millisecond, stop, func(string, ...any) {}); close(done) }()
	m.mu.Lock()
	p.disableByOther()
	m.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		ok := p.enabled
		m.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	<-done
	if !p.enabled {
		t.Fatal("watch loop did not repair a disabled pf within 2 s")
	}
}

// Claim: uninstall flushes the fail-closed anchor, releases the recorded pf token and removes the
// state after the daemon is gone; with no state (feature never used) a failed flush is ignored; with a
// state, a failed flush is reported and the state is kept for another attempt.
func TestUninstallFailClosed(t *testing.T) {
	prev := failClosedStatePathVPNCore
	t.Cleanup(func() { failClosedStatePathVPNCore = prev })
	failClosedStatePathVPNCore = "/Library/Application Support/works.relux.vpn-core/failclosed.json"

	var runRaw func(raw []byte, flushFails bool) ([]string, error)
	run := func(state string, flushFails bool) ([]string, error) {
		var cmds []string
		withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
			c := strings.Join(append([]string{name}, args...), " ")
			cmds = append(cmds, c)
			switch {
			case name == "cat":
				if state == "" {
					return nil, errors.New("no such file")
				}
				return []byte(state), nil
			case strings.Contains(c, "-F all") && flushFails:
				return nil, errors.New("pfctl failed")
			}
			return nil, nil
		})
		return cmds, uninstallFailClosed()
	}
	runRawErr := func(readErr error) ([]string, error) {
		var cmds []string
		withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, strings.Join(append([]string{name}, args...), " "))
			if name == "cat" {
				return nil, readErr
			}
			return nil, nil
		})
		return cmds, uninstallFailClosed()
	}
	runRaw = func(raw []byte, flushFails bool) ([]string, error) {
		var cmds []string
		withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
			cmds = append(cmds, strings.Join(append([]string{name}, args...), " "))
			if name == "cat" {
				return raw, nil
			}
			return nil, nil
		})
		return cmds, uninstallFailClosed()
	}

	cmds, err := run(`{"enabled":true,"token":"42"}`, false)
	joined := strings.Join(cmds, "|")
	if err != nil || !strings.Contains(joined, "/sbin/pfctl -a "+failclosed.AnchorName+" -F all") ||
		!strings.Contains(joined, "/sbin/pfctl -X 42") || !strings.Contains(joined, "rm -f "+failClosedStatePathVPNCore) {
		t.Fatalf("with state: err=%v cmds=%q", err, cmds)
	}
	if _, err := run("", true); err != nil {
		t.Fatalf("never used: err=%v", err)
	}
	// An empty state file reads as "never used" too, not as an unreadable state.
	cmds, err = runRaw([]byte("\n"), false)
	if err != nil || strings.Contains(strings.Join(cmds, "|"), "-X") {
		t.Fatalf("empty state: err=%v cmds=%q", err, cmds)
	}
	cmds, err = run(`{"enabled":true,"token":"42"}`, true)
	if err == nil || strings.Contains(strings.Join(cmds, "|"), "rm -f") {
		t.Fatalf("failed flush: err=%v cmds=%q (state must be kept)", err, cmds)
	}
	// Corrupt state: a recoverable token is still released; an unrecoverable one is reported and
	// the state is kept.
	cmds, err = run(`{"enabled":true,"token":"42",`, false)
	if err != nil || !strings.Contains(strings.Join(cmds, "|"), "/sbin/pfctl -X 42") {
		t.Fatalf("corrupt with token: err=%v cmds=%q", err, cmds)
	}
	// A read failure that is not absence keeps everything and reports.
	cmds, err = runRawErr(errors.New("cat: failclosed.json: Permission denied"))
	if err == nil || strings.Contains(strings.Join(cmds, "|"), "-F all") || strings.Contains(strings.Join(cmds, "|"), "rm -f") {
		t.Fatalf("read failure: err=%v cmds=%q", err, cmds)
	}
	cmds, err = run(`garbage`, false)
	if err == nil || strings.Contains(strings.Join(cmds, "|"), "rm -f") || strings.Contains(strings.Join(cmds, "|"), "-X") {
		t.Fatalf("corrupt without token: err=%v cmds=%q", err, cmds)
	}
}

// Claim: when uninstall cannot confirm that the services are gone, it makes no fail-closed pf or
// state command at all and says the anchor and state were kept.
func TestUninstallKeepsFailClosedWhenServiceNotConfirmedGone(t *testing.T) {
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	var cmds []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		cmds = append(cmds, strings.Join(append([]string{name}, args...), " "))
		if name == "launchctl" && args[0] == "print" {
			return []byte("still loaded"), nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "fail-closed anchor and state kept") {
		t.Fatalf("uninstall err = %v", err)
	}
	for _, c := range cmds {
		if strings.Contains(c, "pfctl") || strings.HasPrefix(c, "cat ") {
			t.Fatalf("fail-closed command ran before the daemon was confirmed gone: %q", c)
		}
	}
}

// Claim: the helper covers every existing physical interface, not only the requested ones, and the
// watchdog re-renders the anchor when a new physical interface appears (uplink switch), within one
// Check; the new interface then appears in the loaded rules.
func TestFailClosedCoversDiscoveredInterfaces(t *testing.T) {
	p := &statefulPF{}
	found := []string{"en0", "en7"}
	m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now,
		interfaces: func() ([]string, error) { return found, nil }}
	if err := m.Apply(goodReq); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.rules, "on { en0 en7 }") {
		t.Fatalf("rules = %q, want both discovered interfaces", p.rules)
	}
	if finding, err := m.Check(); finding != "" || err != nil {
		t.Fatalf("steady check = %q, %v", finding, err)
	}
	found = []string{"en0", "en7", "en8"}
	finding, err := m.Check()
	if err != nil || finding != "physical interfaces changed" || !strings.Contains(p.rules, "on { en0 en7 en8 }") {
		t.Fatalf("after new interface: finding %q err %v rules %q", finding, err, p.rules)
	}
}

// Claim: status reports live enforcement from pf, not the stored policy: enforcing while pf is enabled
// with our rules and full table; not enforcing (pf_enabled=false) right after another party disables pf.
func TestFailClosedStatusIsLive(t *testing.T) {
	p := &statefulPF{}
	m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now}
	if err := m.Apply(goodReq); err != nil {
		t.Fatal(err)
	}
	st, _ := m.Status()
	if !st.LiveChecked || !st.PFEnabled || !st.AnchorLoaded || st.LiveTableEntries != 2 || !st.Enforcing {
		t.Fatalf("healthy status = %+v", st)
	}
	p.disableByOther()
	st, _ = m.Status()
	if !st.Enabled || st.PFEnabled || st.Enforcing {
		t.Fatalf("status after pfctl -d = %+v, want enabled policy but not enforcing", st)
	}
	p.enabled = true
	p.reloadAppleAnchor()
	if st, _ = m.Status(); st.AnchorLoaded || st.Enforcing {
		t.Fatalf("status after anchor reload = %+v", st)
	}
}

// fightingPF reports pf disabled on every check, as a tool that keeps disabling it would.
type fightingPF struct{ statefulPF }

func (f *fightingPF) run(args []string, stdin string) ([]byte, error) {
	if strings.Join(args, " ") == "-s info" {
		return []byte("Status: Disabled\n"), nil
	}
	return f.statefulPF.run(args, stdin)
}

// Claim: when another party keeps undoing the block, detection stays at the base interval (the
// contract's bound) instead of backing off, and status reports the streak.
func TestFailClosedWatchKeepsBoundUnderFight(t *testing.T) {
	p := &fightingPF{}
	m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now}
	_ = m.Apply(goodReq)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { m.watch(10*time.Millisecond, stop, func(string, ...any) {}); close(done) }()
	time.Sleep(300 * time.Millisecond)
	m.mu.Lock()
	note := m.backoffNote
	calls := 0
	for _, c := range p.calls {
		if c == "-s info" {
			calls++
		}
	}
	m.mu.Unlock()
	close(stop)
	<-done
	// 300 ms at a 10 ms bound gives about 30 checks; a backoff would give a handful.
	if calls < 15 || !strings.Contains(note, "recoveries in a row") || !strings.Contains(note, "10ms") {
		t.Fatalf("checks=%d note=%q", calls, note)
	}
}

// Claim: live checks compare the exact table and the exact rule. A table with the same number of
// entries but other addresses, a narrowed rule (proto/port) and an extra permissive rule are each
// reported as not enforcing, and the watchdog repairs them; the healthy state reads as enforcing.
func TestFailClosedLiveCompareIsExact(t *testing.T) {
	for name, tamper := range map[string]func(*statefulPF){
		"same-count wrong table": func(p *statefulPF) { p.table = "9.9.9.9/32\n8.8.8.8/32\n" },
		"narrowed rule":          func(p *statefulPF) { p.rules = "block return out quick on en0 proto tcp to <failclosed> port 443\n" },
		"extra pass rule":        func(p *statefulPF) { p.rules += "pass out quick to <failclosed>\n" },
	} {
		p := &statefulPF{}
		m := &failClosedManager{statePath: filepath.Join(t.TempDir(), "fc.json"), pfctl: p.run, now: time.Now}
		if err := m.Apply(goodReq); err != nil {
			t.Fatal(err)
		}
		if st, _ := m.Status(); !st.Enforcing {
			t.Fatalf("%s: healthy state not enforcing: %+v", name, st)
		}
		tamper(p)
		if st, _ := m.Status(); st.Enforcing {
			t.Fatalf("%s: tampered state still reads as enforcing: %+v", name, st)
		}
		finding, err := m.Check()
		if err != nil || finding == "" {
			t.Fatalf("%s: check = %q, %v", name, finding, err)
		}
		if st, _ := m.Status(); !st.Enforcing {
			t.Fatalf("%s: not repaired: %+v", name, st)
		}
	}
}

// Claim: a symlinked state path is refused before any pfctl call, so the root helper never writes
// through a planted link.
func TestFailClosedRefusesSymlinkedState(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	link := filepath.Join(dir, "fc.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f := &fakePF{}
	m := &failClosedManager{statePath: link, pfctl: f.run, now: time.Now}
	if err := m.Apply(goodReq); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("apply through symlink = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("pfctl called: %q", f.calls)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("link target was written")
	}
}
