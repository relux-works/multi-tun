package vpncore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		"utun interface":  {Interfaces: []string{"utun233"}, Table: goodReq.Table},
		"no interfaces":   {Table: goodReq.Table},
		"private table":   {Interfaces: []string{"en0"}, Table: []string{"192.168.0.0/16"}},
		"malformed table": {Interfaces: []string{"en0"}, Table: []string{"1.2.3.4"}},
		"injected ifname": {Interfaces: []string{"en0 } pass all {"}, Table: goodReq.Table},
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
// (rules already loaded are left alone), while Clear still works so the owner can roll back.
func TestFailClosedCorruptState(t *testing.T) {
	f := &fakePF{}
	m := newTestManager(t, f)
	os.MkdirAll(filepath.Dir(m.statePath), 0o755)
	os.WriteFile(m.statePath, []byte("{not json"), 0o600)
	if err := m.ReapplyAtStart(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("reapply err = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("pfctl called on corrupt state: %q", f.calls)
	}
	if err := m.Clear(); err != nil {
		t.Fatalf("clear with corrupt state: %v", err)
	}
	if f.calls[0] != "-a "+failclosed.AnchorName+" -F all" {
		t.Fatalf("clear calls = %q", f.calls)
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
