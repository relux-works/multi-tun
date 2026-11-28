package vpncore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests use inert children, temporary files and injected command runners.
// They prove the privilege contract and socket transport, not live VPN behavior.
func primitiveRPC(t *testing.T, d *serviceDaemon, req Request) Response {
	t.Helper()
	server, client := unixSocketPair(t)
	done := make(chan struct{})
	go func() { defer close(done); d.handleConn(server, d.requests.enqueue()) }()
	payload, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var rights []byte
	if req.Action == "proc.ensure" && req.ProcEnsure != nil && req.ProcEnsure.Kind != "tcpdump" {
		log := openSecurityTestLog(t, "primitive.log")
		rights = unix.UnixRights(int(log.Fd()))
	}
	writeUnixPayload(t, client, append(payload, '\n'), rights)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	<-done
	return response
}

func primitiveDaemon(t *testing.T) *serviceDaemon {
	t.Helper()
	root := resolvedTempDir(t)
	return newServiceDaemon(ServiceConfig{RuntimeDir: filepath.Join(root, "runtime"), HelperDir: filepath.Join(root, "helper")}, os.Getuid(), os.Getgid())
}

func mockSingBox(t *testing.T) (*atomic.Int32, *atomic.Int32) {
	t.Helper()
	oldCheck, oldCommand := singBoxCheckVPNCore, execCommandVPNCore
	var checks, starts atomic.Int32
	singBoxCheckVPNCore = func(tool, path string) error {
		checks.Add(1)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(tool, "/bin/sing-box") || filepath.Base(path) != "config.json" || !json.Valid(data) {
			return errors.New("incorrect staged check")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			return errors.New("config is not mode 0600")
		}
		info, err = os.Stat(filepath.Dir(path))
		if err != nil || info.Mode().Perm() != 0o700 {
			return errors.New("session is not mode 0700")
		}
		return nil
	}
	execCommandVPNCore = func(name string, args ...string) *exec.Cmd {
		starts.Add(1)
		if !strings.HasSuffix(name, "/bin/sing-box") || len(args) != 3 || args[0] != "run" || args[1] != "-c" {
			return exec.Command("/missing/incorrect-command")
		}
		return exec.Command("/bin/sleep", "30")
	}
	t.Cleanup(func() { singBoxCheckVPNCore, execCommandVPNCore = oldCheck, oldCommand })
	return &checks, &starts
}

func cleanupPrimitiveChildren(t *testing.T, d *serviceDaemon) {
	t.Helper()
	t.Cleanup(func() {
		d.children.mu.Lock()
		handles := make([]string, 0, len(d.children.children))
		for handle := range d.children.children {
			handles = append(handles, handle)
		}
		d.children.mu.Unlock()
		for _, handle := range handles {
			if _, ok := d.children.get(handle); ok {
				_, _ = d.children.signal(handle, syscall.SIGKILL)
			}
			if err := d.children.waitStopped(handle); err != nil {
				t.Error(err)
			}
		}
	})
}

func TestPrimitiveEnsureCheckPassAndFail(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			checks, starts := mockSingBox(t)
			d := primitiveDaemon(t)
			cleanupPrimitiveChildren(t, d)
			var staged string
			checked := singBoxCheckVPNCore
			singBoxCheckVPNCore = func(tool, path string) error {
				staged = filepath.Dir(path)
				if err := checked(tool, path); err != nil {
					return err
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if strings.Contains(string(data), "output") {
					return errors.New("shadowed value reached checker")
				}
				if fail {
					return errors.New("invalid schema")
				}
				return nil
			}
			r := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: []byte(`{"log":{"output":"/private/write"},"log":{"level":"warn"}}`), SetPGID: true}})
			if fail {
				if r.OK || !strings.Contains(r.Error, "sing-box check failed: invalid schema") || starts.Load() != 0 {
					t.Fatalf("check failure spawned: %+v starts=%d", r, starts.Load())
				}
				if _, err := os.Stat(staged); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("failed stage retained: %v", err)
				}
			} else {
				if !r.OK || r.PID <= 0 || !handlePatternVPNCore.MatchString(r.Handle) || starts.Load() != 1 {
					t.Fatalf("start failed: %+v starts=%d", r, starts.Load())
				}
				if checks.Load() != 1 {
					t.Fatal("start bypassed check")
				}
			}
		})
	}
}

func TestPrimitiveRunSingBoxCheckUsesBoundedContext(t *testing.T) {
	old := execCommandContextVPNCore
	defer func() { execCommandContextVPNCore = old }()
	for _, fail := range []bool{false, true} {
		execCommandContextVPNCore = func(ctx context.Context, name string, args ...string) *exec.Cmd {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 10*time.Second || name != "/pinned/sing-box" || !reflect.DeepEqual(args, []string{"check", "-c", "/staged/config.json"}) {
				return exec.Command("/missing/incorrect-check")
			}
			if fail {
				return exec.CommandContext(ctx, "/usr/bin/false")
			}
			return exec.CommandContext(ctx, "/usr/bin/true")
		}
		if err := runSingBoxCheck("/pinned/sing-box", "/staged/config.json"); (err != nil) != fail {
			t.Fatalf("check failed=%t error=%v", fail, err)
		}
	}
}

func TestPrimitiveSlotsReuseReplaceAndStop(t *testing.T) {
	checks, starts := mockSingBox(t)
	d := primitiveDaemon(t)
	cleanupPrimitiveChildren(t, d)
	ensure := ProcEnsureRequest{Kind: "sing-box", Slot: "engine/main", ConfigJSON: []byte(`{}`), SetPGID: true}
	first := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure})
	if !first.OK {
		t.Fatal(first.Error)
	}
	again := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure})
	if !again.OK || again.PID != first.PID || again.Handle != first.Handle || again.Slot != ensure.Slot || again.Kind != ensure.Kind || !again.Running || starts.Load() != 1 || checks.Load() != 1 {
		t.Fatalf("slot not idempotent: %+v", again)
	}
	wrongKind := ProcEnsureRequest{Kind: "tcpdump", Slot: ensure.Slot, Interface: "lo0", Filter: []string{"tcp"}, RunAsUser: true}
	if r := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &wrongKind}); r.OK {
		t.Fatal("slot kind mismatch accepted")
	}
	ensure.Replace = true
	ensure.ConfigJSON = []byte(`{"log":{"output":"/private/write"}}`)
	if r := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure}); r.OK {
		t.Fatal("unsafe replacement accepted")
	}
	if _, ok := d.children.get(first.Handle); !ok {
		t.Fatal("old process removed by invalid config")
	}
	validCheck := singBoxCheckVPNCore
	singBoxCheckVPNCore = func(string, string) error { return errors.New("schema invalid") }
	ensure.ConfigJSON = []byte(`{}`)
	if r := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure}); r.OK {
		t.Fatal("failed check replacement accepted")
	}
	if err := syscall.Kill(first.PID, 0); err != nil || starts.Load() != 1 {
		t.Fatalf("failed precheck stopped old process: %v", err)
	}
	singBoxCheckVPNCore = validCheck
	replacement := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure})
	if !replacement.OK || replacement.PID == first.PID || replacement.Handle == first.Handle || starts.Load() != 2 {
		t.Fatalf("replacement failed: %+v", replacement)
	}
	if _, ok := d.children.get(first.Handle); ok {
		t.Fatal("old process still tracked")
	}
	status := primitiveRPC(t, d, Request{Action: "proc.status", ProcStatus: &ProcStatusRequest{Slot: ensure.Slot}})
	if !status.OK || len(status.Processes) != 1 || status.Processes[0].PID != replacement.PID || status.Processes[0].StartedAt.IsZero() || !status.Processes[0].Running {
		t.Fatalf("wrong status: %+v", status)
	}
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), replacement.Handle) || strings.Contains(string(raw), `"handle"`) {
		t.Fatal("process status leaks opaque handles")
	}
	if r := primitiveRPC(t, d, Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Slot: ensure.Slot}}); !r.OK || !r.Stopped {
		t.Fatalf("stop by slot: %+v", r)
	}
	if err := d.children.waitStopped(replacement.Handle); err != nil {
		t.Fatal(err)
	}
	ensure.Replace = false
	third := primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &ensure})
	if !third.OK {
		t.Fatal(third.Error)
	}
	if r := primitiveRPC(t, d, Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Handle: third.Handle, Signal: "-KILL"}}); !r.OK || !r.Stopped {
		t.Fatalf("stop by handle: %+v", r)
	}
	if err := d.children.waitStopped(third.Handle); err != nil {
		t.Fatal(err)
	}
	if r := primitiveRPC(t, d, Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Handle: third.Handle}}); r.OK {
		t.Fatal("stale handle accepted")
	}
	if r := primitiveRPC(t, d, Request{Action: "proc.stop", ProcStop: &ProcStopRequest{Slot: "missing"}}); r.OK {
		t.Fatal("missing slot accepted")
	}
}

func TestPrimitiveSlotReuseClosesUnusedLog(t *testing.T) {
	d := primitiveDaemon(t)
	handle, err := d.children.add(os.Getpid(), false, "", "sing-box")
	if err != nil {
		t.Fatal(err)
	}
	d.children.mu.Lock()
	child := d.children.children[handle]
	child.slot = "existing"
	d.children.children[handle] = child
	d.children.mu.Unlock()
	log := openSecurityTestLog(t, "unused.log")
	result, err := d.handleProcEnsure(ProcEnsureRequest{Kind: "sing-box", Slot: "existing", ConfigJSON: []byte(`{}`)}, log)
	if err != nil || result.Handle != handle {
		t.Fatalf("reuse failed: %+v %v", result, err)
	}
	if _, err := log.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("unused descriptor retained: %v", err)
	}
	// Registry-only fixture: never signal this process.
	d.children.remove(handle)
}

func TestPrimitiveReadActionsBypassMutationAndDrain(t *testing.T) {
	d := primitiveDaemon(t)
	fixture := newVerificationFixture(t)
	d.cfg.HelperDir = fixture.cfg.HelperDir
	d.socketVerification = fixture.dependencies
	pf := &fakePF{}
	d.failClosed = newTestManager(t, pf)
	d.mutation.Lock()
	defer d.mutation.Unlock()
	d.drainStateMu.Lock()
	d.drainUntil = time.Now().Add(time.Minute)
	d.drainToken = strings.Repeat("a", 64)
	d.drainStateMu.Unlock()
	for _, req := range []Request{
		{Action: "ping"}, {Action: "proc.status"}, {Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}}, {Action: "bin.pin", BinPin: &BinPinRequest{Op: "status"}}, {Action: "bin.pin", BinPin: &BinPinRequest{Op: "verify"}},
	} {
		r := primitiveRPC(t, d, req)
		if !r.OK {
			t.Fatalf("read-only %s refused: %s", req.Action, r.Error)
		}
		if req.Action == "ping" && (r.ProtocolVersion != 2 || !reflect.DeepEqual(r.Capabilities, []string{"proc", "net", "pf", "bin"})) {
			t.Fatalf("missing capabilities: %+v", r)
		}
	}
}

func TestPrimitiveDNSAndRouteRoundTrip(t *testing.T) {
	d := primitiveDaemon(t)
	oldContext, oldOrder, oldResolver, oldRoute := execCommandContextVPNCore, networkServiceOrderVPNCore, resolverDirVPNCore, runNetRouteVPNCore
	defer func() {
		execCommandContextVPNCore, networkServiceOrderVPNCore, resolverDirVPNCore, runNetRouteVPNCore = oldContext, oldOrder, oldResolver, oldRoute
	}()
	var commands [][]string
	execCommandContextVPNCore = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		commands = append(commands, append([]string{name}, args...))
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	networkServiceOrderVPNCore = func() ([]byte, error) { return []byte("(1) Wi-Fi\n"), nil }
	resolverDirVPNCore = t.TempDir()
	marked := filepath.Join(resolverDirVPNCore, "owned")
	if err := os.WriteFile(marked, []byte("# Added by openconnect-tun DNS shim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, req := range []NetDNSRequest{{Op: "scutil", Stdin: "d.init\nquit\n"}, {Op: "networksetup", Service: "Wi-Fi", Servers: []string{"1.1.1.1"}}, {Op: "resolver_cleanup"}} {
		if r := primitiveRPC(t, d, Request{Action: "net.dns", NetDNS: &req}); !r.OK {
			t.Fatal(r.Error)
		}
	}
	if !reflect.DeepEqual(commands, [][]string{{"/usr/sbin/scutil"}, {"/usr/sbin/networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1"}}) {
		t.Fatalf("DNS command mismatch: %v", commands)
	}
	if _, err := os.Stat(marked); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("resolver not cleaned")
	}
	for _, req := range []NetDNSRequest{{Op: "scutil", Stdin: "set State:/Network/Global/DNS\n"}, {Op: "scutil", Stdin: "d.init\n", Service: "Wi-Fi"}, {Op: "networksetup", Service: "Unknown", Servers: []string{"1.1.1.1"}}, {Op: "networksetup", Service: "Wi-Fi", Servers: []string{"1.1.1.1;id"}}, {Op: "networksetup", Service: "Wi-Fi", Servers: []string{"Empty"}, Stdin: "quit"}, {Op: "resolver_cleanup", Servers: []string{"1.1.1.1"}}, {Op: "unknown"}} {
		if r := primitiveRPC(t, d, Request{Action: "net.dns", NetDNS: &req}); r.OK {
			t.Fatalf("unsafe DNS accepted: %+v", req)
		}
	}
	var routeArgs []string
	runNetRouteVPNCore = func(args []string) ([]byte, error) { routeArgs = append([]string(nil), args...); return nil, nil }
	for _, tc := range []struct {
		req  NetRouteRequest
		want []string
	}{
		{NetRouteRequest{Op: "add", CIDR: "192.0.2.123/24", Interface: "utun7"}, []string{"-n", "add", "-net", "192.0.2.0/24", "-interface", "utun7"}},
		{NetRouteRequest{Op: "delete", CIDR: "192.0.2.1"}, []string{"-n", "delete", "-net", "192.0.2.1/32"}},
		{NetRouteRequest{Op: "change", CIDR: "192.0.2.1", Gateway: "192.0.2.254"}, []string{"-n", "change", "-net", "192.0.2.1/32", "192.0.2.254"}},
		{NetRouteRequest{Op: "add", CIDR: "2001:db8::1/64", Gateway: "2001:db8::2"}, []string{"-n", "add", "-inet6", "2001:db8::/64", "2001:db8::2"}},
		{NetRouteRequest{Op: "delete", CIDR: "2001:db8::1", Interface: "utun7"}, []string{"-n", "delete", "-inet6", "2001:db8::1/128", "-interface", "utun7"}},
		{NetRouteRequest{Op: "change", CIDR: "2001:db8::/64", Interface: "en0"}, []string{"-n", "change", "-inet6", "2001:db8::/64", "-interface", "en0"}},
	} {
		if r := primitiveRPC(t, d, Request{Action: "net.route", NetRoute: &tc.req}); !r.OK || !reflect.DeepEqual(routeArgs, tc.want) {
			t.Fatalf("route=%v want=%v response=%+v", routeArgs, tc.want, r)
		}
	}
	for _, req := range []NetRouteRequest{
		{Op: "flush", CIDR: "192.0.2.1", Interface: "en0"}, {Op: "add", CIDR: "default", Interface: "en0"}, {Op: "add", CIDR: "192.0.2.1;id", Interface: "en0"}, {Op: "add", CIDR: "192.0.2.1", Interface: "en0;id"}, {Op: "add", CIDR: "192.0.2.1"}, {Op: "change", CIDR: "2001:db8::1"}, {Op: "delete", CIDR: "192.0.2.1", Interface: "en0", Gateway: "192.0.2.2"}, {Op: "add", CIDR: "192.0.2.1", Gateway: "2001:db8::1"}, {Op: "add", CIDR: "2001:db8::1", Gateway: "192.0.2.1"}, {Op: "add", CIDR: "2001:db8::1", Gateway: "fe80::1%en0"}, {Op: "add", CIDR: "192.0.2.1", Gateway: "-interface"},
	} {
		routeArgs = nil
		if r := primitiveRPC(t, d, Request{Action: "net.route", NetRoute: &req}); r.OK || routeArgs != nil {
			t.Fatalf("invalid route executed: %+v", req)
		}
	}
	runNetRouteVPNCore = func([]string) ([]byte, error) { return nil, errors.New("refused route") }
	if r := primitiveRPC(t, d, Request{Action: "net.route", NetRoute: &NetRouteRequest{Op: "delete", CIDR: "192.0.2.1"}}); r.OK || !strings.Contains(r.Error, "refused route") {
		t.Fatal("route execution failure hidden")
	}
}

func TestPrimitivePFAndBinPins(t *testing.T) {
	d := primitiveDaemon(t)
	pf := &fakePF{}
	d.failClosed = newTestManager(t, pf)
	if r := primitiveRPC(t, d, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "apply", FailClosed: &goodReq}}); !r.OK {
		t.Fatal(r.Error)
	}
	if len(pf.calls) == 0 {
		t.Fatal("PF apply was not delegated")
	}
	if r := primitiveRPC(t, d, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}}); !r.OK || r.FailClosed == nil || !r.FailClosed.Enabled {
		t.Fatalf("PF status lost: %+v", r)
	}
	if r := primitiveRPC(t, d, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "clear"}}); !r.OK {
		t.Fatal(r.Error)
	}
	if r := primitiveRPC(t, d, Request{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}}); !r.OK || r.FailClosed == nil || r.FailClosed.Enabled {
		t.Fatalf("PF clear not persistent: %+v", r)
	}
	fixture := newVerificationFixture(t)
	d.cfg.HelperDir = fixture.cfg.HelperDir
	d.socketVerification = fixture.dependencies
	for _, op := range []string{"status", "verify"} {
		r := primitiveRPC(t, d, Request{Action: "bin.pin", BinPin: &BinPinRequest{Op: op}})
		if !r.OK || len(r.PinnedBins) != 2 {
			t.Fatalf("pins: %+v", r)
		}
		for _, pin := range r.PinnedBins {
			if pin.Verified != (op == "verify") || pin.Error != "" {
				t.Fatalf("pin verification: %+v", pin)
			}
		}
	}
	if err := os.WriteFile(fixture.extraPath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := primitiveRPC(t, d, Request{Action: "bin.pin", BinPin: &BinPinRequest{Op: "verify"}})
	if !r.OK || r.PinnedBins[1].Verified || !r.PinnedBins[1].Drift || !strings.Contains(r.PinnedBins[1].Error, "sha256 mismatch") {
		t.Fatalf("tampering undetected: %+v", r)
	}
	if err := os.Remove(fixture.extraPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fixture.binaryPath, fixture.extraPath); err != nil {
		t.Fatal(err)
	}
	r = primitiveRPC(t, d, Request{Action: "bin.pin", BinPin: &BinPinRequest{Op: "verify"}})
	if !r.OK || r.PinnedBins[1].Verified || r.PinnedBins[1].Error == "" {
		t.Fatal("symlinked binary trusted")
	}
}

func TestPrimitiveClosedSchemas(t *testing.T) {
	valid := []Request{
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: []byte(`{}`)}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "openconnect", OpenConnect: &OpenConnectStartRequest{}}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "tcpdump", Interface: "lo0", Filter: []string{"tcp"}, RunAsUser: true}},
		{Action: "proc.stop", ProcStop: &ProcStopRequest{Slot: "engine/main"}},
		{Action: "proc.status", ProcStatus: &ProcStatusRequest{}},
		{Action: "net.dns", NetDNS: &NetDNSRequest{Op: "resolver_cleanup"}},
		{Action: "net.route", NetRoute: &NetRouteRequest{Op: "delete", CIDR: "192.0.2.1"}},
		{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status"}},
		{Action: "bin.pin", BinPin: &BinPinRequest{Op: "verify"}},
	}
	for i, req := range valid {
		if !knownAction(req.Action) || safeRequestAction(req.Action) != req.Action {
			t.Fatalf("action not registered: %s", req.Action)
		}
		if err := validateRequestShape(req); err != nil {
			t.Fatalf("valid shape %d: %v", i, err)
		}
		// Every primitive payload must be refused alongside every other action.
		for j, other := range valid {
			if req.Action == other.Action {
				continue
			}
			crossed := req
			crossed.Action = other.Action
			if err := validateRequestShape(crossed); err == nil {
				t.Errorf("crossed schemas %d/%d accepted", i, j)
			}
		}
		for _, field := range []Request{{Token: "secret"}, {ConfigJSON: []byte(`{}`)}, {Stdin: "quit"}, {LogMaxLines: 1}, {Handle: strings.Repeat("a", 48)}, {Signal: "-TERM"}, {SetPGID: true}, {Service: "Wi-Fi"}, {Servers: []string{"1.1.1.1"}}, {Interface: "en0"}, {Filter: []string{"tcp"}}, {ApplePCAPNG: true}, {RunAsUser: true}, {OpenConnect: &OpenConnectStartRequest{}}, {FailClosed: &goodReq}} {
			field.Action = req.Action
			field.ProcEnsure, field.ProcStop, field.ProcStatus, field.NetDNS, field.NetRoute, field.PFAnchor, field.BinPin = req.ProcEnsure, req.ProcStop, req.ProcStatus, req.NetDNS, req.NetRoute, req.PFAnchor, req.BinPin
			if err := validateRequestShape(field); err == nil {
				t.Errorf("outer field accepted by %s: %+v", req.Action, field)
			}
		}
	}
	for _, req := range []Request{
		{Action: "proc.ensure"}, {Action: "proc.stop"}, {Action: "net.dns"}, {Action: "net.route"}, {Action: "pf.anchor"},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sh"}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", Slot: "invalid slot", ConfigJSON: []byte(`{}`)}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: []byte(`{}`), LogMaxLines: -1}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: []byte(`{}`), LogMaxLines: 1_000_001}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "sing-box", ConfigJSON: []byte(`{}`), OpenConnect: &OpenConnectStartRequest{}}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "openconnect", OpenConnect: &OpenConnectStartRequest{}, ConfigJSON: []byte(`{}`)}},
		{Action: "proc.ensure", ProcEnsure: &ProcEnsureRequest{Kind: "tcpdump", Interface: "lo0", Filter: []string{"tcp"}}},
		{Action: "proc.stop", ProcStop: &ProcStopRequest{}},
		{Action: "proc.stop", ProcStop: &ProcStopRequest{Slot: "main", Handle: strings.Repeat("a", 48)}},
		{Action: "proc.stop", ProcStop: &ProcStopRequest{Handle: strings.Repeat("A", 48)}},
		{Action: "proc.stop", ProcStop: &ProcStopRequest{Slot: "main", Signal: "-HUP"}},
		{Action: "proc.status", ProcStatus: &ProcStatusRequest{Slot: strings.Repeat("a", 65)}},
		{Action: "proc.status", ProcStatus: &ProcStatusRequest{Handle: "forged"}},
		{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "apply"}},
		{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "clear", FailClosed: &goodReq}},
		{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "status", FailClosed: &goodReq}},
		{Action: "pf.anchor", PFAnchor: &PFAnchorRequest{Op: "replace"}},
		{Action: "bin.pin", BinPin: &BinPinRequest{Op: "install"}},
		{Action: "ping", ProcEnsure: &ProcEnsureRequest{}},
	} {
		if err := validateRequestShape(req); err == nil {
			t.Fatalf("invalid shape accepted: %+v", req)
		}
	}
}

func TestPrimitiveWireDescriptorAndUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		raw, fd string
		valid   bool
	}{
		{`{"action":"proc.ensure","proc_ensure":{"kind":"sing-box","config_json":"e30="}}`, "regular", true},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"openconnect","openconnect":{}}}`, "regular", true},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"sing-box","config_json":"e30="}}`, "", false},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"sing-box","config_json":"e30="}}`, "pipe", false},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"sing-box","config_json":"e30="}}`, "two", false},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"tcpdump","interface":"lo0","filter":["tcp"],"run_as_user":true}}`, "regular", false},
		{`{"action":"proc.status"}`, "regular", false},
		{`{"action":"proc.ensure","proc_ensure":{"kind":"sing-box","config_json":"e30=","command":["sh"]}}`, "regular", false},
		{`{"action":"net.route","net_route":{"op":"delete","cidr":"192.0.2.1","argv":["flush"]}}`, "", false},
		{`{"action":"net.dns","net_dns":{"op":"resolver_cleanup","unexpected":true}}`, "", false},
		{`{"action":"pf.anchor","pf_anchor":{"op":"status","anchor":"other"}}`, "", false},
		{`{"action":"bin.pin","bin_pin":{"op":"status","path":"/private/data"}}`, "", false},
		{`{"action":"proc.status","proc_status":{"handle":"forged"}}`, "", false},
	} {
		server, client := unixSocketPair(t)
		var rights []byte
		switch tc.fd {
		case "regular", "two":
			f := openSecurityTestLog(t, "wire.log")
			if tc.fd == "two" {
				rights = unix.UnixRights(int(f.Fd()), int(f.Fd()))
			} else {
				rights = unix.UnixRights(int(f.Fd()))
			}
		case "pipe":
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			rights = unix.UnixRights(int(w.Fd()))
		}
		writeUnixPayload(t, client, []byte(tc.raw+"\n"), rights)
		_, file, err := readRequest(server)
		if file != nil {
			_ = file.Close()
		}
		if (err == nil) != tc.valid {
			t.Errorf("wire validity=%t got=%v: %s", tc.valid, err, tc.raw)
		}
		_ = server.Close()
		_ = client.Close()
	}
}

func TestLegacyClientsFallbackOnlyAfterOldDaemonRefusal(t *testing.T) {
	calls := []struct {
		primitive, legacy string
		run               func(ServiceConfig, string) error
	}{
		{"proc.ensure", "singbox.start", func(c ServiceConfig, p string) error {
			_, _, err := StartSingBox(c, []byte(`{}`), p, true, LogOptions{})
			return err
		}},
		{"proc.ensure", "openconnect.start", func(c ServiceConfig, p string) error {
			_, _, err := StartOpenConnect(c, OpenConnectStartRequest{}, p)
			return err
		}},
		{"proc.ensure", "tcpdump.start", func(c ServiceConfig, _ string) error {
			_, _, err := StartTCPDump(c, "lo0", []string{"tcp"}, false, true)
			return err
		}},
		{"proc.stop", "signal", func(c ServiceConfig, _ string) error {
			_, err := Signal(c, strings.Repeat("a", 48), "-TERM")
			return err
		}},
		{"net.dns", "dns.scutil", func(c ServiceConfig, _ string) error { return RunSCUtil(c, "d.init\nquit\n") }},
		{"net.dns", "dns.networksetup", func(c ServiceConfig, _ string) error { return RunNetworkSetup(c, "Wi-Fi", []string{"Empty"}) }},
		{"net.dns", "resolver.cleanup", func(c ServiceConfig, _ string) error { return CleanupResolvers(c) }},
		{"pf.anchor", "failclosed.apply", func(c ServiceConfig, _ string) error { return ApplyFailClosed(c, goodReq.Interfaces, goodReq.Table) }},
		{"pf.anchor", "failclosed.clear", func(c ServiceConfig, _ string) error { return ClearFailClosed(c) }},
		{"pf.anchor", "failclosed.status", func(c ServiceConfig, _ string) error { _, err := FailClosedState(c); return err }},
	}
	for _, tc := range calls {
		for _, refusal := range []string{"", `unsupported vpn core action "new"`, `json: unknown field "new"`, "policy refused", "disconnect"} {
			t.Run(tc.legacy+"/"+refusal, func(t *testing.T) {
				cfg, listener := newRPCClientTestListener(t)
				withRPCServerIdentity(t, uint32(os.Getuid()), func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), nil })
				done := make(chan error, 1)
				go func() {
					expected := 1
					if strings.HasPrefix(refusal, "unsupported") || strings.HasPrefix(refusal, "json:") {
						expected = 2
					}
					for i := 0; i < expected; i++ {
						conn, err := listener.AcceptUnix()
						if err != nil {
							done <- err
							return
						}
						req, file, err := readRequest(conn)
						if file != nil {
							_ = file.Close()
						}
						if err != nil {
							_ = conn.Close()
							done <- err
							return
						}
						want := tc.primitive
						if i == 1 {
							want = tc.legacy
						}
						if req.Action != want {
							_ = conn.Close()
							done <- fmt.Errorf("action=%s want=%s", req.Action, want)
							return
						}
						if refusal == "disconnect" {
							_ = conn.Close()
							break
						}
						r := Response{OK: true, PID: 42, Handle: strings.Repeat("a", 48), FailClosed: &FailClosedStatus{}}
						if i == 0 && refusal != "" {
							r = Response{Error: refusal}
						}
						err = writeResponse(conn, r)
						_ = conn.Close()
						if err != nil {
							done <- err
							return
						}
					}
					// Refusals outside the compatibility contract and ambiguous transport
					// failures must produce zero further mutating requests.
					_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
					conn, err := listener.AcceptUnix()
					if err == nil {
						_ = conn.Close()
						done <- errors.New("unexpected retry")
						return
					}
					done <- nil
				}()
				err := tc.run(cfg, filepath.Join(t.TempDir(), "client.log"))
				if refusal == "policy refused" || refusal == "disconnect" {
					if err == nil {
						t.Fatal("failure hidden")
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	// Typed network/timeout errors with the same text are never compatibility refusals.
	for _, err := range []error{errors.New("unsupported vpn core action"), context.DeadlineExceeded, &net.OpError{Op: "read", Net: "unix", Err: errors.New("json: unknown field")}, &RefusedError{Message: "policy refused"}} {
		if olderDaemonRefusal(err) {
			t.Fatalf("unsafe retry classification: %v", err)
		}
	}
}

func TestPrimitiveClientsRoundTrip(t *testing.T) {
	mockSingBox(t)
	fixture := newVerificationFixture(t)
	cfg, listener := newRPCClientTestListener(t)
	cfg.RuntimeDir = filepath.Join(resolvedTempDir(t), "runtime")
	cfg.HelperDir = fixture.cfg.HelperDir
	d := newServiceDaemon(cfg, os.Getuid(), os.Getgid())
	d.socketVerification = fixture.dependencies
	d.failClosed = newTestManager(t, &fakePF{})
	withRPCServerIdentity(t, uint32(os.Getuid()), func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), nil })
	oldRoute, oldResolver := runNetRouteVPNCore, resolverDirVPNCore
	t.Cleanup(func() { runNetRouteVPNCore, resolverDirVPNCore = oldRoute, oldResolver })
	runNetRouteVPNCore = func([]string) ([]byte, error) { return nil, nil }
	resolverDirVPNCore = t.TempDir()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			d.handleConn(conn, d.requests.enqueue())
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	cleanupPrimitiveChildren(t, d)
	result, err := EnsureProcess(cfg, ProcEnsureRequest{Kind: "sing-box", Slot: "client", ConfigJSON: []byte(`{}`)}, filepath.Join(t.TempDir(), "client.log"))
	if err != nil || !result.Running {
		t.Fatalf("ensure: %+v %v", result, err)
	}
	status, err := QueryProcessStatus(cfg, ProcStatusRequest{Handle: result.Handle})
	if err != nil || len(status) != 1 || status[0].Slot != "client" {
		t.Fatalf("status: %+v %v", status, err)
	}
	stop, err := StopProcess(cfg, ProcStopRequest{Handle: result.Handle})
	if err != nil || !stop.Stopped {
		t.Fatalf("stop: %+v %v", stop, err)
	}
	if err := ApplyPFAnchor(cfg, goodReq.Interfaces, goodReq.Table); err != nil {
		t.Fatal(err)
	}
	if _, err := QueryPFAnchorStatus(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ClearPFAnchor(cfg); err != nil {
		t.Fatal(err)
	}
	pins, err := QueryBinPins(cfg, true)
	if err != nil || len(pins) != 2 || !pins[0].Verified {
		t.Fatalf("pins: %+v %v", pins, err)
	}
	if err := ApplyNetRoute(cfg, NetRouteRequest{Op: "delete", CIDR: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyNetDNS(cfg, NetDNSRequest{Op: "resolver_cleanup"}); err != nil {
		t.Fatal(err)
	}
}

func TestPrimitiveConcurrentEnsureUsesOneSlotChild(t *testing.T) {
	_, starts := mockSingBox(t)
	d := primitiveDaemon(t)
	cleanupPrimitiveChildren(t, d)
	req := ProcEnsureRequest{Kind: "sing-box", Slot: "concurrent", ConfigJSON: []byte(`{}`), SetPGID: true}
	replies := make(chan Response, 8)
	for range cap(replies) {
		go func() { replies <- primitiveRPC(t, d, Request{Action: "proc.ensure", ProcEnsure: &req}) }()
	}
	var first Response
	for i := 0; i < cap(replies); i++ {
		r := <-replies
		if !r.OK {
			t.Fatal(r.Error)
		}
		if i == 0 {
			first = r
		} else if r.PID != first.PID || r.Handle != first.Handle {
			t.Fatalf("concurrent slot created different children: %+v %+v", first, r)
		}
	}
	if starts.Load() != 1 {
		t.Fatalf("duplicate spawns: %d", starts.Load())
	}
	if group, err := syscall.Getpgid(first.PID); err != nil || group != first.PID {
		t.Fatalf("setpgid ignored: group=%d error=%v", group, err)
	}
}

func TestPrimitivePinManifestPathsAreConfined(t *testing.T) {
	for _, path := range []string{"../outside", "/private/data", "bin/../../outside", "bin/../vpn-core", ".", ""} {
		fixture := newVerificationFixture(t)
		d := newServiceDaemon(fixture.cfg, os.Getuid(), os.Getgid())
		d.socketVerification = fixture.dependencies
		manifest := Manifest{Version: manifestVersion, Files: []ManifestFile{{Path: path, SHA256: strings.Repeat("a", 64)}}}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture.cfg.ManifestPath(), data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := d.handleBinPin(BinPinRequest{Op: "verify"}); err == nil {
			t.Fatalf("unconfined pin accepted: %q", path)
		}
	}
}

func TestPrimitiveClientTimeoutSamplesPingWithoutRetry(t *testing.T) {
	cfg, listener := newRPCClientTestListener(t)
	withRPCServerIdentity(t, uint32(os.Getuid()), func(*net.UnixConn) (uint32, error) { return uint32(os.Getuid()), nil })
	oldTimeout := rpcResponseTimeoutVPNCore
	rpcResponseTimeoutVPNCore = 30 * time.Millisecond
	defer func() { rpcResponseTimeoutVPNCore = oldTimeout }()
	done := make(chan error, 1)
	go func() {
		original, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		defer original.Close()
		req, file, err := readRequest(original)
		if file != nil {
			_ = file.Close()
		}
		if err != nil || req.Action != "proc.ensure" {
			done <- fmt.Errorf("initial request=%s error=%v", req.Action, err)
			return
		}
		// Keep the original connection open with no reply until the client times
		// out. The only additional allowed RPC is the existing status snapshot.
		_ = listener.SetDeadline(time.Now().Add(2 * time.Second))
		snapshot, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		ping, log, err := readRequest(snapshot)
		if log != nil {
			_ = log.Close()
		}
		if err != nil || ping.Action != "ping" {
			_ = snapshot.Close()
			done <- fmt.Errorf("timeout retried mutation: %s %v", ping.Action, err)
			return
		}
		err = writeResponse(snapshot, Response{OK: true})
		_ = snapshot.Close()
		if err != nil {
			done <- err
			return
		}
		_ = listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
		unexpected, err := listener.AcceptUnix()
		if err == nil {
			_ = unexpected.Close()
			done <- errors.New("retry after timeout snapshot")
			return
		}
		done <- nil
	}()
	_, _, err := StartSingBox(cfg, []byte(`{}`), filepath.Join(t.TempDir(), "client.log"), true, LogOptions{})
	var timeout *RPCTimeoutError
	if !errors.As(err, &timeout) || timeout.Action != "proc.ensure" {
		t.Fatalf("timeout lost: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
