package stack

import (
	"context"
	"errors"
	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"multi-tun/desktop/internal/vless/config"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(s string) { l.mu.Lock(); defer l.mu.Unlock(); l.events = append(l.events, s) }
func (l *eventLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

type fakeProvider struct {
	mu         sync.Mutex
	kind       ProviderKind
	log        *eventLog
	active     map[string]MemberSpec
	failure    map[string]string
	received   []PreparedMember
	reconciled []PreparedMember
}

func (f *fakeProvider) Kind() ProviderKind { return f.kind }
func (f *fakeProvider) Prepare(ctx context.Context, s MemberSpec, peers []PreparedMember) (PreparedMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log.add("prepare:" + s.Selector)
	if f.failure[s.Selector] == "prepare" {
		return PreparedMember{}, errors.New("prepare refused")
	}
	r, d := MergeFragments(peers)
	f.received = append(f.received, PreparedMember{Spec: s, Routing: r, DNS: d})
	m := PreparedMember{Spec: s}
	if s.Role == "overlay" {
		m.Routing = RoutingFragment{RouteExcludes: []string{"203.0.113.1/32"}, DirectProcess: []string{"openconnect"}}
	}
	return m, ctx.Err()
}
func (f *fakeProvider) Start(ctx context.Context, m PreparedMember, r RoutingFragment, d DNSFragment) (MemberState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log.add("start:" + m.Spec.Selector)
	if f.failure[m.Spec.Selector] == "start" {
		return MemberState{}, errors.New("start refused")
	}
	f.active[m.Spec.Server] = m.Spec
	f.received = append(f.received, PreparedMember{Spec: m.Spec, Routing: r, DNS: d})
	return MemberState{Spec: m.Spec, Active: true, Status: "healthy", SessionID: m.Spec.Selector}, nil
}
func (f *fakeProvider) Stop(ctx context.Context, s MemberSpec, force bool, timeout time.Duration) (MemberState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log.add("stop:" + s.Selector)
	if ctx.Err() != nil {
		return MemberState{Spec: s, Active: true}, ctx.Err()
	}
	if f.failure[s.Selector] == "stop" {
		return MemberState{Spec: s, Active: true}, errors.New("stop refused")
	}
	delete(f.active, s.Server)
	return MemberState{Spec: s, Status: "stopped"}, nil
}
func (f *fakeProvider) Status(ctx context.Context, s MemberSpec) (MemberState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	live, active := f.active[s.Server]
	if active && f.failure[live.Selector] == "ready" {
		return MemberState{Spec: live}, nil
	}
	if active {
		return MemberState{Spec: live, Active: true, Status: "healthy", SessionID: live.Selector}, ctx.Err()
	}
	return MemberState{Spec: s, Status: "inactive"}, ctx.Err()
}
func (f *fakeProvider) Fragments(ctx context.Context, s MemberSpec) (RoutingFragment, DNSFragment, error) {
	f.log.add("fragments:" + s.Selector)
	return RoutingFragment{RouteExcludes: []string{"203.0.113.1/32", "10.20.0.0/16", "10.20.0.53/32"}, IncludeRoutes: []string{"10.20.0.0/16"}, DirectProcess: []string{"openconnect"}}, DNSFragment{Domains: []string{"corp.example"}, BypassDomains: []string{"public.example"}, Nameservers: []string{"10.20.0.53"}}, nil
}
func (f *fakeProvider) Reconcile(ctx context.Context, s MemberSpec, r RoutingFragment, d DNSFragment) (MemberState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log.add("reconcile:" + s.Selector)
	if f.failure[s.Selector] == "reconcile" {
		return MemberState{Spec: s, Active: true}, errors.New("reconcile refused")
	}
	f.reconciled = append(f.reconciled, PreparedMember{Spec: s, Routing: r, DNS: d})
	return MemberState{Spec: s, Active: true, Status: "healthy"}, nil
}
func testCoordinator(t *testing.T) (*Coordinator, *fakeProvider, *fakeProvider, *eventLog) {
	t.Helper()
	log := &eventLog{}
	oc := &fakeProvider{kind: ProviderOpenConnect, log: log, active: map[string]MemberSpec{}, failure: map[string]string{}}
	tun := &fakeProvider{kind: ProviderAmneziaAWG, log: log, active: map[string]MemberSpec{}, failure: map[string]string{}}
	resolve := func(ctx context.Context, selector string) (MemberSpec, error) {
		s, err := ParseSelector(selector)
		if err != nil {
			return s, err
		}
		switch s.Server {
		case "mts":
			s.Kind = ProviderOpenConnect
			s.Role = "overlay"
		case "amnezia", "other":
			s.Kind = ProviderAmneziaAWG
			s.Role = "egress"
		default:
			return s, errors.New("unknown server")
		}
		return s, nil
	}
	c := NewCoordinator(CoordinatorOptions{Providers: map[ProviderKind]TunnelProvider{oc.kind: oc, tun.kind: tun}, Resolve: resolve, StatePath: filepath.Join(t.TempDir(), "state.json")})
	return c, oc, tun, log
}
func assertCode(t *testing.T, err error, code RefusalCode) {
	t.Helper()
	var se *StackError
	if !errors.As(err, &se) || se.Code != code || se.Verdict != VerdictRefuse {
		t.Fatalf("error = %v; want %s Refuse", err, code)
	}
}
func TestStartStackSingleAndOverlayFirst(t *testing.T) {
	for _, selectors := range [][]string{{"amnezia/us"}, {"amnezia/us", "mts/outside"}} {
		t.Run(strings.Join(selectors, "+"), func(t *testing.T) {
			c, _, tun, log := testCoordinator(t)
			report, err := c.StartStack(context.Background(), selectors, StartStackOptions{})
			if err != nil || report.Verdict != VerdictAdmit || report.State != StateActive {
				t.Fatalf("start = %+v, %v", report, err)
			}
			events := log.all()
			starts := 0
			for _, event := range events {
				if event == "start:amnezia/us" {
					starts++
				}
			}
			if starts != 1 {
				t.Fatalf("egress started %d times: %v", starts, events)
			}
			if len(selectors) == 2 {
				want := []string{"prepare:mts/outside", "start:mts/outside", "fragments:mts/outside", "prepare:amnezia/us", "start:amnezia/us"}
				if !reflect.DeepEqual(events, want) {
					t.Fatalf("activation order = %v", events)
				}
				got := tun.received[len(tun.received)-1]
				if !reflect.DeepEqual(got.DNS.Domains, []string{"corp.example"}) || !reflect.DeepEqual(got.DNS.Nameservers, []string{"10.20.0.53"}) || len(got.Routing.RouteExcludes) != 3 || !reflect.DeepEqual(got.Routing.DirectProcess, []string{"openconnect"}) {
					t.Fatalf("lost live fragments: %+v", got)
				}
			}
			status, err := c.Status(context.Background())
			if err != nil || status.State != StateActive || len(status.Members) != len(selectors) {
				t.Fatalf("persisted status = %+v, %v", status, err)
			}
		})
	}
}
func TestValidationHasNoProviderEffects(t *testing.T) {
	cases := []struct {
		selectors []string
		code      RefusalCode
	}{{nil, StackEmpty}, {[]string{""}, StackInvalidSelector}, {[]string{"mts/"}, StackInvalidSelector}, {[]string{"mts/a/b"}, StackInvalidSelector}, {[]string{"mts/ outside"}, StackInvalidSelector}, {[]string{"missing/p"}, StackMemberUnknown}, {[]string{"amnezia/us", "amnezia/de"}, StackDuplicateServer}, {[]string{"amnezia/us", "other/us"}, StackTunConflict}}
	for _, tc := range cases {
		t.Run(string(tc.code)+strings.Join(tc.selectors, "+"), func(t *testing.T) {
			c, _, _, log := testCoordinator(t)
			_, err := c.StartStack(context.Background(), tc.selectors, StartStackOptions{})
			assertCode(t, err, tc.code)
			if len(log.all()) != 0 {
				t.Fatal("validation mutated providers")
			}
		})
	}
}
func TestStartFailureRollsBackOnlyThisAttempt(t *testing.T) {
	for phase, code := range map[string]RefusalCode{"prepare": ProviderPrepareFailed, "start": ProviderStartFailed, "ready": ReadinessFailed} {
		t.Run(phase, func(t *testing.T) {
			c, oc, tun, log := testCoordinator(t)
			tun.failure["amnezia/us"] = phase
			report, err := c.StartStack(context.Background(), []string{"mts/outside", "amnezia/us"}, StartStackOptions{})
			assertCode(t, err, code)
			if report.Verdict != VerdictRefuse || len(oc.active) != 0 || len(tun.active) != 0 {
				t.Fatalf("leaked started member: %+v, %v", report, err)
			}
			events := log.all()
			if events[len(events)-1] != "stop:mts/outside" {
				t.Fatalf("rollback order %v", events)
			}
			if len(report.RolledBack) == 0 {
				t.Fatal("rollback not recorded")
			}
		})
	}
	c, oc, tun, _ := testCoordinator(t)
	_, err := c.StartStack(context.Background(), []string{"mts/outside"}, StartStackOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tun.failure["amnezia/us"] = "start"
	_, err = c.Up(context.Background(), "amnezia/us", UpOptions{})
	assertCode(t, err, ProviderStartFailed)
	if len(oc.active) != 1 {
		t.Fatal("preexisting overlay rolled back")
	}
}
func TestRollbackFailureRetainsRecoveryState(t *testing.T) {
	c, oc, tun, _ := testCoordinator(t)
	oc.failure["mts/outside"] = "stop"
	tun.failure["amnezia/us"] = "start"
	_, err := c.StartStack(context.Background(), []string{"mts/outside", "amnezia/us"}, StartStackOptions{})
	assertCode(t, err, RollbackFailed)
	state, err := readState(c.statePath)
	if err != nil || len(state.Members) != 1 || state.Members[0].Spec.Server != "mts" {
		t.Fatalf("lost recovery state: %+v %v", state, err)
	}
}
func TestUpBothOrdersAndIdempotence(t *testing.T) {
	for _, overlayFirst := range []bool{true, false} {
		t.Run(fmtBool(overlayFirst), func(t *testing.T) {
			c, _, tun, log := testCoordinator(t)
			first, second := "amnezia/us", "mts/outside"
			if overlayFirst {
				first, second = second, first
			}
			if _, err := c.Up(context.Background(), first, UpOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Up(context.Background(), second, UpOptions{}); err != nil {
				t.Fatal(err)
			}
			before := len(log.all())
			report, err := c.Up(context.Background(), second, UpOptions{})
			if err != nil || !report.AlreadyActive || len(log.all()) != before {
				t.Fatalf("idempotence: %+v %v", report, err)
			}
			if overlayFirst {
				if len(tun.reconciled) != 0 {
					t.Fatal("egress restarted despite live overlay fragments")
				}
			} else {
				if len(tun.reconciled) != 2 {
					t.Fatalf("Order B reconcile count %d", len(tun.reconciled))
				}
				pre, post := tun.reconciled[0], tun.reconciled[1]
				if !reflect.DeepEqual(pre.Routing.RouteExcludes, []string{"203.0.113.1/32"}) || len(pre.DNS.Domains) != 0 || len(post.DNS.Domains) != 1 {
					t.Fatalf("preexclude/post fragments %+v %+v", pre, post)
				}
				events := log.all()
				preIndex, startIndex, postIndex := -1, -1, -1
				for i, e := range events {
					switch e {
					case "reconcile:amnezia/us":
						if preIndex < 0 {
							preIndex = i
						} else {
							postIndex = i
						}
					case "start:mts/outside":
						startIndex = i
					}
				}
				if !(preIndex < startIndex && startIndex < postIndex) {
					t.Fatalf("unsafe Order B: %v", events)
				}
			}
		})
	}
}
func fmtBool(value bool) string {
	if value {
		return "overlay-first"
	}
	return "egress-first"
}
func TestUpConflictAndReplacementPrevalidation(t *testing.T) {
	c, _, tun, log := testCoordinator(t)
	if _, err := c.Up(context.Background(), "amnezia/us", UpOptions{}); err != nil {
		t.Fatal(err)
	}
	before := len(log.all())
	_, err := c.Up(context.Background(), "other/us", UpOptions{})
	assertCode(t, err, StackTunConflict)
	if len(log.all()) != before {
		t.Fatal("conflict mutated providers")
	}
	tun.failure["other/us"] = "prepare"
	_, err = c.Up(context.Background(), "other/us", UpOptions{Replace: true})
	assertCode(t, err, ProviderPrepareFailed)
	if _, ok := tun.active["amnezia"]; !ok {
		t.Fatal("old egress stopped before prevalidation")
	}
	delete(tun.failure, "other/us")
	if _, err := c.Up(context.Background(), "other/us", UpOptions{Replace: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := tun.active["amnezia"]; ok {
		t.Fatal("old egress survived replace")
	}
}
func TestDownAndStopRoleOrder(t *testing.T) {
	for _, remove := range []string{"mts/outside", "amnezia/us", "all"} {
		t.Run(remove, func(t *testing.T) {
			c, oc, tun, log := testCoordinator(t)
			if _, err := c.StartStack(context.Background(), []string{"mts/outside", "amnezia/us"}, StartStackOptions{}); err != nil {
				t.Fatal(err)
			}
			before := len(log.all())
			var report StackReport
			var err error
			if remove == "all" {
				report, err = c.StopStack(context.Background(), DownOptions{})
			} else {
				report, err = c.Down(context.Background(), remove, DownOptions{})
			}
			if err != nil || report.Verdict != VerdictClose {
				t.Fatalf("down: %+v %v", report, err)
			}
			events := log.all()[before:]
			switch remove {
			case "mts/outside":
				if len(tun.active) != 1 || len(oc.active) != 0 || len(tun.reconciled) != 1 || len(tun.reconciled[0].DNS.Domains) != 0 {
					t.Fatal("surviving egress not cleaned")
				}
			case "amnezia/us":
				if !reflect.DeepEqual(events, []string{"stop:amnezia/us"}) || len(oc.active) != 1 {
					t.Fatalf("overlay disturbed: %v", events)
				}
			case "all":
				if !reflect.DeepEqual(events, []string{"stop:amnezia/us", "stop:mts/outside"}) || report.State != StateIdle {
					t.Fatalf("stop order: %v", events)
				}
			}
		})
	}
}
func TestStatePersistenceSerializesIndependentCoordinators(t *testing.T) {
	c, _, _, log := testCoordinator(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		other := NewCoordinator(CoordinatorOptions{Providers: c.providers, Resolve: c.resolve, StatePath: c.statePath})
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := other.Up(context.Background(), "amnezia/us", UpOptions{})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	starts := 0
	for _, e := range log.all() {
		if e == "start:amnezia/us" {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("concurrent activation count %d", starts)
	}
	state, err := readState(c.statePath)
	if err != nil || len(state.Members) != 1 {
		t.Fatalf("state: %+v %v", state, err)
	}
}
func TestMergeFragmentsCopiesAndSorts(t *testing.T) {
	source := []string{"b", "a", "b"}
	r, d := MergeFragments([]PreparedMember{{Routing: RoutingFragment{RouteExcludes: source}, DNS: DNSFragment{Domains: source}}})
	if !reflect.DeepEqual(r.RouteExcludes, []string{"a", "b"}) || !reflect.DeepEqual(d.Domains, []string{"a", "b"}) || !reflect.DeepEqual(source, []string{"b", "a", "b"}) {
		t.Fatalf("merge mutated or lost fragments: %+v %+v %v", r, d, source)
	}
}

func TestOpenConnectProviderUnifiedAndLegacyAliases(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmtBool(legacy), func(t *testing.T) {
			spec := MemberSpec{Selector: "mts/outside", Server: "mts", Profile: "outside", Kind: ProviderOpenConnect, Role: "overlay"}
			cfg := config.ProjectConfig{OpenConnectConfigPath: "/neutral/legacy.json", Servers: map[string]config.ServerConfig{"mts": {Engine: &config.EngineConfig{Type: config.EngineOpenConnect}, OpenConnect: &config.OpenConnectServerConfig{ServerURL: "https://vpn.example", CacheDir: t.TempDir(), Auth: &openconnectcfg.AuthConfig{UsernameKeychainAccount: "sample/user", PasswordKeychainAccount: "sample/password", SecondFactor: &openconnectcfg.SecondFactorConfig{Mode: openconnectcfg.SecondFactorModeTOTPAuto, TOTPKeychainAccount: "sample/totp"}}, SplitInclude: &openconnectcfg.SplitIncludeConfig{Routes: []string{"10.20.0.0/16"}, VPNDomains: []string{"corp.example"}, Nameservers: []string{"10.20.0.53"}}, PAC: &openconnectcfg.PACConfig{Rewrites: []openconnectcfg.PACRewriteRule{{Host: "mybonus.mts.ru", Return: "DIRECT"}}}}, Profiles: map[string]config.ProfileConfig{"outside": {OpenConnect: &openconnectcfg.ProfileConfig{Name: "Native Outside", Mode: "split-include"}}}}}}
			server := cfg.Servers["mts"]
			oc := server.OpenConnect
			provider := &OpenConnectProvider{Config: cfg, LookupSecret: func(account string) (string, error) { return "synthetic-" + account, nil }, LookupIP: func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP("203.0.113.1")}}, nil
			}, InterfacePresent: func(string) bool { return true }}
			if legacy {
				provider.Config.Servers = nil
				provider.LoadConfig = func(path string) (openconnectcfg.Config, string, error) {
					if path != "/neutral/legacy.json" {
						t.Fatal("legacy config path lost")
					}
					return openconnectcfg.Config{CacheDir: oc.CacheDir, Servers: map[string]openconnectcfg.ServerConfig{"mts": {ServerURL: oc.ServerURL, Auth: oc.Auth, SplitInclude: oc.SplitInclude, PAC: oc.PAC, Profiles: map[string]openconnectcfg.ProfileConfig{"mts-outside": {Name: "Native Outside", Mode: "split-include"}}}}}, path, nil
				}
			}
			resolved, err := provider.Resolve(context.Background(), spec.Selector)
			if err != nil || resolved.Kind != ProviderOpenConnect {
				t.Fatalf("resolve %+v %v", resolved, err)
			}
			prepared, err := provider.Prepare(context.Background(), spec, nil)
			if err != nil {
				t.Fatal(err)
			}
			var current openconnect.CurrentSession
			provider.LoadSession = func(string) (openconnect.CurrentSession, error) {
				if current.ID == "" {
					return current, os.ErrNotExist
				}
				return current, nil
			}
			provider.SessionAlive = func(c openconnect.CurrentSession) (bool, int, error) { return c.PID > 0, c.PID, nil }
			provider.Connect = func(options openconnect.ConnectOptions) (openconnect.ConnectResult, error) {
				if !options.SuppressReconcile || options.Profile != "Native Outside" || options.Credentials.TOTPSecret != "synthetic-sample/totp" || options.Credentials.Username != "synthetic-sample/user" || len(options.PACRewrites) != 1 || !reflect.DeepEqual(options.GatewayIPs, []string{"203.0.113.1"}) {
					t.Fatalf("lost provider contract: profile=%q suppress=%t", options.Profile, options.SuppressReconcile)
				}
				current = openconnect.CurrentSession{ID: "session", PID: 42, Server: options.Server, Profile: options.Profile, Interface: "utun9", Mode: options.Mode, GatewayIPs: options.GatewayIPs, IncludeRoutes: options.IncludeRoutes, VPNDomains: options.VPNDomains, VPNNameservers: options.VPNNameservers}
				return openconnect.ConnectResult{SessionID: current.ID, PID: current.PID, Interface: current.Interface}, nil
			}
			member, err := provider.Start(context.Background(), prepared, RoutingFragment{}, DNSFragment{})
			if err != nil || !member.Active {
				t.Fatalf("start %+v %v", member, err)
			}
			routing, dns, err := provider.Fragments(context.Background(), spec)
			if err != nil || len(routing.RouteExcludes) != 3 || !reflect.DeepEqual(dns.Domains, []string{"corp.example"}) || !reflect.DeepEqual(dns.Nameservers, []string{"10.20.0.53"}) {
				t.Fatalf("live emission %+v %+v %v", routing, dns, err)
			}
			provider.InterfacePresent = func(string) bool { return false }
			unhealthy, err := provider.Status(context.Background(), resolved)
			if err != nil || !unhealthy.Active || unhealthy.Status != "degraded" {
				t.Fatal("missing interface was treated as healthy or as a stopped process")
			}
			provider.InterfacePresent = func(string) bool { return true }
			provider.StopSession = func(string, time.Duration) (openconnect.CurrentSession, string, error) {
				old := current
				current.PID = 0
				return old, "stopped", nil
			}
			if member, err := provider.Stop(context.Background(), resolved, false, time.Second); err != nil || member.Active {
				t.Fatalf("stop %+v %v", member, err)
			}
		})
	}
}
func TestCoordinatorUnavailableAndCanceledOperationsAreInert(t *testing.T) {
	c, _, _, log := testCoordinator(t)
	delete(c.providers, ProviderAmneziaAWG)
	_, err := c.StartStack(context.Background(), []string{"amnezia/us"}, StartStackOptions{})
	assertCode(t, err, ProviderUnavailable)
	if len(log.all()) != 0 {
		t.Fatal("unavailable provider mutated state")
	}
	c, _, _, log = testCoordinator(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.StartStack(ctx, []string{"mts/outside"}, StartStackOptions{})
	if err == nil || len(log.all()) != 0 {
		t.Fatal("canceled activation had effects")
	}
}

func TestUpDiscoversAlreadyActiveUntrackedMember(t *testing.T) {
	c, oc, _, log := testCoordinator(t)
	spec, err := c.resolveSpec(context.Background(), "mts/outside")
	if err != nil {
		t.Fatal(err)
	}
	oc.active[spec.Server] = spec
	report, err := c.Up(context.Background(), "mts/outside", UpOptions{})
	if err != nil || !report.AlreadyActive || len(log.all()) != 0 {
		t.Fatalf("untracked member was restarted: %+v %v %v", report, err, log.all())
	}
	if _, err := c.Down(context.Background(), "mts/outside", DownOptions{}); err != nil || len(oc.active) != 0 {
		t.Fatalf("untracked member was not stopped: %v", err)
	}
}
func TestStackStateLockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	unlock, err := lockState(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if release, err := lockState(ctx, path); err == nil {
		release()
		t.Fatal("concurrent lock ignored cancellation")
	}
}
