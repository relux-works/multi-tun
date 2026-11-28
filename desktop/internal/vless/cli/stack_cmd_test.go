package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnectcfg"
	"multi-tun/desktop/internal/stack"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/session"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
)

type fakeStackCLI struct {
	calls     []string
	selectors []string
	replace   bool
	force     bool
	refresh   bool
	timeout   time.Duration
}

func (f *fakeStackCLI) StartStack(ctx context.Context, selectors []string, o stack.StartStackOptions) (stack.StackReport, error) {
	f.calls = append(f.calls, "start")
	f.selectors = append([]string(nil), selectors...)
	f.refresh = o.Refresh
	return stack.StackReport{Verdict: stack.VerdictAdmit, State: stack.StateActive}, nil
}
func (f *fakeStackCLI) Up(ctx context.Context, s string, o stack.UpOptions) (stack.StackReport, error) {
	f.calls = append(f.calls, "up")
	f.selectors = []string{s}
	f.replace, f.refresh, f.timeout = o.Replace, o.Refresh, o.Timeout
	return stack.StackReport{Verdict: stack.VerdictAdmit, State: stack.StateActive}, nil
}
func (f *fakeStackCLI) Down(ctx context.Context, s string, o stack.DownOptions) (stack.StackReport, error) {
	f.calls = append(f.calls, "down")
	f.selectors = []string{s}
	f.force, f.timeout = o.Force, o.Timeout
	return stack.StackReport{Verdict: stack.VerdictClose}, nil
}
func (f *fakeStackCLI) StopStack(ctx context.Context, o stack.DownOptions) (stack.StackReport, error) {
	f.calls = append(f.calls, "stop")
	f.force, f.timeout = o.Force, o.Timeout
	return stack.StackReport{Verdict: stack.VerdictClose}, nil
}
func (f *fakeStackCLI) Status(ctx context.Context) (stack.StackStatus, error) {
	f.calls = append(f.calls, "status")
	return stack.StackStatus{State: stack.StateActive}, nil
}
func stackCLIConfig(t *testing.T) (string, config.ProjectConfig) {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.CacheDir = filepath.Join(dir, "cache")
	cfg.Artifacts.SingboxConfigPath = filepath.Join(dir, "sing-box.json")
	cfg.Current = &config.CurrentConfig{Server: "amnezia", Profile: "us"}
	cfg.Servers = map[string]config.ServerConfig{
		"amnezia": {Engine: &config.EngineConfig{Type: config.EngineVLESS}, Source: config.SourceConfig{Mode: config.SourceModeDirect, URL: amneziaTestURI}, Profiles: map[string]config.ProfileConfig{"us": {Selector: "USA"}, "de": {Selector: "DE"}}},
		"mts":     {Engine: &config.EngineConfig{Type: config.EngineOpenConnect}, Source: config.SourceConfig{Mode: config.SourceModeOpenConnect}, OpenConnect: &config.OpenConnectServerConfig{ServerURL: "https://vpn.example"}, Profiles: map[string]config.ProfileConfig{"outside": {OpenConnect: &openconnectcfg.ProfileConfig{Name: "Native Outside"}}}},
	}
	path := filepath.Join(dir, "config.json")
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}
func TestStartStackDisambiguationPreservesLegacy(t *testing.T) {
	_, cfg := stackCLIConfig(t)
	for _, tc := range []struct {
		args  []string
		stack bool
	}{{nil, false}, {[]string{"amnezia", "us"}, false}, {[]string{"amnezia/us"}, false}, {[]string{"amnezia"}, false}, {[]string{"mts/outside"}, true}, {[]string{"mts"}, true}, {[]string{"mts/outside", "amnezia/us"}, true}, {[]string{"mts", "amnezia"}, true}, {[]string{"amnezia", "us", "extra"}, true}} {
		if got := shouldStartStack(cfg, tc.args); got != tc.stack {
			t.Fatalf("classification %v = %t", tc.args, got)
		}
	}
	cfg.Stack = []string{"amnezia/us"}
	if !shouldStartStack(cfg, nil) {
		t.Fatal("configured stack ignored")
	}
}
func TestUnifiedCLIStackLifecycleDispatch(t *testing.T) {
	path, cfg := stackCLIConfig(t)
	fake := &fakeStackCLI{}
	previous, previousStop := newStackCoordinatorCLI, stopCurrentSessionFunc
	newStackCoordinatorCLI = func(a *App, c config.ProjectConfig, p string, refresh bool) (stackController, error) {
		if p != path {
			t.Fatal("lost config path")
		}
		return fake, nil
	}
	stopCurrentSessionFunc = func(string, config.PrivilegedLaunchConfig, bool, time.Duration) (*session.CurrentSession, string, error) {
		return nil, "none", nil
	}
	defer func() { newStackCoordinatorCLI, stopCurrentSessionFunc = previous, previousStop }()
	run := func(args ...string) {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := NewWithName(&out, &errOut, "tun-wave").Run(args); code != 0 {
			t.Fatalf("%v: exit=%d %s", args, code, errOut.String())
		}
	}
	run("start", "--config", path, "mts/outside", "amnezia/us")
	if !reflect.DeepEqual(fake.selectors, []string{"mts/outside", "amnezia/us"}) {
		t.Fatal("lost explicit stack selectors")
	}
	cfg.Stack = []string{"amnezia/us"}
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	run("start", "--config", path)
	if !reflect.DeepEqual(fake.selectors, cfg.Stack) {
		t.Fatal("configured stack ignored")
	}
	cfg.Current = &config.CurrentConfig{Server: "mts", Profile: "outside"}
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	run("start", "--config", path)
	if !reflect.DeepEqual(fake.selectors, cfg.Stack) {
		t.Fatal("current openconnect selection overrode configured stack")
	}
	cfg.Current = &config.CurrentConfig{Server: "amnezia", Profile: "us"}
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	run("start", "--config", path, "mts/outside")
	if !reflect.DeepEqual(fake.selectors, []string{"mts/outside"}) {
		t.Fatal("single OC selector not dispatched")
	}
	run("up", "--config", path, "--refresh", "--replace", "amnezia/us")
	if !fake.replace || !fake.refresh || fake.calls[len(fake.calls)-1] != "up" {
		t.Fatal("up flags lost")
	}
	run("down", "--config", path, "--force", "--timeout", "2s", "mts/outside")
	if !fake.force || fake.timeout != 2*time.Second || fake.calls[len(fake.calls)-1] != "down" {
		t.Fatal("down flags lost")
	}
	run("stop", "--config", path, "mts/outside")
	if fake.calls[len(fake.calls)-1] != "down" {
		t.Fatal("member stop did not use coordinator")
	}
	run("stop", "--config", path)
	if fake.calls[len(fake.calls)-1] != "stop" {
		t.Fatal("stop all did not use coordinator")
	}
	run("status", "--config", path)
	if fake.calls[len(fake.calls)-1] != "status" {
		t.Fatal("status did not inspect stack")
	}
	cfg.Stack = nil
	if _, err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	app := New(io.Discard, io.Discard)
	for _, args := range [][]string{{"--config", path, "amnezia", "us"}, {"--config", path, "amnezia/us"}, {"--config", path, "--server", "amnezia", "--profile", "us"}, {"--config", path}} {
		if handled, _ := app.maybeStackStart(args); handled {
			t.Fatalf("legacy path captured by stack: %v", args)
		}
	}
}
func TestCoordinatedRouteOnlyExclusionDoesNotInventDNS(t *testing.T) {
	input := []byte(`{"inbounds":[{"type":"tun","interface_name":"utun233","address":["172.19.0.1/30"]}],"dns":{"rules":[]},"route":{"rules":[]}}`)
	result, addresses, err := applyCoordinatedRouting(input, stack.RoutingFragment{RouteExcludes: []string{"172.19.0.0/16", "203.0.113.1/32"}, DirectProcess: []string{"openconnect"}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatal(err)
	}
	inbound := doc["inbounds"].([]any)[0].(map[string]any)
	if len(inbound["route_exclude_address"].([]any)) != 2 || len(addresses) != 1 || addresses[0] == "172.19.0.1/30" {
		t.Fatalf("gateway exclusion/subnet avoidance missing: %s", result)
	}
	if strings.Contains(string(result), "nameservers") || strings.Contains(string(result), "corp.example") {
		t.Fatal("route-only reconciliation invented DNS")
	}
	if _, _, err := applyCoordinatedRouting(input, stack.RoutingFragment{RouteExcludes: []string{"bad-route"}}); err == nil {
		t.Fatal("invalid overlay route accepted")
	}
}
func TestPACServeIsRegisteredInUnifiedCLI(t *testing.T) {
	var stderr bytes.Buffer
	if code := NewWithName(io.Discard, &stderr, "tun-wave").Run([]string{"__pac-serve", "--upstream-url"}); code != 2 || strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("PAC dispatch exit %d: %s", code, stderr.String())
	}
}
func TestStackStateUsesConfigCache(t *testing.T) {
	path, cfg := stackCLIConfig(t)
	coordinator, err := New(io.Discard, io.Discard).buildStackCoordinator(cfg, path, false)
	if err != nil || coordinator == nil {
		t.Fatal(err)
	}
	// Construction must be inert: no cache, process or credentials are touched.
	if _, err := os.Stat(cfg.CacheDir); !os.IsNotExist(err) {
		t.Fatal("coordinator construction touched runtime state")
	}
}

func TestStackPreparationPreservesPreviousRenderAndUsesExplicitFragments(t *testing.T) {
	path, cfg := stackCLIConfig(t)
	target := cfg.Artifacts.SingboxConfigPath
	previous := []byte("previous rendered bytes\n")
	if err := os.WriteFile(target, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	oldLookup, oldLaunch, oldRender, oldRefresh := lookPathFunc, resolveLaunchModeCLI, resolveRenderOptionsCLI, refreshSourceFunc
	lookPathFunc = func(string) (string, error) { return "/fake/sing-box", nil }
	resolveLaunchModeCLI = func(string, config.PrivilegedLaunchConfig) (string, error) { return config.LaunchModeDirect, nil }
	resolveRenderOptionsCLI = func(string) singbox.RenderOptions {
		t.Fatal("coordinated preparation scraped overlay state")
		return singbox.RenderOptions{}
	}
	profile, err := subscription.ParseVLESSURI(amneziaTestURI)
	if err != nil {
		t.Fatal(err)
	}
	refreshSourceFunc = func(config.ProjectConfig) (subscription.CacheSnapshot, error) {
		return subscription.CacheSnapshot{Profiles: []model.Profile{profile}}, nil
	}
	defer func() {
		lookPathFunc, resolveLaunchModeCLI, resolveRenderOptionsCLI, refreshSourceFunc = oldLookup, oldLaunch, oldRender, oldRefresh
	}()
	spec := stack.MemberSpec{Selector: "amnezia/us", Server: "amnezia", Profile: "us", Kind: stack.ProviderVLESS, Role: "egress"}
	prepared, err := New(io.Discard, io.Discard).prepareStackTUN(context.Background(), cfg, path, spec, stack.RoutingFragment{RouteExcludes: []string{"203.0.113.1/32"}}, stack.DNSFragment{Domains: []string{"corp.example"}, Nameservers: []string{"10.20.0.53"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(actual, previous) {
		t.Fatal("prevalidation replaced the running session's rendered file")
	}
	var candidate []byte
	for _, file := range prepared.rendered {
		if file.path == target {
			candidate = file.data
		}
	}
	for _, want := range []string{"corp.example", "10.20.0.53", "203.0.113.1/32"} {
		if !bytes.Contains(candidate, []byte(want)) {
			t.Fatalf("candidate lost explicit fragment %s", want)
		}
	}
}
