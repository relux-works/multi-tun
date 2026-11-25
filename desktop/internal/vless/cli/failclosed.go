package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"multi-tun/desktop/internal/core/failclosed"
	"multi-tun/desktop/internal/core/vpncore"
	"multi-tun/desktop/internal/vless/config"
)

// Injection points for tests. None of them starts, stops or reconfigures a tunnel.
var (
	failClosedApplyCLI  = vpncore.ApplyFailClosed
	failClosedClearCLI  = vpncore.ClearFailClosed
	failClosedStatusCLI = vpncore.FailClosedState
	failClosedLookupCLI = func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	// failClosedTunnelLookupCLI resolves through the tunnel's DNS (sing-box
	// hijacks DNS sent into the TUN, so any address routed into it answers).
	failClosedTunnelLookupCLI = func(ctx context.Context, server netip.AddrPort, host string) ([]netip.Addr, error) {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server.String())
		}}
		return r.LookupNetIP(ctx, "ip", host)
	}
	failClosedInterfacesCLI  = listInterfaces
	failClosedHelperReadyCLI = func() bool { return vpncore.Available(vpncore.DefaultServiceConfig()) }
	failClosedNowCLI         = time.Now
	failClosedTablePathCLI   = func() string {
		if root := userCacheRootCLI(); root != "" {
			return filepath.Join(root, "vless-tun", "failclosed-table.json")
		}
		return ""
	}
)

type ifaceInfo struct {
	Name string
	Up   bool
}

func listInterfaces() ([]ifaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ifaceInfo, 0, len(ifs))
	for _, i := range ifs {
		out = append(out, ifaceInfo{Name: i.Name, Up: i.Flags&net.FlagUp != 0})
	}
	return out, nil
}

func userCacheRootCLI() string {
	if value := os.Getenv("XDG_CACHE_HOME"); value != "" {
		return value
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".cache")
	}
	return ""
}

var physicalIfaceCLI = regexp.MustCompile(`^(en|bridge)[0-9]{1,3}$`)

// tunnelDNSServer returns the peer address of the first IPv4 TUN prefix
// (for example 172.19.0.2 for 172.19.0.1/30): it is routed into the TUN, where
// sing-box answers DNS.
func tunnelDNSServer(tunAddresses []string) (netip.AddrPort, bool) {
	for _, a := range tunAddresses {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil || !p.Addr().Is4() {
			continue
		}
		peer := p.Addr().Next()
		if !p.Contains(peer) {
			continue
		}
		return netip.AddrPortFrom(peer, 53), true
	}
	return netip.AddrPort{}, false
}

func (a *App) runFailClosed(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: vless-tun failclosed status|apply|off [--config path]")
		fmt.Fprintf(a.stderr, "emergency, if the helper does not answer: sudo pfctl -a %s -F all, then vless-tun failclosed off\n", failclosed.AnchorName)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("failclosed "+sub, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	switch sub {
	case "off":
		// Rollback in one command: clears the anchor and the pf token in the
		// helper. Never touches sing-box, its routes or DNS.
		if err := failClosedClearCLI(vpncore.DefaultServiceConfig()); err != nil {
			fmt.Fprintf(a.stderr, "failclosed off failed: %v\nemergency: sudo pfctl -a %s -F all, then run vless-tun failclosed off again once the helper answers\n", err, failclosed.AnchorName)
			return 1
		}
		fmt.Fprintln(a.stdout, "fail_closed: off (anchor cleared, pf token released; stays off after reboot until the next apply)")
		fmt.Fprintln(a.stdout, "to keep it off when the tunnel is next applied, set \"fail_closed\": {\"enabled\": false} in the config")
		return 0
	case "status", "apply":
	default:
		fmt.Fprintf(a.stderr, "unknown failclosed command %q; use status, apply or off\n", sub)
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "failclosed %s failed: %v\n", sub, err)
		return 1
	}
	policy, err := cfg.FailClosedPolicy()
	if err != nil {
		fmt.Fprintf(a.stderr, "failclosed %s failed: %v\n", sub, err)
		return 1
	}
	ifs, err := failClosedInterfacesCLI()
	if err != nil {
		fmt.Fprintf(a.stderr, "failclosed %s failed: %v\n", sub, err)
		return 1
	}
	tunnelUp := false
	var physical []string
	for _, i := range ifs {
		if i.Name == policy.TunnelInterface && i.Up {
			tunnelUp = true
		}
		if physicalIfaceCLI.MatchString(i.Name) && i.Up {
			physical = append(physical, i.Name)
		}
	}
	sort.Strings(physical)
	if sub == "status" {
		return a.printFailClosedStatus(policy, tunnelUp)
	}
	dnsServer, _ := tunnelDNSServer(cfg.TunAddresses())
	summary, err := a.applyFailClosedPolicy(policy, tunnelUp, physical, dnsServer)
	if err != nil {
		fmt.Fprintf(a.stderr, "failclosed apply failed: %v\nthe tunnel was not touched\n", err)
		return 1
	}
	fmt.Fprintln(a.stdout, summary)
	return 0
}

// applyFailClosedPolicy applies an enabled policy or clears a disabled one.
// It never touches the tunnel.
func (a *App) applyFailClosedPolicy(policy failclosed.Policy, tunnelUp bool, physical []string, tunnelDNS netip.AddrPort) (string, error) {
	if !policy.Enabled {
		if err := failClosedClearCLI(vpncore.DefaultServiceConfig()); err != nil {
			return "", err
		}
		return "fail_closed: disabled in config; anchor cleared", nil
	}
	table, err := a.refreshFailClosedTable(policy, tunnelUp, tunnelDNS)
	if err != nil {
		return "", err
	}
	if err := failClosedApplyCLI(vpncore.DefaultServiceConfig(), physical, table); err != nil {
		return "", err
	}
	return fmt.Sprintf("fail_closed: active services=%s addresses=%d physical=%s tunnel=%s",
		serviceNames(policy), len(table), strings.Join(physical, ","), upDown(tunnelUp)), nil
}

// refreshFailClosedAfterStart refreshes the address table once the tunnel is
// up (start or reconnect through the helper). Best effort: a failure is a
// warning and never affects the session that just started. A disabled policy
// is left alone here; 'failclosed apply' or 'off' change it explicitly.
func (a *App) refreshFailClosedAfterStart(policy failclosed.Policy, err error, tunAddresses []string) {
	if err != nil {
		fmt.Fprintf(a.stderr, "warning: fail_closed not refreshed: %v\n", err)
		return
	}
	if !policy.Enabled {
		return
	}
	ifs, ierr := failClosedInterfacesCLI()
	if ierr != nil {
		fmt.Fprintf(a.stderr, "warning: fail_closed not refreshed: %v\n", ierr)
		return
	}
	tunnelUp, physical := false, []string(nil)
	for _, i := range ifs {
		if i.Name == policy.TunnelInterface && i.Up {
			tunnelUp = true
		}
		if physicalIfaceCLI.MatchString(i.Name) && i.Up {
			physical = append(physical, i.Name)
		}
	}
	sort.Strings(physical)
	dnsServer, _ := tunnelDNSServer(tunAddresses)
	summary, aerr := a.applyFailClosedPolicy(policy, tunnelUp, physical, dnsServer)
	if aerr != nil {
		fmt.Fprintf(a.stderr, "warning: fail_closed not refreshed (the tunnel is unaffected): %v\n", aerr)
		return
	}
	fmt.Fprintln(a.stdout, summary)
}

// refreshFailClosedTable resolves the policy domains, merges them into the
// stored table, ages it (only while the tunnel is up) and returns the contents.
func (a *App) refreshFailClosedTable(policy failclosed.Policy, tunnelUp bool, tunnelDNS netip.AddrPort) ([]string, error) {
	path := failClosedTablePathCLI()
	var table failclosed.Table
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(data, &table); err != nil {
				fmt.Fprintf(a.stderr, "warning: ignoring unreadable fail-closed table %s: %v\n", path, err)
				table = failclosed.Table{}
			}
		}
	}
	now := failClosedNowCLI()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Union of the system resolver and, while the tunnel is up, the tunnel's
	// DNS: the two can answer differently (geo, split DNS).
	for _, host := range policy.ResolveNames() {
		if addrs, err := failClosedLookupCLI(ctx, host); err == nil {
			table.Merge(addrs, now)
		}
		if tunnelUp && tunnelDNS.IsValid() {
			if addrs, err := failClosedTunnelLookupCLI(ctx, tunnelDNS, host); err == nil {
				table.Merge(addrs, now)
			}
		}
	}
	table.Prune(now, tunnelUp)
	contents, err := policy.Contents(table)
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, errors.New("no addresses resolved and no cidrs configured; nothing to enforce")
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			if data, err := json.Marshal(table); err == nil {
				_ = os.WriteFile(path, data, 0o600)
			}
		}
	}
	return contents, nil
}

func (a *App) printFailClosedStatus(policy failclosed.Policy, tunnelUp bool) int {
	fmt.Fprintf(a.stdout, "config_enabled: %t\n", policy.Enabled)
	fmt.Fprintf(a.stdout, "config_services: %s\n", serviceNames(policy))
	fmt.Fprintf(a.stdout, "tunnel_interface: %s (%s)\n", policy.TunnelInterface, upDown(tunnelUp))
	st, err := failClosedStatusCLI(vpncore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(a.stdout, "helper: unavailable (%v)\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "helper_enabled: %t\n", st.Enabled)
	fmt.Fprintf(a.stdout, "helper_addresses: %d\n", st.TableEntries)
	fmt.Fprintf(a.stdout, "helper_physical_interfaces: %s\n", strings.Join(st.Interfaces, ","))
	fmt.Fprintf(a.stdout, "pf_token_held: %t\n", st.TokenHeld)
	if !st.AppliedAt.IsZero() {
		fmt.Fprintf(a.stdout, "applied_at: %s\n", st.AppliedAt.Format(time.RFC3339))
	}
	if st.LastError != "" {
		fmt.Fprintf(a.stdout, "last_error: %s\n", st.LastError)
	}
	if st.LastRecovery != "" {
		fmt.Fprintf(a.stdout, "last_recovery: %s at %s\n", st.LastRecovery, st.RecoveredAt.Format(time.RFC3339))
	}
	if st.LiveChecked {
		fmt.Fprintf(a.stdout, "pf_enabled: %t\n", st.PFEnabled)
		fmt.Fprintf(a.stdout, "anchor_loaded: %t\n", st.AnchorLoaded)
		fmt.Fprintf(a.stdout, "live_table_entries: %d\n", st.LiveTableEntries)
	}
	if st.LiveError != "" {
		fmt.Fprintf(a.stdout, "live_error: %s\n", st.LiveError)
	}
	if st.Backoff != "" {
		fmt.Fprintf(a.stdout, "watchdog: %s\n", st.Backoff)
	}
	fmt.Fprintf(a.stdout, "enforcing: %t\n", st.Enforcing)
	fmt.Fprintf(a.stdout, "blocking: %t\n", st.Enforcing && !tunnelUp)
	fmt.Fprintf(a.stdout, "limit: %s\n", failclosed.Limit)
	return 0
}

func serviceNames(p failclosed.Policy) string {
	names := make([]string, 0, len(p.Services))
	for _, s := range p.Services {
		names = append(names, s.Name)
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ",")
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// printFailClosedSummary prints one fail_closed line for status and diagnose.
// It reads only; it never applies or clears anything.
func (a *App) printFailClosedSummary(cfg config.ProjectConfig) {
	policy, err := cfg.FailClosedPolicy()
	switch {
	case err != nil:
		fmt.Fprintf(a.stdout, "fail_closed: config error: %v\n", err)
		return
	case !policy.Enabled:
		fmt.Fprintln(a.stdout, "fail_closed: disabled")
		return
	}
	st, err := failClosedStatusCLI(vpncore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(a.stdout, "fail_closed: services=%s helper=unavailable (%v)\n", serviceNames(policy), err)
		return
	}
	fmt.Fprintf(a.stdout, "fail_closed: services=%s enforcing=%t pf_enabled=%t anchor_loaded=%t (%s)\n",
		serviceNames(policy), st.Enforcing, st.PFEnabled, st.AnchorLoaded, failclosed.Limit)
}

// applyFailClosedBeforeStart puts the block in place before the tunnel comes
// up, so a first start (or a start after the policy changed) is already fail
// closed. Best effort and only through an installed helper; never affects the
// start that follows.
func (a *App) applyFailClosedBeforeStart(cfg config.ProjectConfig) {
	if !failClosedHelperReadyCLI() {
		return
	}
	policy, err := cfg.FailClosedPolicy()
	a.refreshFailClosedAfterStart(policy, err, cfg.TunAddresses())
}
