package cli

import (
	"flag"
	"fmt"
	"slices"
	"strings"

	"multi-tun/desktop/internal/vless/session"
)

func (a *App) runReconcile(args []string) int {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	force := fs.Bool("force", false, "Reconnect even when overlay DNS already matches")
	reason := fs.String("reason", "", "Optional reconciliation reason")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "reconcile failed: unexpected positional arguments")
		return 2
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "reconcile failed: %v\n", err)
		return 1
	}
	targets, err := sessionTargetsForConfig(*configPath, "")
	if err != nil {
		fmt.Fprintf(a.stderr, "reconcile failed: %v\n", err)
		return 1
	}
	var current *session.CurrentSession
	for _, target := range targets {
		candidate, _, alive, err := currentSessionStateForSelection(target.cacheDir, target.launch)
		if err != nil {
			fmt.Fprintf(a.stderr, "reconcile failed: inspect session: %v\n", err)
			return 1
		}
		if !alive {
			continue
		}
		if candidate == nil || current != nil {
			fmt.Fprintln(a.stderr, "reconcile failed: cannot identify one active session")
			return 1
		}
		current = candidate
	}
	if current == nil {
		fmt.Fprintln(a.stdout, "reconcile: no active session")
		return 0
	}
	desired := resolveRenderOptionsCLI(cfg.NetworkMode()).OverlayDNS
	desiredActive := desired != nil
	var desiredDomains []string
	if desiredActive {
		desiredDomains = normalizedReconcileDomains(desired.Domains)
	}
	if !*force && desiredActive == current.OverlayDNSActive && slices.Equal(desiredDomains, normalizedReconcileDomains(current.OverlayDNSDomains)) {
		fmt.Fprintf(a.stdout, "reconcile: already converged (overlay_active=%t)\n", desiredActive)
		return 0
	}

	reconnectArgs := []string{"--refresh=false"}
	if *configPath != "" {
		reconnectArgs = append(reconnectArgs, "--config", *configPath)
	}
	if (current.ResolvedServer == "" || current.ResolvedAlias == "") && strings.TrimSpace(current.ProfileID) == "" {
		fmt.Fprintln(a.stderr, "reconcile failed: active session has no profile selector")
		return 1
	}
	switch {
	case current.ResolvedServer != "" && current.ResolvedAlias != "":
		reconnectArgs = append(reconnectArgs, current.ResolvedServer+"/"+current.ResolvedAlias)
	case current.ResolvedServer != "":
		reconnectArgs = append(reconnectArgs, "--server", current.ResolvedServer, "--selector", current.ProfileID)
	default:
		reconnectArgs = append(reconnectArgs, "--selector", current.ProfileID)
	}
	fmt.Fprintf(a.stdout, "reconcile: reconnecting (overlay_active=%t reason=%q)\n", desiredActive, *reason)
	return a.runReconnect(reconnectArgs)
}

func normalizedReconcileDomains(values []string) []string {
	domains := make([]string, 0, len(values))
	for _, domain := range values {
		domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	slices.Sort(domains)
	return slices.Compact(domains)
}
