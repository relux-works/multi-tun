package singbox

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

type OverlayDNS struct {
	Domains       []string
	Nameservers   []string
	RouteExcludes []string
}

type RenderOptions struct {
	OverlayDNS *OverlayDNS
}

func Render(cfg config.ProjectConfig, profile model.Profile) ([]byte, error) {
	return RenderWithOptions(cfg, profile, RenderOptions{})
}

func RenderWithOptions(cfg config.ProjectConfig, profile model.Profile, options RenderOptions) ([]byte, error) {
	proxyOutbound, err := buildVLESSOutbound(cfg, profile)
	if err != nil {
		return nil, err
	}
	return renderWithProxyOutbound(cfg, profile, options, proxyRenderBackend{
		Outbound:              proxyOutbound,
		UseUpstreamDirectDNS:  upstreamHostNeedsDirectDNS(profile),
		UpstreamRouteExcludes: upstreamRouteExcludeCIDRs(profile),
	})
}

func RenderXrayFrontendWithOptions(cfg config.ProjectConfig, profile model.Profile, options RenderOptions) ([]byte, error) {
	proxyOutbound := map[string]any{
		"type":        "socks",
		"tag":         "proxy",
		"server":      cfg.XraySocksListen(),
		"server_port": cfg.XraySocksPort(),
		"version":     "5",
	}
	return renderWithProxyOutbound(cfg, profile, options, proxyRenderBackend{
		Outbound:           proxyOutbound,
		DirectProcessNames: cfg.XrayProcessNames(),
	})
}

type proxyRenderBackend struct {
	Outbound              map[string]any
	UseUpstreamDirectDNS  bool
	UpstreamRouteExcludes []string
	DirectProcessNames    []string
}

func renderWithProxyOutbound(cfg config.ProjectConfig, profile model.Profile, options RenderOptions, backend proxyRenderBackend) ([]byte, error) {
	mode := cfg.NetworkMode()
	bypassSuffixes := cfg.NormalizedBypassSuffixes()
	bypassExcludes := cfg.NormalizedBypassExcludes()
	directRoutes := cfg.NormalizedRoutes()
	overlayDNS := normalizeOverlayDNS(options.OverlayDNS)
	useOverlayDNS := mode == config.RenderModeTun && overlayDNS != nil
	proxyResolver := cfg.ProxyResolver()

	if backend.Outbound == nil {
		return nil, fmt.Errorf("proxy outbound is required")
	}
	proxyOutbound := backend.Outbound
	useUpstreamDirectDNS := backend.UseUpstreamDirectDNS

	useBypassRules := len(bypassSuffixes) > 0
	useBypassExcludes := len(bypassExcludes) > 0
	useDirectRoutes := len(directRoutes) > 0
	useBypassDNSRules := mode == config.RenderModeTun && useBypassRules
	useBypassExcludeDNSRules := mode == config.RenderModeTun && useBypassExcludes
	directDomainResolver := "dns-direct"
	if useOverlayDNS {
		directDomainResolver = "dns-proxy"
	}
	upstreamRouteExcludes := normalizeRouteExcludes(backend.UpstreamRouteExcludes)

	dnsServers := []any{
		map[string]any{
			"type":        "tls",
			"tag":         "dns-proxy",
			"server":      proxyResolver.Address,
			"server_port": proxyResolver.Port,
			"detour":      "proxy",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": proxyResolver.TLSServerName,
			},
		},
	}
	if !useOverlayDNS || useBypassDNSRules || useUpstreamDirectDNS {
		dnsServers = append([]any{
			map[string]any{
				"type":   "local",
				"tag":    "dns-direct",
				"detour": "direct",
			},
		}, dnsServers...)
	}
	if useOverlayDNS {
		dnsServers = append(dnsServers, map[string]any{
			"type":        "udp",
			"tag":         "dns-overlay",
			"server":      overlayDNS.Nameservers[0],
			"server_port": 53,
			"detour":      "direct",
		})
	}
	dnsRules := []any{
		map[string]any{
			"action": "route",
			"server": "dns-proxy",
		},
	}
	if useOverlayDNS {
		dnsRules = append([]any{
			map[string]any{
				"domain_suffix": overlayDNS.Domains,
				"action":        "route",
				"server":        "dns-overlay",
			},
		}, dnsRules...)
	}
	routeRuleSet := []any{}
	routeRules := append(processNameDirectRules(backend.DirectProcessNames), baseRouteRules(cfg, mode)...)

	if len(upstreamRouteExcludes) > 0 {
		routeRuleSet = append(routeRuleSet, map[string]any{
			"type": "inline",
			"tag":  "upstream-direct",
			"rules": []any{
				map[string]any{
					"ip_cidr": upstreamRouteExcludes,
				},
			},
		})
		routeRules = append(routeRules, map[string]any{
			"rule_set": []string{"upstream-direct"},
			"action":   "route",
			"outbound": "direct",
		})
	}

	if useBypassDNSRules {
		dnsRules = append([]any{
			map[string]any{
				"rule_set": []string{"ru-direct"},
				"action":   "route",
				"server":   "dns-direct",
			},
		}, dnsRules...)
	}
	if useBypassExcludeDNSRules {
		dnsRules = append([]any{
			map[string]any{
				"rule_set": []string{"proxy-exceptions"},
				"action":   "route",
				"server":   "dns-proxy",
			},
		}, dnsRules...)
	}

	if useBypassExcludes {
		routeRuleSet = append([]any{
			map[string]any{
				"type": "inline",
				"tag":  "proxy-exceptions",
				"rules": []any{
					map[string]any{
						"domain_suffix": bypassExcludes,
					},
				},
			},
		}, routeRuleSet...)
		routeRules = append(routeRules, map[string]any{
			"rule_set": []string{"proxy-exceptions"},
			"action":   "route",
			"outbound": "proxy",
		})
	}

	if useBypassRules {
		routeRuleSet = append(routeRuleSet, map[string]any{
			"type": "inline",
			"tag":  "ru-direct",
			"rules": []any{
				map[string]any{
					"domain_suffix": bypassSuffixes,
				},
			},
		})
		routeRules = append(routeRules, map[string]any{
			"rule_set": []string{"ru-direct"},
			"action":   "route",
			"outbound": "direct",
		})
	}

	if useDirectRoutes {
		routeRuleSet = append(routeRuleSet, map[string]any{
			"type": "inline",
			"tag":  "direct-routes",
			"rules": []any{
				map[string]any{
					"ip_cidr": directRoutes,
				},
			},
		})
		routeRules = append(routeRules, map[string]any{
			"rule_set": []string{"direct-routes"},
			"action":   "route",
			"outbound": "direct",
		})
	}

	inbounds, err := buildInbounds(cfg, overlayDNS, upstreamRouteExcludes)
	if err != nil {
		return nil, err
	}

	root := map[string]any{
		"log": map[string]any{
			"level": cfg.LogLevel(),
		},
		"dns": map[string]any{
			"servers":         dnsServers,
			"rules":           dnsRules,
			"final":           "dns-proxy",
			"strategy":        "prefer_ipv4",
			"reverse_mapping": true,
		},
		"inbounds": inbounds,
		"outbounds": []any{
			proxyOutbound,
			map[string]any{
				"type":            "direct",
				"tag":             "direct",
				"domain_resolver": directDomainResolver,
			},
			map[string]any{
				"type": "block",
				"tag":  "block",
			},
		},
		"route": map[string]any{
			"auto_detect_interface": true,
			"default_domain_resolver": map[string]any{
				"server":   "dns-proxy",
				"strategy": "prefer_ipv4",
			},
			"rule_set": routeRuleSet,
			"rules":    routeRules,
			"final":    "proxy",
		},
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func normalizeOverlayDNS(overlay *OverlayDNS) *OverlayDNS {
	if overlay == nil {
		return nil
	}

	domains := make([]string, 0, len(overlay.Domains))
	seenDomains := map[string]struct{}{}
	for _, domain := range overlay.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if _, ok := seenDomains[domain]; ok {
			continue
		}
		seenDomains[domain] = struct{}{}
		domains = append(domains, domain)
	}

	nameservers := make([]string, 0, len(overlay.Nameservers))
	seenNameservers := map[string]struct{}{}
	for _, nameserver := range overlay.Nameservers {
		nameserver = strings.TrimSpace(nameserver)
		if nameserver == "" {
			continue
		}
		if _, ok := seenNameservers[nameserver]; ok {
			continue
		}
		seenNameservers[nameserver] = struct{}{}
		nameservers = append(nameservers, nameserver)
	}

	if len(domains) == 0 || len(nameservers) == 0 {
		return nil
	}

	routeExcludes := make([]string, 0, len(overlay.RouteExcludes))
	seenRouteExcludes := map[string]struct{}{}
	for _, route := range overlay.RouteExcludes {
		route = strings.TrimSpace(route)
		if route == "" {
			continue
		}
		if _, ok := seenRouteExcludes[route]; ok {
			continue
		}
		seenRouteExcludes[route] = struct{}{}
		routeExcludes = append(routeExcludes, route)
	}

	return &OverlayDNS{
		Domains:       domains,
		Nameservers:   nameservers,
		RouteExcludes: routeExcludes,
	}
}

func upstreamRouteExcludeCIDRs(profile model.Profile) []string {
	host := strings.TrimSpace(profile.Host)
	if host == "" {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return []string{netip.PrefixFrom(addr, bits).String()}
}

func upstreamHostNeedsDirectDNS(profile model.Profile) bool {
	host := strings.TrimSpace(profile.Host)
	if host == "" {
		return false
	}
	_, err := netip.ParseAddr(host)
	return err != nil
}

func baseRouteRules(cfg config.ProjectConfig, mode string) []any {
	rules := []any{
		map[string]any{
			"ip_is_private": true,
			"action":        "route",
			"outbound":      "direct",
		},
	}
	if cfg.SniffEnabled() {
		rules = append([]any{buildSniffRule(cfg)}, rules...)
	}
	if mode == config.RenderModeTun {
		rules = append([]any{
			map[string]any{
				"protocol": "dns",
				"action":   "hijack-dns",
			},
		}, rules...)
	}
	return rules
}

func buildSniffRule(cfg config.ProjectConfig) map[string]any {
	rule := map[string]any{
		"action": "sniff",
	}
	if sniffers := cfg.NormalizedSniffers(); len(sniffers) > 0 {
		rule["sniffer"] = sniffers
	}
	if timeout := cfg.SniffTimeout(); timeout != "" {
		rule["timeout"] = timeout
	}
	return rule
}

func buildInbounds(cfg config.ProjectConfig, overlayDNS *OverlayDNS, upstreamRouteExcludes []string) ([]any, error) {
	if cfg.NetworkMode() != config.RenderModeTun {
		return nil, fmt.Errorf("unsupported render mode %q", cfg.NetworkMode())
	}

	inbound := map[string]any{
		"type":           "tun",
		"tag":            "tun-in",
		"interface_name": cfg.TunInterfaceName(),
		"address":        cfg.TunAddresses(),
		"auto_route":     true,
		"strict_route":   true,
		"mtu":            1400,
	}
	routeExcludes := append([]string(nil), upstreamRouteExcludes...)
	if overlayDNS != nil && len(overlayDNS.RouteExcludes) > 0 {
		routeExcludes = append(routeExcludes, overlayDNS.RouteExcludes...)
	}
	if len(routeExcludes) > 0 {
		inbound["route_exclude_address"] = normalizeRouteExcludes(routeExcludes)
	}
	return []any{inbound}, nil
}

func normalizeRouteExcludes(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildVLESSOutbound(cfg config.ProjectConfig, profile model.Profile) (map[string]any, error) {
	transport, err := buildTransport(profile)
	if err != nil {
		return nil, err
	}

	proxyOutbound := map[string]any{
		"type":        "vless",
		"tag":         "proxy",
		"server":      profile.Host,
		"server_port": profile.Port,
		"uuid":        profile.UUID,
	}
	if profile.Flow != "" {
		proxyOutbound["flow"] = profile.Flow
	}
	if tlsConfig := buildTLS(cfg, profile); tlsConfig != nil {
		proxyOutbound["tls"] = tlsConfig
	}
	if transport != nil {
		proxyOutbound["transport"] = transport
	}
	if upstreamHostNeedsDirectDNS(profile) {
		proxyOutbound["domain_resolver"] = "dns-direct"
	}
	return proxyOutbound, nil
}

func processNameDirectRules(processNames []string) []any {
	processNames = configNormalStrings(processNames)
	if len(processNames) == 0 {
		return nil
	}
	return []any{
		map[string]any{
			"process_name": processNames,
			"action":       "route",
			"outbound":     "direct",
		},
	}
}

func configNormalStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func buildTransport(profile model.Profile) (map[string]any, error) {
	switch profile.Network {
	case "", "tcp":
		return nil, nil
	case "grpc":
		transport := map[string]any{
			"type": "grpc",
		}
		if profile.ServiceName != "" {
			transport["service_name"] = profile.ServiceName
		}
		return transport, nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", profile.Network)
	}
}

func buildTLS(cfg config.ProjectConfig, profile model.Profile) map[string]any {
	switch profile.Security {
	case "", "none":
		return nil
	case "tls":
		tlsConfig := map[string]any{
			"enabled": true,
		}
		if profile.SNI != "" {
			tlsConfig["server_name"] = profile.SNI
		}
		if profile.Fingerprint != "" {
			tlsConfig["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": profile.Fingerprint,
			}
		}
		applyTLSClientOptions(cfg, tlsConfig)
		return tlsConfig
	case "reality":
		tlsConfig := map[string]any{
			"enabled": true,
			"reality": map[string]any{
				"enabled":    true,
				"public_key": profile.PublicKey,
			},
		}
		if profile.SNI != "" {
			tlsConfig["server_name"] = profile.SNI
		}
		if profile.Fingerprint != "" {
			tlsConfig["utls"] = map[string]any{
				"enabled":     true,
				"fingerprint": profile.Fingerprint,
			}
		}
		if profile.ShortID != "" {
			reality := tlsConfig["reality"].(map[string]any)
			reality["short_id"] = profile.ShortID
		}
		applyTLSClientOptions(cfg, tlsConfig)
		return tlsConfig
	default:
		tlsConfig := map[string]any{
			"enabled": true,
		}
		applyTLSClientOptions(cfg, tlsConfig)
		return tlsConfig
	}
}

func applyTLSClientOptions(cfg config.ProjectConfig, tlsConfig map[string]any) {
	options := cfg.TLSOptions()
	if options.Fragment != nil {
		tlsConfig["fragment"] = *options.Fragment
	}
	if options.FragmentFallbackDelay != "" {
		tlsConfig["fragment_fallback_delay"] = options.FragmentFallbackDelay
	}
	if options.RecordFragment != nil {
		tlsConfig["record_fragment"] = *options.RecordFragment
	}
	if curvePreferences := cfg.NormalizedCurvePreferences(); len(curvePreferences) > 0 {
		tlsConfig["curve_preferences"] = curvePreferences
	}
}
