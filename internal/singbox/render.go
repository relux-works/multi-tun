package singbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"multi-tun/internal/config"
	"multi-tun/internal/model"
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
	transport, err := buildTransport(profile)
	if err != nil {
		return nil, err
	}
	mode := cfg.NetworkMode()
	bypassSuffixes := cfg.NormalizedBypassSuffixes()
	bypassExcludes := cfg.NormalizedBypassExcludes()
	overlayDNS := normalizeOverlayDNS(options.OverlayDNS)
	useOverlayDNS := mode == config.RenderModeTun && overlayDNS != nil
	proxyResolver := cfg.ProxyResolver()

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
	if tlsConfig := buildTLS(profile); tlsConfig != nil {
		proxyOutbound["tls"] = tlsConfig
	}
	if transport != nil {
		proxyOutbound["transport"] = transport
	}

	useBypassRules := len(bypassSuffixes) > 0
	useBypassExcludes := len(bypassExcludes) > 0
	useBypassDNSRules := mode == config.RenderModeTun && useBypassRules
	useBypassExcludeDNSRules := mode == config.RenderModeTun && useBypassExcludes
	directDomainResolver := "dns-direct"
	if useOverlayDNS {
		directDomainResolver = "dns-proxy"
	}

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
	if !useOverlayDNS || useBypassDNSRules {
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
	routeRules := baseRouteRules(mode)

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

	inbounds, err := buildInbounds(cfg, overlayDNS)
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

func baseRouteRules(mode string) []any {
	rules := []any{
		map[string]any{
			"action": "sniff",
		},
		map[string]any{
			"ip_is_private": true,
			"action":        "route",
			"outbound":      "direct",
		},
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

func buildInbounds(cfg config.ProjectConfig, overlayDNS *OverlayDNS) ([]any, error) {
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
	if overlayDNS != nil && len(overlayDNS.RouteExcludes) > 0 {
		inbound["route_exclude_address"] = overlayDNS.RouteExcludes
	}
	return []any{inbound}, nil
}

func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
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

func buildTLS(profile model.Profile) map[string]any {
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
		return tlsConfig
	default:
		return map[string]any{
			"enabled": true,
		}
	}
}
