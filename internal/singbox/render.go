package singbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vpn-config/internal/config"
	"vpn-config/internal/model"
)

func Render(cfg config.ProjectConfig, profile model.Profile) ([]byte, error) {
	transport, err := buildTransport(profile)
	if err != nil {
		return nil, err
	}
	mode := cfg.Render.ModeOrDefault()
	bypassSuffixes := cfg.Render.NormalizedBypassSuffixes()
	bypassExcludes := cfg.Render.NormalizedBypassExcludes()

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
	useDirectDNSBypass := useBypassRules && mode == config.RenderModeTun

	dnsServers := []any{
		map[string]any{
			"type":   "local",
			"tag":    "dns-direct",
			"detour": "direct",
		},
		map[string]any{
			"type":        "tls",
			"tag":         "dns-proxy",
			"server":      cfg.Render.ProxyDNS.Address,
			"server_port": cfg.Render.ProxyDNS.Port,
			"detour":      "proxy",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": cfg.Render.ProxyDNS.TLSServerName,
			},
		},
	}
	dnsRules := []any{
		map[string]any{
			"action": "route",
			"server": "dns-proxy",
		},
	}
	routeRuleSet := []any{}
	routeRules := baseRouteRules(mode)

	if useDirectDNSBypass {
		if useBypassExcludes {
			dnsRules = append([]any{
				map[string]any{
					"rule_set": []string{"proxy-exceptions"},
					"action":   "route",
					"server":   "dns-proxy",
				},
			}, dnsRules...)
		}
		dnsRules = append([]any{
			map[string]any{
				"rule_set": []string{"ru-direct"},
				"action":   "route",
				"server":   "dns-direct",
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

	inbounds, err := buildInbounds(cfg.Render)
	if err != nil {
		return nil, err
	}

	root := map[string]any{
		"log": map[string]any{
			"level": cfg.Render.LogLevel,
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
				"domain_resolver": "dns-direct",
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

func buildInbounds(cfg config.RenderConfig) ([]any, error) {
	switch cfg.ModeOrDefault() {
	case config.RenderModeTun:
		return []any{
			map[string]any{
				"type":           "tun",
				"tag":            "tun-in",
				"interface_name": cfg.InterfaceName,
				"address":        cfg.TunAddresses,
				"auto_route":     true,
				"strict_route":   true,
				"mtu":            1400,
			},
		}, nil
	case config.RenderModeSystemProxy:
		return []any{
			map[string]any{
				"type":             "mixed",
				"tag":              "mixed-in",
				"listen":           cfg.ProxyListenAddress,
				"listen_port":      cfg.ProxyListenPort,
				"set_system_proxy": true,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported render mode %q", cfg.ModeOrDefault())
	}
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
