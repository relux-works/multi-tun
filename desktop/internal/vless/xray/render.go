package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
)

func Render(cfg config.ProjectConfig, profile model.Profile) ([]byte, error) {
	streamSettings, err := buildStreamSettings(profile)
	if err != nil {
		return nil, err
	}

	user := map[string]any{
		"id":         profile.UUID,
		"encryption": firstNonEmpty(profile.Encryption, "none"),
	}
	if profile.Flow != "" {
		user["flow"] = profile.Flow
	}

	outbound := map[string]any{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": profile.Host,
					"port":    profile.Port,
					"users":   []any{user},
				},
			},
		},
	}
	if streamSettings != nil {
		outbound["streamSettings"] = streamSettings
	}

	root := map[string]any{
		"log": map[string]any{
			"loglevel": xrayLogLevel(cfg.LogLevel()),
		},
		"inbounds": []any{
			map[string]any{
				"tag":      "socks-in",
				"listen":   cfg.XraySocksListen(),
				"port":     cfg.XraySocksPort(),
				"protocol": "socks",
				"settings": map[string]any{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": []any{
			outbound,
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
			},
			map[string]any{
				"tag":      "block",
				"protocol": "blackhole",
			},
		},
	}

	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func buildStreamSettings(profile model.Profile) (map[string]any, error) {
	network, err := buildNetworkSettings(profile)
	if err != nil {
		return nil, err
	}

	streamSettings := map[string]any{
		"network": firstNonEmpty(profile.Network, "tcp"),
	}
	if network != nil {
		for key, value := range network {
			streamSettings[key] = value
		}
	}

	switch profile.Security {
	case "", "none":
	case "tls":
		streamSettings["security"] = "tls"
		tlsSettings := map[string]any{}
		if profile.SNI != "" {
			tlsSettings["serverName"] = profile.SNI
		}
		if profile.Fingerprint != "" {
			tlsSettings["fingerprint"] = profile.Fingerprint
		}
		streamSettings["tlsSettings"] = tlsSettings
	case "reality":
		streamSettings["security"] = "reality"
		realitySettings := map[string]any{}
		if profile.SNI != "" {
			realitySettings["serverName"] = profile.SNI
		}
		if profile.Fingerprint != "" {
			realitySettings["fingerprint"] = profile.Fingerprint
		}
		if profile.PublicKey != "" {
			realitySettings["publicKey"] = profile.PublicKey
		}
		if profile.ShortID != "" {
			realitySettings["shortId"] = profile.ShortID
		}
		if profile.SpiderX != "" {
			realitySettings["spiderX"] = profile.SpiderX
		}
		streamSettings["realitySettings"] = realitySettings
	default:
		return nil, fmt.Errorf("unsupported security type %q", profile.Security)
	}

	return streamSettings, nil
}

func buildNetworkSettings(profile model.Profile) (map[string]any, error) {
	switch profile.Network {
	case "", "tcp":
		return nil, nil
	case "grpc":
		grpcSettings := map[string]any{}
		if profile.ServiceName != "" {
			grpcSettings["serviceName"] = profile.ServiceName
		}
		return map[string]any{"grpcSettings": grpcSettings}, nil
	default:
		return nil, fmt.Errorf("unsupported network type %q", profile.Network)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func xrayLogLevel(value string) string {
	switch value {
	case "":
		return "warning"
	case "warn":
		return "warning"
	default:
		return value
	}
}
