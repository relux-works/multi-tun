package cli

import (
	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/singbox"
)

func resolveRenderOptions(mode string) singbox.RenderOptions {
	if mode != config.RenderModeTun {
		return singbox.RenderOptions{}
	}

	overlay, err := openconnect.ActiveOverlayDNS("")
	if err != nil || overlay == nil {
		return singbox.RenderOptions{}
	}

	return singbox.RenderOptions{
		OverlayDNS: &singbox.OverlayDNS{
			Domains:       append([]string(nil), overlay.Domains...),
			Nameservers:   append([]string(nil), overlay.Nameservers...),
			RouteExcludes: append([]string(nil), overlay.RouteExcludes...),
		},
	}
}
