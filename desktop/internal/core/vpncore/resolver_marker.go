package vpncore

import "strings"

// IsOpenConnectResolverMarker reports whether a resolver's first line marks it as owned by openconnect-tun.
func IsOpenConnectResolverMarker(firstLine string) bool {
	return strings.HasPrefix(firstLine, "# Added by openconnect-tun DNS shim") ||
		strings.HasPrefix(firstLine, "# Added by openconnect-tun public bypass")
}
