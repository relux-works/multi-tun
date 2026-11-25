package cli

import (
	"context"
	"errors"
	"net/netip"

	"multi-tun/desktop/internal/core/vpncore"
)

// errHostFailClosedCall marks a test that reached a fail-closed host call without installing its
// own fake. Tests in this package must never reach the live vpn-core helper or the real resolver.
var errHostFailClosedCall = errors.New("test reached a host fail-closed call without a fake")

func init() {
	failClosedApplyCLI = func(vpncore.ServiceConfig, []string, []string) error { return errHostFailClosedCall }
	failClosedClearCLI = func(vpncore.ServiceConfig) error { return errHostFailClosedCall }
	failClosedStatusCLI = func(vpncore.ServiceConfig) (vpncore.FailClosedStatus, error) {
		return vpncore.FailClosedStatus{}, errHostFailClosedCall
	}
	failClosedLookupCLI = func(context.Context, string) ([]netip.Addr, error) { return nil, errHostFailClosedCall }
	failClosedInterfacesCLI = func() ([]ifaceInfo, error) { return nil, errHostFailClosedCall }
}
