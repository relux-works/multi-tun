package vpncore

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

type NetRouteRequest struct {
	Op        string `json:"op"`
	CIDR      string `json:"cidr"`
	Interface string `json:"interface,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
}

var runNetRouteVPNCore = func(args []string) ([]byte, error) {
	return runTypedCommand("/sbin/route", args, "")
}

func netRouteArgs(req NetRouteRequest) ([]string, error) {
	switch req.Op {
	case "add", "delete", "change":
	default:
		return nil, errors.New("unsupported net.route operation")
	}
	prefix, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		addr, addrErr := netip.ParseAddr(req.CIDR)
		if addrErr != nil || addr.Zone() != "" {
			return nil, errors.New("route CIDR must be an IP address or prefix")
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	prefix = prefix.Masked()
	if req.Interface != "" && !interfacePatternVPNCore.MatchString(req.Interface) {
		return nil, errors.New("invalid route interface")
	}
	if req.Interface != "" && req.Gateway != "" || req.Op != "delete" && req.Interface == "" && req.Gateway == "" {
		return nil, errors.New("route needs exactly one interface or gateway (delete permits neither)")
	}
	if req.Gateway != "" {
		gateway, err := netip.ParseAddr(req.Gateway)
		if err != nil || gateway.Zone() != "" || gateway.Is4() != prefix.Addr().Is4() {
			return nil, errors.New("route gateway must match the CIDR address family")
		}
		req.Gateway = gateway.String()
	}
	family := "-net"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	args := []string{"-n", req.Op, family, prefix.String()}
	if req.Interface != "" {
		args = append(args, "-interface", req.Interface)
	}
	if req.Gateway != "" {
		args = append(args, req.Gateway)
	}
	return args, nil
}

func (d *serviceDaemon) handleNetRoute(req NetRouteRequest) error {
	args, err := netRouteArgs(req)
	if err != nil {
		return err
	}
	output, err := runNetRouteVPNCore(args)
	if err != nil {
		return fmt.Errorf("route: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}
