package awg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// RunProxy creates only an in-process netstack; it never creates an OS TUN.
func RunProxy(ctx context.Context, cfg RuntimeConfig, logOut io.Writer) error {
	if err := ValidateRuntimeConfig(cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	local := make([]netip.Addr, 0, len(cfg.Addresses))
	for _, value := range cfg.Addresses {
		addr, _ := parseAddress(value)
		local = append(local, addr)
	}
	dns := make([]netip.Addr, 0, len(cfg.DNS))
	for _, value := range cfg.DNS {
		addr, _ := netip.ParseAddr(value)
		dns = append(dns, addr)
	}
	if len(dns) == 0 {
		dns = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	host, port, _ := splitEndpoint(cfg.Endpoint)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		resolveCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(resolveCtx, "ip", host)
		if err != nil || len(ips) == 0 {
			return errors.New("resolve AWG endpoint failed")
		}
		ip = ips[0]
		for _, candidate := range ips {
			if candidate.Unmap().Is4() {
				ip = candidate.Unmap()
				break
			}
		}
	}
	uapi, err := BuildUAPI(cfg, net.JoinHostPort(ip.String(), port))
	if err != nil {
		return err
	}
	tunDev, tnet, err := netstack.CreateNetTUN(local, dns, mtu)
	if err != nil {
		return errors.New("create AWG userspace netstack failed")
	}
	logger := device.NewLogger(device.LogLevelError, "awg-proxy: ")
	var logMu sync.Mutex
	if logOut == nil {
		logOut = io.Discard
	}
	// Error level only, with upstream details suppressed because UAPI errors may contain key material.
	logger.Errorf = func(string, ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		_, _ = fmt.Fprintln(logOut, "awg-proxy device error")
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	// Device.Close owns and closes tunDev; netstack's Close is not idempotent.
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		return errors.New("configure AWG device failed")
	}
	if err := dev.Up(); err != nil {
		return errors.New("start AWG device failed")
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("bind AWG loopback listener failed")
	}
	defer ln.Close()
	logMu.Lock()
	_, _ = fmt.Fprintf(logOut, "awg-proxy listening on %s endpoint=%s mtu=%d\n", ln.Addr(), cfg.Endpoint, mtu)
	logMu.Unlock()
	return ServeSOCKS5(ctx, ln, netstackAdapter{tnet}, logOut)
}

type netstackAdapter struct{ *netstack.Net }

func (n netstackAdapter) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return n.Net.DialContextTCPAddrPort(ctx, addr)
}
func (n netstackAdapter) DialUDPAddrPort(local, remote netip.AddrPort) (net.Conn, error) {
	return n.Net.DialUDPAddrPort(local, remote)
}
