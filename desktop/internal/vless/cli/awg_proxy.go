package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/awg"
	"multi-tun/desktop/internal/vless/config"
)

var awgSidecarExecutableFunc = defaultAWGSidecarExecutable
var runAWGProxyFunc = awg.RunProxy

func defaultAWGSidecarExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(path)
}

func (a *App) runAWGProxy(args []string) int {
	fs := flag.NewFlagSet("_awg-proxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("c", "", "Runtime configuration path")
	if err := fs.Parse(args); err != nil || *configPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, "AWG proxy requires -c <path>")
		return 2
	}
	cfg, err := awg.ReadRuntimeConfig(*configPath)
	if err != nil {
		fmt.Fprintln(a.stderr, "AWG proxy configuration refused")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := runAWGProxyFunc(ctx, cfg, a.stderr); err != nil {
		// Runtime and parser errors can contain supplied keys or paths.
		fmt.Fprintln(a.stderr, "AWG proxy failed")
		return 1
	}
	return 0
}

func buildAWGRuntimeConfig(cfg config.ProjectConfig, c *amnezia.AWGConfig) (awg.RuntimeConfig, error) {
	if c == nil {
		return awg.RuntimeConfig{}, amnezia.NewRefusal(amnezia.CodeKeyInvalid, "missing AmneziaWG configuration")
	}
	mtu := c.MTU
	if mtu <= 0 {
		mtu = cfg.AWGMTU()
	}
	keepalive := c.PersistentKeepaliveRaw
	if keepalive == "" && c.PersistentKeepalive > 0 {
		keepalive = strconv.Itoa(c.PersistentKeepalive)
	}
	runtime := awg.RuntimeConfig{
		Listen: net.JoinHostPort(cfg.AWGSocksListen(), strconv.Itoa(cfg.AWGSocksPort())),
		MTU:    mtu, Endpoint: net.JoinHostPort(c.EndpointHost, strconv.Itoa(c.EndpointPort)),
		Addresses: append([]string(nil), c.Address...), DNS: append([]string(nil), c.DNS...),
		PrivateKey: c.PrivateKey, PublicKey: c.PublicKey, PresharedKey: c.PresharedKey,
		AllowedIPs: append([]string(nil), c.AllowedIPs...), PersistentKeepalive: keepalive,
		Jc: c.Jc, Jmin: c.Jmin, Jmax: c.Jmax, S1: c.S1, S2: c.S2, S3: c.S3, S4: c.S4,
		H1: c.H1, H2: c.H2, H3: c.H3, H4: c.H4,
		I1: c.I1, I2: c.I2, I3: c.I3, I4: c.I4, I5: c.I5,
		HeaderProtectionKey: c.HeaderProtectionKey, ContentPaddingAddition: c.ContentPaddingAddition,
		RekeyAfterTime: c.RekeyAfterTime, RekeyTimeout: c.RekeyTimeout, RejectAfterTime: c.RejectAfterTime,
		KeepaliveTimeout: c.KeepaliveTimeout, MaxHandshakeAttempts: c.MaxHandshakeAttempts,
		RandomTrailers: c.RandomTrailers, DisableCookies: c.DisableCookies,
	}
	if err := awg.ValidateRuntimeConfig(runtime); err != nil {
		return awg.RuntimeConfig{}, amnezia.NewRefusal(amnezia.CodeKeyInvalid, "invalid AmneziaWG runtime configuration")
	}
	return runtime, nil
}
