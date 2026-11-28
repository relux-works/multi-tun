package awg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func syntheticConfig() RuntimeConfig {
	key := func(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }
	return RuntimeConfig{Listen: "127.0.0.1:20809", Addresses: []string{"192.0.2.2/32"}, Endpoint: "127.0.0.1:51820", PrivateKey: key(1), PublicKey: key(2), PresharedKey: key(3)}
}

// This exercises the real v3 parser and userspace netstack with synthetic keys.
// It proves UAPI compatibility, not live peer connectivity or OS integration.
func TestBuildUAPIRealDevice(t *testing.T) {
	c := syntheticConfig()
	c.Jc, c.Jmin, c.Jmax = 6, 10, 80
	c.S1, c.S2, c.S3, c.S4 = 475, 986, 979, 12
	c.H1, c.H2, c.H3, c.H4 = "1", "2", "3", "4"
	c.I1 = "<b 0x524547>"
	c.I2, c.I3, c.I4, c.I5 = "<b 0x01>", "<b 0x02>", "<b 0x03>", "<b 0x04>"
	c.HeaderProtectionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32))
	c.ContentPaddingAddition = "10-100"
	c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime = "100-120", "3-8", "150-180"
	c.KeepaliveTimeout, c.MaxHandshakeAttempts, c.PersistentKeepalive = "7-13", "15-20", "25-35"
	c.RandomTrailers, c.DisableCookies = "true", "false"
	uapi, err := BuildUAPI(c, c.Endpoint)
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range []string{
		"jc=6", "jmin=10", "jmax=80", "s1=475", "s2=986", "s3=979", "s4=12",
		"h1=1", "h2=2", "h3=3", "h4=4", "i1=<b 0x524547>",
		"i2=<b 0x01>", "i3=<b 0x02>", "i4=<b 0x03>", "i5=<b 0x04>",
		"content_padding_addition=10-100", "rekey_after_time=100-120", "rekey_timeout=3-8",
		"reject_after_time=150-180", "keepalive_timeout=7-13", "max_handshake_attempts=15-20",
		"persistent_keepalive_interval=25-35", "random_trailers=true", "disable_cookies=false",
		"endpoint=127.0.0.1:51820", "allowed_ip=0.0.0.0/0",
	} {
		if !strings.Contains(uapi, line+"\n") {
			t.Errorf("missing expected UAPI line %s", line)
		}
	}

	for _, pair := range [][2]string{{"private_key", c.PrivateKey}, {"public_key", c.PublicKey}, {"preshared_key", c.PresharedKey}, {"header_protection_key", c.HeaderProtectionKey}} {
		b, _ := base64.StdEncoding.DecodeString(pair[1])
		if !strings.Contains(uapi, pair[0]+"="+hex.EncodeToString(b)+"\n") {
			t.Errorf("incorrect conversion of %s", pair[0])
		}
	}
	if !strings.Contains(uapi, "allowed_ip=0.0.0.0/0\n") {
		t.Fatal("missing default allowed IP")
	}
	tun, _, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil, DefaultMTU)
	if err != nil {
		t.Fatal(err)
	}
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	dev := device.NewDevice(tun, offlineBind{conn.NewDefaultBind()}, logger)
	defer dev.Close()
	if err := dev.IpcSet(uapi); err != nil {
		t.Fatalf("real v3 IpcSet rejected configuration: %v", err)
	}
	c.AllowedIPs = []string{"192.0.2.7/24", "2001:db8::/32"}
	uapi, err = BuildUAPI(c, "[::1]:51820")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(uapi, "allowed_ip=192.0.2.0/24\n") || !strings.Contains(uapi, "allowed_ip=2001:db8::/32\n") {
		t.Fatal("custom allowed IPs missing")
	}
}

func TestRuntimeConfigRefusalsAndRedaction(t *testing.T) {
	for name, change := range map[string]func(*RuntimeConfig){
		"wildcard":            func(c *RuntimeConfig) { c.Listen = "0.0.0.0:20809" },
		"LAN":                 func(c *RuntimeConfig) { c.Listen = "192.168.1.1:20809" },
		"IPv6 wildcard":       func(c *RuntimeConfig) { c.Listen = "[::]:20809" },
		"hostname listen":     func(c *RuntimeConfig) { c.Listen = "localhost:20809" },
		"zero listen port":    func(c *RuntimeConfig) { c.Listen = "127.0.0.1:0" },
		"high listen port":    func(c *RuntimeConfig) { c.Listen = "127.0.0.1:65536" },
		"private key":         func(c *RuntimeConfig) { c.PrivateKey = "synthetic-secret-invalid" },
		"public key":          func(c *RuntimeConfig) { c.PublicKey = "synthetic-secret-invalid" },
		"preshared key":       func(c *RuntimeConfig) { c.PresharedKey = "synthetic-secret-invalid" },
		"header key":          func(c *RuntimeConfig) { c.HeaderProtectionKey = "synthetic-secret-invalid" },
		"short key":           func(c *RuntimeConfig) { c.PrivateKey = base64.StdEncoding.EncodeToString([]byte("short")) },
		"no endpoint port":    func(c *RuntimeConfig) { c.Endpoint = "localhost" },
		"zero endpoint port":  func(c *RuntimeConfig) { c.Endpoint = "localhost:0" },
		"high endpoint port":  func(c *RuntimeConfig) { c.Endpoint = "localhost:65536" },
		"bad endpoint host":   func(c *RuntimeConfig) { c.Endpoint = "bad host:51820" },
		"no addresses":        func(c *RuntimeConfig) { c.Addresses = nil },
		"bad address":         func(c *RuntimeConfig) { c.Addresses = []string{"invalid"} },
		"bad DNS":             func(c *RuntimeConfig) { c.DNS = []string{"invalid"} },
		"bad allowed IP":      func(c *RuntimeConfig) { c.AllowedIPs = []string{"192.0.2.1"} },
		"small MTU":           func(c *RuntimeConfig) { c.MTU = 575 },
		"negative parameter":  func(c *RuntimeConfig) { c.S4 = -1 },
		"UAPI injection":      func(c *RuntimeConfig) { c.I1 = "<b 0x01>\nlisten_port=1" },
		"keepalive injection": func(c *RuntimeConfig) { c.PersistentKeepalive = "25\nlisten_port=1" },
	} {
		t.Run(name, func(t *testing.T) {
			c := syntheticConfig()
			change(&c)
			err := ValidateRuntimeConfig(c)
			if err == nil {
				t.Fatal("accepted forbidden configuration")
			}
			for _, key := range []string{c.PrivateKey, c.PublicKey, c.PresharedKey, c.HeaderProtectionKey} {
				if key != "" && strings.Contains(err.Error(), key) {
					t.Fatal("error disclosed key")
				}
			}
			if _, err := BuildUAPI(c, "127.0.0.1:51820"); err == nil {
				t.Fatal("UAPI accepted invalid configuration")
			}
			path := filepath.Join(t.TempDir(), "absent", "config.json")
			if err := WriteRuntimeConfig(path, c); err == nil {
				t.Fatal("writer accepted invalid configuration")
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("invalid config writer created parent directory")
			}
		})
	}
	for _, listen := range []string{"127.0.0.1:1", "[::1]:65535", "127.0.0.2:20809"} {
		c := syntheticConfig()
		c.Listen = listen
		c.Endpoint = "peer.example:51820"
		if err := ValidateRuntimeConfig(c); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildUAPI(syntheticConfig(), "peer.example:51820"); err == nil {
		t.Fatal("unresolved endpoint accepted")
	}
}

func TestRuntimeConfigFile(t *testing.T) {
	cfg := syntheticConfig()
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "runtime.json")
	if err := WriteRuntimeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{path: 0600, dir: 0700} {
		stat, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode().Perm() != want {
			t.Fatalf("mode = %o, want %o", stat.Mode().Perm(), want)
		}
	}
	got, err := ReadRuntimeConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, cfg) {
		t.Fatal("runtime config changed during round-trip")
	}
	// Atomic replacement repairs an existing permissive file without exposing new contents.
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := WriteRuntimeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	stat, _ := os.Stat(path)
	if stat.Mode().Perm() != 0600 {
		t.Fatal("replacement permissions")
	}
	for _, raw := range []string{`{"unknown":"synthetic-secret"}`, `{"private_key":42}`, `{} {}`, `null`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ReadRuntimeConfig(path)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("invalid JSON accepted or disclosed")
		}
	}
}

type loopbackDialer struct {
	mu        sync.Mutex
	calls     []netip.AddrPort
	lookup    []string
	fail4     bool
	udpClosed chan struct{}
}

func (d *loopbackDialer) DialContextTCPAddrPort(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, a)
	d.mu.Unlock()
	if !a.Addr().IsLoopback() {
		return nil, errors.New("test refuses non-loopback dial")
	}
	if d.fail4 && a.Addr().Is4() {
		return nil, errors.New("synthetic IPv4 refusal")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
}
func (d *loopbackDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("unexpected generic dial")
}
func (d *loopbackDialer) DialUDPAddrPort(_, r netip.AddrPort) (net.Conn, error) {
	if !r.Addr().IsLoopback() {
		return nil, errors.New("test refuses non-loopback UDP")
	}
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(r))
	if err != nil {
		return nil, err
	}
	if d.udpClosed != nil {
		return &closeWitnessConn{Conn: conn, closed: d.udpClosed}, nil
	}
	return conn, nil
}
func (d *loopbackDialer) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host != "echo.test" {
		return nil, errors.New("synthetic DNS refusal")
	}
	return d.lookup, nil
}

func startSOCKS(t *testing.T, d TunnelDialer) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeSOCKS5(ctx, ln, d, io.Discard) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("SOCKS server leaked handlers")
		}
	})
	return ln.Addr().String(), cancel, done
}
func socksControl(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var got [2]byte
	if _, err = io.ReadFull(c, got[:]); err != nil {
		t.Fatal(err)
	}
	if got != [2]byte{5, 0} {
		t.Fatalf("unexpected greeting %v", got)
	}
	return c
}
func socksRequest(t *testing.T, c net.Conn, cmd byte, target []byte) socksTarget {
	t.Helper()
	if _, err := c.Write(append([]byte{5, cmd, 0}, target...)); err != nil {
		t.Fatal(err)
	}
	var head [3]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		t.Fatal(err)
	}
	if head != [3]byte{5, 0, 0} {
		t.Fatalf("request refused: %v", head)
	}
	addr, err := readTarget(c)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}
func domainTarget(host string, port uint16) []byte {
	b := append([]byte{3, byte(len(host))}, []byte(host)...)
	return append(b, byte(port>>8), byte(port))
}

func TestSOCKSConnect(t *testing.T) {
	for _, tc := range []struct {
		name, listen  string
		domain, fail4 bool
	}{{"IPv4", "127.0.0.1:0", false, false}, {"domain prefers IPv4", "127.0.0.1:0", true, false}, {"IPv6", "[::1]:0", false, false}, {"domain falls back IPv6", "[::1]:0", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			echo, err := net.Listen("tcp", tc.listen)
			if err != nil {
				if strings.Contains(tc.listen, "::1") {
					t.Skip("IPv6 loopback unavailable")
				}
				t.Fatal(err)
			}
			defer echo.Close()
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				c, err := echo.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
			remote := echo.Addr().(*net.TCPAddr).AddrPort()
			d := &loopbackDialer{lookup: []string{"::1", "127.0.0.1"}, fail4: tc.fail4}
			addr, _, _ := startSOCKS(t, d)
			c := socksControl(t, addr)
			target := encodeAddr(remote)
			if tc.domain {
				target = domainTarget("echo.test", remote.Port())
			}
			socksRequest(t, c, 1, target)
			payload := []byte("loopback payload")
			if _, err = c.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("payload corrupted")
			}
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			var tail [1]byte
			if _, err = c.Read(tail[:]); err != io.EOF {
				t.Fatalf("half-close did not propagate: %v", err)
			}
			_ = c.Close()
			select {
			case <-echoDone:
			case <-time.After(time.Second):
				t.Fatal("echo handler leaked")
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			if tc.domain && (len(d.calls) == 0 || !d.calls[0].Addr().Is4()) {
				t.Fatal("domain did not prefer IPv4")
			}
		})
	}
}

func TestSOCKSUDPAssociate(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		b := make([]byte, 65535)
		for {
			n, source, err := echo.ReadFromUDPAddrPort(b)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDPAddrPort(b[:n], source)
		}
	}()
	closed := make(chan struct{})
	addr, _, _ := startSOCKS(t, &loopbackDialer{lookup: []string{"::1", "127.0.0.1"}, udpClosed: closed})
	control := socksControl(t, addr)
	bound := socksRequest(t, control, 3, encodeAddr(netip.MustParseAddrPort("0.0.0.0:0")))
	relay, err := net.ResolveUDPAddr("udp4", targetString(bound))
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	for _, domain := range []bool{false, true} {
		remote := echo.LocalAddr().(*net.UDPAddr).AddrPort()
		target := encodeAddr(remote)
		if domain {
			target = domainTarget("echo.test", remote.Port())
		}
		frame := append([]byte{0, 0, 0}, target...)
		frame = append(frame, []byte("udp payload")...)
		if _, err = client.Write(frame); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if n < 3 || !bytes.Equal(buf[:3], []byte{0, 0, 0}) {
			t.Fatal("bad UDP frame")
		}
		r := &packetReader{b: buf[3:n]}
		response, err := readTarget(r)
		if err != nil {
			t.Fatal(err)
		}
		if targetString(response) != remote.String() || string(r.b) != "udp payload" {
			t.Fatal("UDP relay corrupted address or payload")
		}
	}
	// Fragmented packets must be dropped, never passed to the tunnel.
	bad := append([]byte{0, 0, 1}, encodeAddr(echo.LocalAddr().(*net.UDPAddr).AddrPort())...)
	bad = append(bad, 'x')
	_, _ = client.Write(bad)
	_ = client.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if _, err = client.Read(make([]byte, 1024)); err == nil {
		t.Fatal("fragmented UDP packet forwarded")
	}
	// Closing TCP must tear down the UDP association even while its socket is idle.
	_ = control.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("TCP control close did not close tunnel UDP flow")
	}
	_ = echo.Close()
	select {
	case <-echoDone:
	case <-time.After(time.Second):
		t.Fatal("UDP echo leaked")
	}
}

func TestSOCKSRefusalsAndCancellation(t *testing.T) {
	addr, cancel, _ := startSOCKS(t, &loopbackDialer{})
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte{5, 1, 2})
	var greeting [2]byte
	if _, err = io.ReadFull(c, greeting[:]); err != nil {
		t.Fatal(err)
	}
	if greeting != [2]byte{5, 255} {
		t.Fatal("unsupported authentication admitted")
	}
	control := socksControl(t, addr)
	_, _ = control.Write(append([]byte{5, 2, 0}, encodeAddr(netip.MustParseAddrPort("127.0.0.1:9"))...))
	var refusal [3]byte
	if _, err = io.ReadFull(control, refusal[:]); err != nil {
		t.Fatal(err)
	}
	if refusal[1] != 7 {
		t.Fatal("unsupported command admitted")
	}
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	cancel()
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancel did not close pending handshake")
	}
}

func TestRunProxyRejectsBeforeDeviceCreation(t *testing.T) {
	c := syntheticConfig()
	c.Listen = "0.0.0.0:20809"
	var logs bytes.Buffer
	if err := RunProxy(context.Background(), c, &logs); err == nil {
		t.Fatal("non-loopback RunProxy admitted")
	}
	if logs.Len() != 0 {
		t.Fatal("invalid configuration produced output")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunProxy(ctx, syntheticConfig(), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
}

// A close witness distinguishes control-connection teardown from parent cancellation.
type closeWitnessConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeWitnessConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type addressOnlyListener struct{ address *net.TCPAddr }

func (l addressOnlyListener) Accept() (net.Conn, error) { return nil, errors.New("unexpected accept") }
func (l addressOnlyListener) Close() error              { return nil }
func (l addressOnlyListener) Addr() net.Addr            { return l.address }
func TestSOCKSRefusesNonLoopbackListener(t *testing.T) {
	// No socket is created: even validation controls remain offline/loopback only.
	ln := addressOnlyListener{&net.TCPAddr{IP: net.IPv4zero, Port: 20809}}
	err := ServeSOCKS5(context.Background(), ln, &loopbackDialer{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatal("wildcard listener not explicitly refused")
	}
}

type cancelDialer struct {
	loopbackDialer
	started  chan struct{}
	finished chan struct{}
}

func (d *cancelDialer) DialContextTCPAddrPort(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	close(d.finished)
	return nil, ctx.Err()
}
func TestSOCKSCancelsPendingTunnelDial(t *testing.T) {
	d := &cancelDialer{started: make(chan struct{}), finished: make(chan struct{})}
	addr, cancel, _ := startSOCKS(t, d)
	c := socksControl(t, addr)
	_, err := c.Write(append([]byte{5, 1, 0}, encodeAddr(netip.MustParseAddrPort("127.0.0.1:9"))...))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.started:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	cancel()
	select {
	case <-d.finished:
	case <-time.After(time.Second):
		t.Fatal("tunnel dial ignored cancellation")
	}
}

func TestBuildUAPIRejectsResolvedEndpointInjection(t *testing.T) {
	for _, endpoint := range []string{"[fe80::1%zone\nlisten_port=1]:51820", "[fe80::1%zone\r]:51820", "127.0.0.1:0"} {
		if _, err := BuildUAPI(syntheticConfig(), endpoint); err == nil {
			t.Fatal("malformed resolved endpoint admitted")
		}
	}
}

// Keep the real endpoint parser but suppress transport sockets entirely, including
// the automatic EventUp emitted by CreateNetTUN. IpcSet still uses the real device.
type offlineBind struct{ conn.Bind }

func (offlineBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, port, nil }
func (offlineBind) Close() error                                         { return nil }
func (offlineBind) SetMark(uint32) error                                 { return nil }
func (offlineBind) Send([][]byte, conn.Endpoint) error                   { return nil }
