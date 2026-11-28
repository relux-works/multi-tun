package awg

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type TunnelDialer interface {
	DialContextTCPAddrPort(context.Context, netip.AddrPort) (net.Conn, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	DialUDPAddrPort(netip.AddrPort, netip.AddrPort) (net.Conn, error)
	LookupContextHost(context.Context, string) ([]string, error)
}

const handshakeTimeout = 10 * time.Second

// ServeSOCKS5 owns ln and waits for all accepted connections on shutdown.
// Protocol errors are deliberately not logged: client input may contain secrets.
func ServeSOCKS5(ctx context.Context, ln net.Listener, dialer TunnelDialer, logOut io.Writer) error {
	if !isLoopbackAddr(ln.Addr()) {
		return errors.New("SOCKS5 listener must bind a loopback IP")
	}
	if dialer == nil {
		return errors.New("SOCKS5 tunnel dialer is required")
	}
	serveCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	stop := context.AfterFunc(serveCtx, func() { _ = ln.Close() })
	defer func() { cancel(); _ = ln.Close(); stop(); wg.Wait() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !isLoopbackAddr(c.RemoteAddr()) {
			_ = c.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			stop := context.AfterFunc(serveCtx, func() { _ = c.Close() })
			defer stop()
			serveClient(serveCtx, c, dialer)
		}()
	}
}

func isLoopbackAddr(a net.Addr) bool {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

type socksTarget struct {
	host string
	port uint16
}

func readTarget(r io.Reader) (socksTarget, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return socksTarget{}, err
	}
	var host string
	switch typ[0] {
	case 1, 4:
		n := 4
		if typ[0] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return socksTarget{}, err
		}
		addr, _ := netip.AddrFromSlice(b)
		host = addr.String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return socksTarget{}, err
		}
		if n[0] == 0 {
			return socksTarget{}, errors.New("empty domain")
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return socksTarget{}, err
		}
		host = string(b)
	default:
		return socksTarget{}, errors.New("unsupported address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return socksTarget{}, err
	}
	return socksTarget{host, binary.BigEndian.Uint16(port[:])}, nil
}

func encodeAddr(a netip.AddrPort) []byte {
	ip := a.Addr().Unmap()
	typ := byte(4)
	if ip.Is4() {
		typ = 1
	}
	b := append([]byte{typ}, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}

func reply(c net.Conn, code byte, addr netip.AddrPort) error {
	if !addr.IsValid() {
		addr = netip.MustParseAddrPort("0.0.0.0:0")
	}
	_, err := c.Write(append([]byte{5, code, 0}, encodeAddr(addr)...))
	return err
}

func targetAddresses(ctx context.Context, d TunnelDialer, target socksTarget) ([]netip.AddrPort, error) {
	if ip, err := netip.ParseAddr(target.host); err == nil {
		return []netip.AddrPort{netip.AddrPortFrom(ip.Unmap(), target.port)}, nil
	}
	hosts, err := d.LookupContextHost(ctx, target.host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.AddrPort
	for _, host := range hosts {
		if ip, err := netip.ParseAddr(host); err == nil {
			addr := netip.AddrPortFrom(ip.Unmap(), target.port)
			if ip.Unmap().Is4() {
				v4 = append(v4, addr)
			} else {
				v6 = append(v6, addr)
			}
		}
	}
	if len(v4)+len(v6) == 0 {
		return nil, errors.New("no tunnel DNS addresses")
	}
	return append(v4, v6...), nil
}

func serveClient(ctx context.Context, c net.Conn, d TunnelDialer) {
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	var hello [2]byte
	if _, err := io.ReadFull(c, hello[:]); err != nil || hello[0] != 5 || hello[1] == 0 {
		return
	}
	methods := make([]byte, int(hello[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	supported := false
	for _, m := range methods {
		supported = supported || m == 0
	}
	method := byte(255)
	if supported {
		method = 0
	}
	if _, err := c.Write([]byte{5, method}); err != nil || !supported {
		return
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	target, err := readTarget(c)
	if err != nil {
		_ = reply(c, 8, netip.AddrPort{})
		return
	}
	switch req[1] {
	case 1:
		if target.port == 0 {
			_ = reply(c, 1, netip.AddrPort{})
			return
		}
		dialCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		addresses, err := targetAddresses(dialCtx, d, target)
		var upstream net.Conn
		if err == nil {
			for index, addr := range addresses {
				// Reserve time for later addresses when an earlier route stalls,
				// while giving each attempt enough headroom for a cold AWG handshake.
				deadline, _ := dialCtx.Deadline()
				remaining := time.Until(deadline)
				if remaining <= 0 {
					err = context.DeadlineExceeded
					break
				}
				budget := remaining / time.Duration(len(addresses)-index)
				if minBudget := 3 * time.Second; budget < minBudget && remaining > minBudget {
					budget = minBudget
				}
				attemptCtx, attemptCancel := context.WithTimeout(dialCtx, budget)
				upstream, err = d.DialContextTCPAddrPort(attemptCtx, addr)
				attemptCancel()
				if err == nil {
					break
				}
			}
		}
		cancel()
		if err != nil || upstream == nil {
			_ = reply(c, 5, netip.AddrPort{})
			return
		}
		defer upstream.Close()
		stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
		defer stop()
		if err := reply(c, 0, netip.AddrPort{}); err != nil {
			return
		}
		_ = c.SetDeadline(time.Time{})
		relayTCP(c, upstream)
	case 3:
		serveUDP(ctx, c, d, target)
	default:
		_ = reply(c, 7, netip.AddrPort{})
	}
}

func relayTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			_ = half.CloseWrite()
		} else {
			_ = dst.Close()
		}
		// Bound the remaining half after EOF, while allowing a response to drain.
		_ = dst.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	wg.Add(2)
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
}

func serveUDP(parent context.Context, control net.Conn, d TunnelDialer, requested socksTarget) {
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		_ = reply(control, 1, netip.AddrPort{})
		return
	}
	ctx, cancel := context.WithCancel(parent)
	var wg sync.WaitGroup
	flows := make(map[netip.AddrPort]udpFlow)
	stop := context.AfterFunc(ctx, func() { _ = udp.Close(); _ = control.Close() })
	defer func() {
		cancel()
		_ = udp.Close()
		_ = control.Close()
		stop()
		for _, flow := range flows {
			_ = flow.conn.Close()
		}
		wg.Wait()
	}()
	if err := reply(control, 0, udp.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = io.Copy(io.Discard, control); cancel() }()
	peerHost, _, _ := net.SplitHostPort(control.RemoteAddr().String())
	peerIP, _ := netip.ParseAddr(peerHost)
	var client netip.AddrPort
	buf := make([]byte, 65535)
	for {
		n, source, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		sameHost := source.Addr().Unmap() == peerIP.Unmap() || peerIP.Is6() && peerIP.IsLoopback() && source.Addr().IsLoopback()
		if !sameHost || requested.port != 0 && source.Port() != requested.port {
			continue
		}
		if client.IsValid() && source != client {
			continue
		}
		if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue
		}
		reader := &packetReader{b: buf[3:n]}
		target, err := readTarget(reader)
		if err != nil || target.port == 0 {
			continue
		}
		if !client.IsValid() {
			client = source
		}
		lookupCtx, lookupCancel := context.WithTimeout(ctx, handshakeTimeout)
		addresses, err := targetAddresses(lookupCtx, d, target)
		lookupCancel()
		if err != nil {
			continue
		}
		var conn net.Conn
		var remote netip.AddrPort
		for _, addr := range addresses {
			if flow, ok := flows[addr]; ok {
				select {
				case <-flow.done:
					delete(flows, addr)
				default:
					conn = flow.conn
				}
			}
			remote = addr
			if conn != nil {
				break
			}
			if len(flows) >= 128 {
				for address, flow := range flows {
					select {
					case <-flow.done:
						delete(flows, address)
					default:
					}
				}
				if len(flows) >= 128 {
					continue
				}
			}
			conn, err = d.DialUDPAddrPort(netip.AddrPort{}, addr)
			if err == nil {
				break
			}
			conn = nil
		}
		if conn == nil {
			continue
		}
		if _, ok := flows[remote]; !ok {
			done := make(chan struct{})
			flows[remote] = udpFlow{conn: conn, done: done}
			destination := client
			socket := conn
			responseAddr := remote
			stopFlow := context.AfterFunc(ctx, func() { _ = socket.Close() })
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(done)
				defer socket.Close()
				defer stopFlow()
				response := make([]byte, 65535)
				for {
					_ = socket.SetReadDeadline(time.Now().Add(time.Minute))
					n, err := socket.Read(response)
					if err != nil {
						return
					}
					frame := append([]byte{0, 0, 0}, encodeAddr(responseAddr)...)
					frame = append(frame, response[:n]...)
					if _, err = udp.WriteToUDPAddrPort(frame, destination); err != nil {
						return
					}
				}
			}()
		}
		_ = conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		if _, err := conn.Write(reader.b); err != nil {
			if flow, ok := flows[remote]; ok {
				_ = flow.conn.Close()
				delete(flows, remote)
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
	}
}

type packetReader struct{ b []byte }

func (r *packetReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// Keep address formatting independent from platform net.Addr implementations.
func targetString(t socksTarget) string { return net.JoinHostPort(t.host, strconv.Itoa(int(t.port))) }

type udpFlow struct {
	conn net.Conn
	done <-chan struct{}
}
