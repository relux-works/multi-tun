// labserver is the server side of the sing-box TUN lab (lab/singbox-tun).
//
// It generates a throwaway CA and a leaf certificate for --ip, writes the CA to
// --ca-out, and serves:
//   - TLS on --tls-addr: the client sends a 16-byte request (seed uint64,
//     seconds uint32, rate bytes/s uint32, big endian); the server writes the
//     deterministic pattern stream for that seed at that rate, pausing for
//     --gap every --gap-every, then closes.
//   - plain TCP on --tcp-addr: writes "ok\n" and closes (connection churn).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"multi-tun/lab/singbox-tun/pattern"
)

func main() {
	ip := flag.String("ip", "203.0.113.10", "IP address the leaf certificate names")
	caOut := flag.String("ca-out", "/out/ca.pem", "where to write the CA certificate (PEM)")
	tlsAddr := flag.String("tls-addr", ":8443", "TLS stream listener")
	tcpAddr := flag.String("tcp-addr", ":8080", "plain TCP churn listener")
	gap := flag.Duration("gap", 3*time.Second, "pause length inside a stream")
	gapEvery := flag.Duration("gap-every", 10*time.Second, "pause interval inside a stream (0 = none)")
	flag.Parse()

	cfg, caPEM, err := certificates(net.ParseIP(*ip))
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caOut, caPEM, 0o644); err != nil {
		log.Fatal(err)
	}
	go serveTCP(*tcpAddr)
	ln, err := tls.Listen("tcp", *tlsAddr, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("labserver ready tls=%s tcp=%s", *tlsAddr, *tcpAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Print(err)
			continue
		}
		go stream(c, *gap, *gapEvery)
	}
}

func serveTCP(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			c.Write([]byte("ok\n"))
			c.Close()
		}()
	}
}

func stream(c net.Conn, gap, gapEvery time.Duration) {
	defer c.Close()
	var req [16]byte
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	seed := binary.BigEndian.Uint64(req[0:8])
	dur := time.Duration(binary.BigEndian.Uint32(req[8:12])) * time.Second
	rate := int64(binary.BigEndian.Uint32(req[12:16]))
	start := time.Now()
	nextGap := start.Add(gapEvery)
	buf := make([]byte, 16*1024)
	var off uint64
	for time.Since(start) < dur {
		if gapEvery > 0 && time.Now().After(nextGap) {
			time.Sleep(gap)
			nextGap = time.Now().Add(gapEvery)
		}
		pattern.Fill(seed, off, buf)
		if _, err := c.Write(buf); err != nil {
			return
		}
		off += uint64(len(buf))
		if rate > 0 {
			want := time.Duration(float64(off) / float64(rate) * float64(time.Second))
			if el := time.Since(start); want > el {
				time.Sleep(want - el)
			}
		}
	}
}

func certificates(ip net.IP) (*tls.Config, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "singbox-tun-lab CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: ip.String()},
		IPAddresses:  []net.IP{ip},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	return cfg, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}
