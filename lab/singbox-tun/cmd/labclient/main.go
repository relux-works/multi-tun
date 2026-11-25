// labclient is the client side of the sing-box TUN lab (lab/singbox-tun).
//
// It runs --streams concurrent TLS streams (certificate verified against
// --ca) for --duration each and checks every received byte against the
// deterministic pattern, while --churn workers open short plain TCP
// connections to --tcp as fast as they can. It prints one JSON summary and
// exits 1 when any stream failed or any byte mismatched.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"multi-tun/lab/singbox-tun/pattern"
)

type streamResult struct {
	Seed      uint64  `json:"seed"`
	Outcome   string  `json:"outcome"`
	Seconds   float64 `json:"seconds"`
	Bytes     uint64  `json:"bytes"`
	Mismatch  int64   `json:"mismatch_offset"`
	Error     string  `json:"error,omitempty"`
	LocalPort int     `json:"local_port"`
}

type summary struct {
	Label            string         `json:"label"`
	Streams          []streamResult `json:"streams"`
	StreamsOK        int            `json:"streams_ok"`
	StreamsFailed    int            `json:"streams_failed"`
	ChurnAttempts    int64          `json:"churn_attempts"`
	ChurnOK          int64          `json:"churn_ok"`
	ChurnConnTimeout int64          `json:"churn_connect_timeout"`
	ChurnOtherErr    int64          `json:"churn_other_error"`
	ChurnBadReply    int64          `json:"churn_bad_reply"`
	ErrorClasses     map[string]int `json:"stream_error_classes"`
}

func main() {
	addr := flag.String("tls", "203.0.113.10:8443", "TLS stream server")
	tcp := flag.String("tcp", "203.0.113.10:8080", "plain TCP churn server")
	caPath := flag.String("ca", "/out/ca.pem", "CA certificate (PEM)")
	streams := flag.Int("streams", 8, "concurrent TLS streams")
	waves := flag.Int("waves", 1, "sequential waves of streams")
	duration := flag.Duration("duration", 120*time.Second, "length of each stream")
	rate := flag.Uint("rate", 256*1024, "stream rate in bytes/s")
	churn := flag.Int("churn", 32, "parallel churn workers (0 = none)")
	connTimeout := flag.Duration("connect-timeout", 3*time.Second, "churn connect timeout")
	label := flag.String("label", "", "run label")
	flag.Parse()

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "no CA in", *caPath)
		os.Exit(2)
	}
	host, _, _ := net.SplitHostPort(*addr)
	tcfg := &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS13}

	sum := summary{Label: *label, ErrorClasses: map[string]int{}}
	stop := make(chan struct{})
	var cwg sync.WaitGroup
	var attempts, ok, cto, other, bad atomic.Int64
	for i := 0; i < *churn; i++ {
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			d := net.Dialer{Timeout: *connTimeout}
			buf := make([]byte, 8)
			for {
				select {
				case <-stop:
					return
				default:
				}
				attempts.Add(1)
				c, err := d.Dial("tcp", *tcp)
				if err != nil {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						cto.Add(1)
					} else {
						other.Add(1)
					}
					continue
				}
				c.SetDeadline(time.Now().Add(*connTimeout))
				n, _ := io.ReadFull(c, buf[:3])
				c.Close()
				if n == 3 && string(buf[:3]) == "ok\n" {
					ok.Add(1)
				} else {
					bad.Add(1)
				}
			}
		}()
	}

	var mu sync.Mutex
	seed := uint64(time.Now().UnixNano())
	for w := 0; w < *waves; w++ {
		var wg sync.WaitGroup
		for i := 0; i < *streams; i++ {
			seed++
			wg.Add(1)
			go func(s uint64) {
				defer wg.Done()
				r := runStream(*addr, tcfg, s, *duration, uint32(*rate))
				mu.Lock()
				sum.Streams = append(sum.Streams, r)
				mu.Unlock()
			}(seed)
		}
		wg.Wait()
	}
	close(stop)
	cwg.Wait()

	sort.Slice(sum.Streams, func(i, j int) bool { return sum.Streams[i].Seed < sum.Streams[j].Seed })
	for _, r := range sum.Streams {
		if r.Outcome == "ok" {
			sum.StreamsOK++
		} else {
			sum.StreamsFailed++
			sum.ErrorClasses[classify(r)]++
		}
	}
	sum.ChurnAttempts, sum.ChurnOK, sum.ChurnConnTimeout = attempts.Load(), ok.Load(), cto.Load()
	sum.ChurnOtherErr, sum.ChurnBadReply = other.Load(), bad.Load()
	json.NewEncoder(os.Stdout).Encode(sum)
	if sum.StreamsFailed > 0 {
		os.Exit(1)
	}
}

func classify(r streamResult) string {
	if r.Mismatch >= 0 {
		return "byte_mismatch"
	}
	return r.Outcome + ": " + r.Error
}

func runStream(addr string, cfg *tls.Config, seed uint64, dur time.Duration, rate uint32) streamResult {
	res := streamResult{Seed: seed, Mismatch: -1}
	start := time.Now()
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
	if err != nil {
		res.Outcome, res.Error = "dial", err.Error()
		res.Seconds = time.Since(start).Seconds()
		return res
	}
	defer conn.Close()
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		res.LocalPort = la.Port
	}
	var req [16]byte
	binary.BigEndian.PutUint64(req[0:8], seed)
	binary.BigEndian.PutUint32(req[8:12], uint32(dur/time.Second))
	binary.BigEndian.PutUint32(req[12:16], rate)
	if _, err := conn.Write(req[:]); err != nil {
		res.Outcome, res.Error = "write", err.Error()
		return res
	}
	buf := make([]byte, 32*1024)
	var off uint64
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			if i := pattern.Mismatch(seed, off, buf[:n]); i >= 0 && res.Mismatch < 0 {
				res.Mismatch = int64(off) + int64(i)
			}
			off += uint64(n)
		}
		if err != nil {
			res.Bytes, res.Seconds = off, time.Since(start).Seconds()
			switch {
			case errors.Is(err, io.EOF) && res.Mismatch < 0 && time.Since(start) >= dur-time.Second:
				res.Outcome = "ok"
			case errors.Is(err, io.EOF):
				res.Outcome, res.Error = "early_eof", err.Error()
			default:
				res.Outcome, res.Error = "read", err.Error()
			}
			if res.Mismatch >= 0 && res.Outcome == "ok" {
				res.Outcome = "mismatch"
			}
			return res
		}
	}
}
