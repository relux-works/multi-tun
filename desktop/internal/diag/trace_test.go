package diag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestTraceTarget(t *testing.T) {
	for _, tc := range []struct{ raw, scheme, host, url string }{{"gitlab.services.mts.ru", "", "gitlab.services.mts.ru", "https://gitlab.services.mts.ru/"}, {"nodedata.io/whoami", "", "nodedata.io", "https://nodedata.io/whoami"}, {"https://www.gosuslugi.ru/", "", "www.gosuslugi.ru", "https://www.gosuslugi.ru/"}, {"EXAMPLE.TEST.", "http", "example.test", "http://EXAMPLE.TEST./"}, {"127.0.0.1:8080/path", "http", "127.0.0.1", "http://127.0.0.1:8080/path"}, {"::1", "", "::1", "https://[::1]/"}, {"https://[2001:db8::1]:443/", "", "2001:db8::1", "https://[2001:db8::1]:443/"}} {
		t.Run(tc.raw, func(t *testing.T) {
			host, u, err := ParseTraceTarget(tc.raw, tc.scheme)
			if err != nil || host != tc.host || u != tc.url {
				t.Fatalf("got %q %q %v", host, u, err)
			}
		})
	}
	for _, raw := range []string{"", " ", "example.test\n", "a b", "\x1bexample.test", "https://user:pass@example.test/", "user:pass@example.test", "https://example.test@other.test/", "file:///tmp/a", "ftp://example.test/", "https:///path", "https://example.test:bad/", "https://example.test:0/", "https://example.test:65536/", "-bad.test", "a..test", "https://%0a.test", "https://example.test:/", "https://[fe80::1%25en0]/", "https://example.test/\u202e"} {
		if _, _, err := ParseTraceTarget(raw, ""); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, _, err := ParseTraceTarget("example.test", "ftp"); err == nil {
		t.Fatal("accepted scheme")
	}
}
func traceDeps(t *testing.T) Deps {
	t.Helper()
	d := healthyDeps()
	d.Now = time.Now
	data := renderedConfig(t)
	d.ReadFile = func(path string) ([]byte, error) {
		if path != "active.json" {
			t.Errorf("active session config not selected: %s", path)
		}
		return data, nil
	}
	d.ResolveIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.20.30.40")}, nil
	}
	d.RouteGet = func(_ context.Context, ip string) (string, error) {
		return "route to: 10.20.30.40\ndestination: 10.0.0.0\nmask: 255.0.0.0\ngateway: 10.0.0.1\ninterface: utun4\nflags: <UP,GATEWAY>\n", nil
	}
	return d
}
func trustedClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: time.Second}
}
func TestTraceFullPipelineTrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/whoami" {
			t.Errorf("path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("peer=fixture\r\n\x1b\x00\x7f" + strings.Repeat("x", 1000)))
	}))
	defer server.Close()
	d := traceDeps(t)
	d.HTTPClient = trustedClient(t, server)
	// The httptest certificate includes example.com. Use that DNS name while the
	// transport connects exclusively to the local TLS server; verification stays on.
	conf := d.Configuration
	d.Configuration = func(ctx context.Context) Configuration {
		c := conf(ctx)
		c.Policy.Services[0].Domains = []string{"example.com"}
		return c
	}
	r, err := Trace(context.Background(), d, TraceOptions{Host: "https://example.com/whoami", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != "ok" || r.Host != "example.com" || r.Timestamp == "" || !r.VPNCore.Reachable || len(r.Interfaces) != 1 || !r.Guard.Enforcing || !r.Guard.HostProtected || r.Guard.MatchedService != "service" {
		t.Fatalf("health: %+v", r)
	}
	if r.ScutilDNS == nil || r.ScutilDNS.ResolverID != 1 || r.ScutilError != "" {
		t.Fatalf("resolver: %+v", r.ScutilDNS)
	}
	if len(r.DNSResolution.IPs) != 1 || r.DNSResolution.IPs[0] != "10.20.30.40" || r.DNSResolution.LatencyMS <= 0 || r.DNSResolution.Error != "" {
		t.Fatalf("DNS: %+v", r.DNSResolution)
	}
	if r.KernelRoute == nil || r.KernelRoute.Interface != "utun4" || r.KernelRoute.Gateway != "10.0.0.1" {
		t.Fatalf("route: %+v", r.KernelRoute)
	}
	if r.SingBoxError != "" || r.SingBoxRule == nil || !r.SingBoxRule.TUNExcluded || r.SingBoxRule.Outbound != "direct" || r.SingBoxRule.DNSServerTag != "dns-proxy" || r.SingBoxRule.ConfigPath != "active.json" {
		t.Fatalf("sing-box: %+v %s", r.SingBoxRule, r.SingBoxError)
	}
	h := r.HTTPProbe
	if h == nil || !h.OK || h.StatusCode != 200 || h.RemoteAddr != server.Listener.Addr().String() || h.TLSServerName != "example.com" || h.LatencyMS <= 0 || len([]rune(h.BodyPreview)) > 160 || !strings.HasPrefix(h.BodyPreview, "peer=fixture") {
		t.Fatalf("HTTP: %+v", h)
	}
	for _, r := range h.BodyPreview {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			t.Fatalf("unsafe preview: %q", h.BodyPreview)
		}
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TraceReport
	if err = json.Unmarshal(data, &decoded); err != nil || decoded.HTTPProbe.RemoteAddr != h.RemoteAddr || !decoded.Guard.HostProtected {
		t.Fatalf("round trip: %v", err)
	}
	text := FormatTraceText(r)
	for _, layer := range []string{"vpn-core:", "TUN utun233", "PF guard:", "scutil --dns:", "DNS lookup:", "Kernel route:", "sing-box:", "HTTP probe:", "Verdict: ok"} {
		if !strings.Contains(text, layer) {
			t.Errorf("missing layer %s", layer)
		}
	}
}
func TestTraceFailures(t *testing.T) {
	t.Run("invalid target makes no calls", func(t *testing.T) {
		d := Deps{Configuration: func(context.Context) Configuration { t.Fatal("unexpected collection"); return Configuration{} }}
		if _, err := Trace(context.Background(), d, TraceOptions{Host: "https://user:pass@example.test/"}); err == nil {
			t.Fatal("accepted userinfo")
		}
	})
	t.Run("DNS failure", func(t *testing.T) {
		d := traceDeps(t)
		d.ResolveIP = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("DNS unavailable") }
		d.RouteGet = func(context.Context, string) (string, error) { t.Fatal("route called without IP"); return "", nil }
		r, err := Trace(context.Background(), d, TraceOptions{Host: "gitlab.services.mts.ru", SkipHTTP: true})
		if err != nil || r.Verdict != "unhealthy" || r.DNSResolution.Error != "DNS unavailable" || r.KernelRoute != nil || r.HTTPProbe != nil {
			t.Fatalf("report: %+v %v", r, err)
		}
	})
	t.Run("route failure", func(t *testing.T) {
		d := traceDeps(t)
		d.RouteGet = func(context.Context, string) (string, error) {
			return "route: not in table", errors.New("exit status 1")
		}
		r, err := Trace(context.Background(), d, TraceOptions{Host: "host.test", SkipHTTP: true})
		if err != nil || r.Verdict != "unhealthy" || r.KernelRoute.Error == "" {
			t.Fatalf("report: %+v %v", r, err)
		}
	})
	t.Run("HTTP timeout", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		defer server.Close()
		d := traceDeps(t)
		d.HTTPClient = trustedClient(t, server)
		r, err := Trace(context.Background(), d, TraceOptions{Host: server.URL, Timeout: 100 * time.Millisecond})
		if err != nil || r.HTTPProbe == nil || r.HTTPProbe.OK || r.HTTPProbe.Error == "" || r.Verdict != "unhealthy" {
			t.Fatalf("timeout: %+v %v", r, err)
		}
	})
	t.Run("trusted certificate wrong hostname", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("wrong hostname request reached handler") }))
		defer server.Close()
		d := traceDeps(t)
		d.HTTPClient = trustedClient(t, server)
		r, err := Trace(context.Background(), d, TraceOptions{Host: "https://wrong.test/", Timeout: time.Second})
		if err != nil || r.HTTPProbe == nil || r.HTTPProbe.OK || !strings.Contains(r.HTTPProbe.Error, "certificate") {
			t.Fatalf("hostname refusal: %+v %v", r.HTTPProbe, err)
		}
	})

	t.Run("untrusted certificate", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted request reached handler") }))
		defer server.Close()
		d := traceDeps(t)
		d.HTTPClient = NewHTTPClient(time.Second)
		r, err := Trace(context.Background(), d, TraceOptions{Host: server.URL, Timeout: time.Second})
		if err != nil || r.HTTPProbe == nil || r.HTTPProbe.OK || !strings.Contains(r.HTTPProbe.Error, "certificate") {
			t.Fatalf("TLS refusal: %+v %v", r.HTTPProbe, err)
		}
	})
}
func TestTraceConfigSelectionAndProtection(t *testing.T) {
	for _, tc := range []struct {
		name, path, host  string
		active, protected bool
	}{{"active", "active.json", "login.mts.ru", true, true}, {"fallback", "fallback.json", "fakemts.ru", false, false}, {"explicit", "explicit.json", "gitlab.services.mts.ru", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			d := traceDeps(t)
			if !tc.active {
				d.Sessions = func(context.Context) ([]SessionHealth, error) { return nil, nil }
			}
			data := renderedConfig(t)
			d.ReadFile = func(path string) ([]byte, error) {
				if path != tc.path {
					t.Errorf("config: %s, want %s", path, tc.path)
				}
				return data, nil
			}
			opts := TraceOptions{Host: tc.host, SkipHTTP: true}
			if tc.name == "explicit" {
				opts.ConfigPath = tc.path
			}
			r, err := Trace(context.Background(), d, opts)
			if err != nil || r.Guard.HostProtected != tc.protected {
				t.Fatalf("protection: %+v %v", r.Guard, err)
			}
		})
	}
}
func TestProbeBoundsAndRedirect(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/other", http.StatusFound)
			return
		}
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("é", 1000)))
	}))
	defer server.Close()
	d := Deps{Now: time.Now, HTTPClient: NewHTTPClient(time.Second)}
	r := probeHTTP(context.Background(), d, server.URL)
	if !r.OK || len([]rune(r.BodyPreview)) > 160 {
		t.Fatalf("bound: %+v", r)
	}
	r = probeHTTP(context.Background(), d, server.URL+"/redirect")
	if !r.OK || r.StatusCode != 302 || hits != 2 {
		t.Fatalf("redirect followed or refused: %+v hits=%d", r, hits)
	}
	r = probeHTTP(context.Background(), d, server.URL+"/error")
	if r.OK || r.StatusCode != 502 {
		t.Fatalf("502 accepted: %+v", r)
	}
}
