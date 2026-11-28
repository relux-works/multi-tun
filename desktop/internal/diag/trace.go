package diag

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

type TraceOptions struct {
	Host       string
	Timeout    time.Duration
	HTTPScheme string
	SkipHTTP   bool
	ConfigPath string
}
type TraceGuardResult struct {
	GuardHealth
	HostProtected  bool   `json:"host_protected"`
	MatchedService string `json:"matched_service,omitempty"`
}
type DNSResolutionResult struct {
	IPs       []string `json:"ips"`
	LatencyMS float64  `json:"latency_ms"`
	Error     string   `json:"error,omitempty"`
}
type HTTPProbeResult struct {
	URL           string  `json:"url"`
	OK            bool    `json:"ok"`
	StatusCode    int     `json:"status_code"`
	LatencyMS     float64 `json:"latency_ms"`
	RemoteAddr    string  `json:"remote_addr,omitempty"`
	TLSServerName string  `json:"tls_server_name,omitempty"`
	BodyPreview   string  `json:"body_preview,omitempty"`
	Error         string  `json:"error,omitempty"`
}
type TraceReport struct {
	Timestamp     string              `json:"timestamp"`
	Host          string              `json:"host"`
	ProbeURL      string              `json:"probe_url"`
	Verdict       string              `json:"verdict"`
	VPNCore       VPNCoreHealth       `json:"vpn_core"`
	Interfaces    []TUNInterfaceInfo  `json:"interfaces"`
	Guard         TraceGuardResult    `json:"guard"`
	ScutilDNS     *ResolverMatch      `json:"scutil_dns"`
	ScutilError   string              `json:"scutil_error,omitempty"`
	DNSResolution DNSResolutionResult `json:"dns_resolution"`
	KernelRoute   *KernelRoute        `json:"kernel_route"`
	SingBoxRule   *SingBoxMatch       `json:"sing_box_rule"`
	SingBoxError  string              `json:"sing_box_error,omitempty"`
	HTTPProbe     *HTTPProbeResult    `json:"http_probe"`
}

func ParseTraceTarget(raw, defaultScheme string) (host, probeURL string, err error) {
	bad := func() (string, string, error) { return "", "", fmt.Errorf("invalid trace target") }
	if raw == "" || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || !unicode.IsPrint(r) }) {
		return bad()
	}
	if defaultScheme == "" {
		defaultScheme = "https"
	}
	if defaultScheme != "https" && defaultScheme != "http" {
		return bad()
	}
	value := raw
	if !strings.Contains(value, "://") {
		if ip, e := netip.ParseAddr(value); e == nil && ip.Is6() {
			value = "[" + value + "]"
		}
		value = defaultScheme + "://" + value
	}
	u, e := url.Parse(value)
	if e != nil || u.User != nil || u.Opaque != "" || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return bad()
	}
	host = normalizeHost(u.Hostname())
	if ip, e := netip.ParseAddr(host); e != nil {
		if len(host) > 253 {
			return bad()
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return bad()
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return bad()
				}
			}
		}
	} else if ip.Zone() != "" {
		return bad()
	}
	if strings.HasSuffix(u.Host, ":") {
		return bad()
	}
	if port := u.Port(); port != "" {
		if _, e := netip.ParseAddrPort("127.0.0.1:" + port); e != nil || port == "0" {
			return bad()
		}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return host, u.String(), nil
}

// NewHTTPClient uses strict certificate/hostname verification, no ambient proxy,
// and no redirects (which could downgrade an HTTPS probe or leak its path).
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DialContext: (&net.Dialer{Timeout: timeout}).DialContext, TLSHandshakeTimeout: timeout, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func probeHTTP(ctx context.Context, d Deps, target string) HTTPProbeResult {
	result := HTTPProbeResult{URL: target}
	start := d.now()
	if d.HTTPClient == nil {
		result.Error = "HTTP client unavailable"
		return result
	}
	// Clone standard transports so even an injected test client cannot disable
	// certificate verification. Custom transports are outside this TLS boundary.
	client := *d.HTTPClient
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	standard, ok := transport.(*http.Transport)
	if !ok {
		result.Error = "HTTP probe requires a standard TLS-verifying transport"
		return result
	}
	tr := standard.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	tr.TLSClientConfig.InsecureSkipVerify = false
	tr.TLSClientConfig.ServerName = ""
	tr.DialTLSContext = nil
	tr.DialTLS = nil
	if tr.TLSClientConfig.VerifyConnection != nil || tr.TLSClientConfig.VerifyPeerCertificate != nil {
		result.Error = "custom certificate verification is unsupported"
		return result
	}
	client.Transport = tr
	defer tr.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var mu sync.Mutex
	remote := ""
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		if info.Conn != nil {
			remote = info.Conn.RemoteAddr().String()
		}
	}}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target, nil)
	if err == nil {
		var resp *http.Response
		resp, err = client.Do(req)
		if err == nil {
			result.StatusCode = resp.StatusCode
			// 2xx/3xx over verified TLS proves end-to-end HTTP reachability without
			// following redirects (e.g., corporate GitLab 302 -> /users/sign_in).
			result.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
			if resp.TLS != nil {
				result.TLSServerName = resp.TLS.ServerName
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			result.BodyPreview = clean(string(body), 160)
			if readErr != nil {
				err = readErr
				result.OK = false
			}
		}
	}
	result.LatencyMS = float64(d.now().Sub(start)) / float64(time.Millisecond)
	mu.Lock()
	result.RemoteAddr = remote
	mu.Unlock()
	if err != nil {
		result.Error = clean(err.Error(), 512)
	}
	return result
}
func Trace(ctx context.Context, d Deps, opts TraceOptions) (TraceReport, error) {
	host, target, err := ParseTraceTarget(opts.Host, opts.HTTPScheme)
	if err != nil {
		return TraceReport{}, err
	}
	if opts.Timeout < 0 {
		return TraceReport{}, fmt.Errorf("timeout must be positive")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	doctor, c, snap := collect(ctx, d)
	r := TraceReport{Timestamp: doctor.Timestamp, Host: host, ProbeURL: target, Verdict: doctor.Verdict, VPNCore: doctor.VPNCore, Interfaces: doctor.Interfaces, Guard: TraceGuardResult{GuardHealth: doctor.Guard}, ScutilDNS: MatchResolverForHost(snap, host), ScutilError: doctor.DNS.Error}
	start := d.now()
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		ips = []netip.Addr{ip}
	} else if d.ResolveIP == nil {
		err = fmt.Errorf("DNS resolver unavailable")
	} else {
		ips, err = d.ResolveIP(ctx, host)
	}
	r.DNSResolution.LatencyMS = float64(d.now().Sub(start)) / float64(time.Millisecond)
	for _, ip := range ips {
		if ip.IsValid() {
			r.DNSResolution.IPs = append(r.DNSResolution.IPs, ip.String())
		}
	}
	if err == nil && len(r.DNSResolution.IPs) == 0 {
		err = fmt.Errorf("DNS returned no addresses")
	}
	if err != nil {
		r.DNSResolution.Error = clean(err.Error(), 512)
		r.Verdict = "unhealthy"
	}
	// Policy coverage is distinct from the live enforcement fact above.
	for _, svc := range c.Policy.Services {
		match := false
		for _, domain := range append(append([]string{}, svc.Domains...), svc.Hosts...) {
			if suffixMatch(host, domain) {
				match = true
			}
		}
		for _, cidr := range svc.CIDRs {
			match = match || containsIP(ips, cidr)
		}
		if c.Policy.Enabled && match {
			r.Guard.HostProtected = true
			r.Guard.MatchedService = svc.Name
			break
		}
	}
	if len(r.DNSResolution.IPs) > 0 {
		ip := primaryTraceIP(ips, r.DNSResolution.IPs[0])
		route := KernelRoute{TargetIP: ip, Error: "route collector unavailable"}
		if d.RouteGet != nil {
			out, e := d.RouteGet(ctx, ip)
			route = ParseRouteGet(ip, out)
			if e != nil {
				route.Error = clean(e.Error()+" "+out, 512)
			}
		}
		r.KernelRoute = &route
		if route.Error != "" {
			r.Verdict = "unhealthy"
		}
	}
	path := opts.ConfigPath
	if path == "" {
		for _, s := range doctor.Sessions {
			if s.State == "active" && s.ConfigPath != "" {
				path = s.ConfigPath
				break
			}
		}
	}
	if path == "" {
		path = c.ConfigPath
	}
	if d.ReadFile == nil || path == "" {
		r.SingBoxError = "rendered sing-box config unavailable"
	} else {
		data, e := d.ReadFile(path)
		if e != nil {
			r.SingBoxError = clean(e.Error(), 512)
		} else {
			r.SingBoxRule, e = EvaluateSingBoxConfig(data, path, host, ips)
			if e != nil {
				r.SingBoxError = clean(e.Error(), 512)
			}
		}
	}
	if r.SingBoxError != "" || r.ScutilError != "" {
		if r.Verdict == "ok" {
			r.Verdict = "degraded"
		}
	}
	if !opts.SkipHTTP {
		probe := probeHTTP(ctx, d, target)
		r.HTTPProbe = &probe
		if !probe.OK {
			r.Verdict = "unhealthy"
		}
	}
	return r, nil
}
func primaryTraceIP(ips []netip.Addr, fallback string) string {
	for _, ip := range ips {
		if ip.IsValid() && ip.Is4() {
			return ip.String()
		}
	}
	return fallback
}
func FormatTraceText(r TraceReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Trace: %s (%s)\nvpn-core: reachable=%t pid=%d error=%s\n", clean(r.Host, 253), clean(r.Timestamp, 80), r.VPNCore.Reachable, r.VPNCore.DaemonPID, clean(r.VPNCore.Error, 512))
	for _, in := range r.Interfaces {
		fmt.Fprintf(&b, "TUN %s: up=%t mtu=%d role=%s flags=%s addresses=%s\n", clean(in.Name, 32), in.Up, in.MTU, clean(in.Role, 32), clean(in.Flags, 100), clean(strings.Join(in.Addresses, ", "), 512))
	}
	fmt.Fprintf(&b, "PF guard: enabled=%t enforcing=%t blocking=%t protected=%t service=%s table=%d live=%d matches=%t error=%s\n", r.Guard.ConfigEnabled, r.Guard.Enforcing, r.Guard.Blocking, r.Guard.HostProtected, clean(r.Guard.MatchedService, 80), r.Guard.TableEntries, r.Guard.LiveTableEntries, r.Guard.TableMatches, clean(r.Guard.Error, 512))
	if m := r.ScutilDNS; m != nil {
		fmt.Fprintf(&b, "scutil --dns: resolver #%d domain=%s nameservers=%s interface=%s (%s)\n", m.ResolverID, clean(m.MatchedDomain, 253), clean(strings.Join(m.Nameservers, ", "), 256), clean(m.Interface, 32), clean(m.MatchReason, 80))
	} else {
		fmt.Fprintf(&b, "scutil --dns: no matching resolver %s\n", clean(r.ScutilError, 512))
	}
	fmt.Fprintf(&b, "DNS lookup: %s (%.2f ms) %s\n", clean(strings.Join(r.DNSResolution.IPs, ", "), 512), r.DNSResolution.LatencyMS, clean(r.DNSResolution.Error, 512))
	if k := r.KernelRoute; k != nil {
		fmt.Fprintf(&b, "Kernel route: %s destination=%s gateway=%s interface=%s flags=%s %s\n", clean(k.TargetIP, 80), clean(k.Destination, 80), clean(k.Gateway, 80), clean(k.Interface, 32), clean(k.Flags, 160), clean(k.Error, 512))
	} else {
		b.WriteString("Kernel route: unavailable\n")
	}
	if s := r.SingBoxRule; s != nil {
		fmt.Fprintf(&b, "sing-box: config=%s TUN-excluded=%t cidr=%s DNS rule=%d %s server=%s address=%s detour=%s route rule=%d %s outbound=%s\n", clean(s.ConfigPath, 256), s.TUNExcluded, clean(s.TUNExcludeCIDR, 80), s.DNSRuleIndex, clean(s.DNSMatcher, 160), clean(s.DNSServerTag, 80), clean(s.DNSServerAddress, 160), clean(s.DNSDetour, 80), s.RouteRuleIndex, clean(s.RouteMatcher, 160), clean(s.Outbound, 80))
		for _, note := range s.Notes {
			fmt.Fprintf(&b, "  %s\n", clean(note, 256))
		}
	}
	if r.SingBoxError != "" {
		fmt.Fprintf(&b, "sing-box: %s\n", clean(r.SingBoxError, 512))
	}
	if h := r.HTTPProbe; h != nil {
		fmt.Fprintf(&b, "HTTP probe: %s status=%d (%.2f ms) remote=%s TLS=%s\n  %s %s\n", clean(h.URL, 512), h.StatusCode, h.LatencyMS, clean(h.RemoteAddr, 100), clean(h.TLSServerName, 253), clean(h.BodyPreview, 160), clean(h.Error, 512))
	} else {
		b.WriteString("HTTP probe: skipped\n")
	}
	fmt.Fprintf(&b, "Verdict: %s\n", clean(r.Verdict, 40))
	return b.String()
}
