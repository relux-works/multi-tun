package vpncorecli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/subscription"
)

type vlessFetchOptions struct {
	URL           string
	HostHeader    string
	TLSServerName string
	UserAgent     string
	InsecureTLS   bool
	DisableHTTP2  bool
	Timeout       time.Duration
}

type vlessFetchResult struct {
	Status      string
	StatusCode  int
	ContentType string
	Body        []byte
}

type vlessProbeReport struct {
	SourceMode   string
	Attempts     []vlessProbeAttempt
	SuccessIndex int
}

type vlessProbeAttempt struct {
	Name          string
	URL           string
	Status        string
	StatusCode    int
	ContentType   string
	PayloadFormat string
	Profiles      []model.Profile
	Err           error
}

func (a *App) runInspectVLESSURL(args []string) int {
	fs := flag.NewFlagSet("inspect-vless-url", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	sourceMode := fs.String("source-mode", "", "Source mode: proxy for HTTP subscriptions, direct for literal vless:// URIs")
	insecureTLS := fs.Bool("insecure", false, "Skip TLS certificate verification for subscription fetches")
	hostHeader := fs.String("host", "", "Override HTTP Host header")
	tlsServerName := fs.String("tls-server-name", "", "Override TLS server name")
	userAgent := fs.String("user-agent", "vpn-core/0.1", "HTTP User-Agent for subscription fetches")
	timeout := fs.Duration("timeout", 8*time.Second, "Per-attempt HTTP request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.stderr, "inspect-vless-url failed: pass exactly one URL")
		return 2
	}

	mode := strings.TrimSpace(*sourceMode)
	sourceURL := strings.TrimSpace(fs.Arg(0))
	if mode == "" {
		mode = inferVLESSProbeSourceMode(sourceURL)
	}

	report, err := inspectVLESSURL(context.Background(), mode, sourceURL, vlessFetchOptions{
		HostHeader:    strings.TrimSpace(*hostHeader),
		TLSServerName: strings.TrimSpace(*tlsServerName),
		UserAgent:     strings.TrimSpace(*userAgent),
		InsecureTLS:   *insecureTLS,
		Timeout:       *timeout,
	})

	fmt.Fprintf(a.stdout, "source_mode: %s\n", report.SourceMode)
	printVLESSProbeAttempts(a.stdout, sourceURL, report.Attempts)
	if err != nil {
		fmt.Fprintf(a.stderr, "inspect-vless-url failed: %v\n", err)
		return 1
	}

	success := report.Attempts[report.SuccessIndex]
	fmt.Fprintf(a.stdout, "selected_attempt: %s\n", success.Name)
	fmt.Fprintf(a.stdout, "payload_format: %s\n", success.PayloadFormat)
	fmt.Fprintf(a.stdout, "profile_count: %d\n", len(success.Profiles))
	for idx, profile := range success.Profiles {
		fmt.Fprintf(a.stdout, "%d. name=%q endpoint=%s protocol=%s security=%s network=%s flow=%s sni=%s fingerprint=%s service_name=%s authority=%s public_key=%s short_id=%s\n",
			idx+1,
			profile.DisplayName(),
			profile.Endpoint(),
			profile.Protocol,
			profile.Security,
			profile.Network,
			emptyLabel(profile.Flow),
			emptyLabel(profile.SNI),
			emptyLabel(profile.Fingerprint),
			emptyLabel(profile.ServiceName),
			emptyLabel(profile.Authority),
			presentLabel(profile.PublicKey),
			presentLabel(profile.ShortID),
		)
	}
	return 0
}

func inspectVLESSURL(ctx context.Context, sourceMode string, sourceURL string, options vlessFetchOptions) (vlessProbeReport, error) {
	if sourceMode == "" {
		sourceMode = inferVLESSProbeSourceMode(sourceURL)
	}
	report := vlessProbeReport{
		SourceMode:   sourceMode,
		SuccessIndex: -1,
	}

	switch sourceMode {
	case "direct":
		attempt := inspectVLESSDirect("direct-uri", sourceURL)
		report.Attempts = append(report.Attempts, attempt)
		if attempt.Err != nil {
			return report, attempt.Err
		}
		report.SuccessIndex = 0
		return report, nil
	case "", "proxy":
		for _, analyzer := range vlessProxyProbeAnalyzers(ctx, sourceURL, options) {
			attempt := inspectVLESSProxy(ctx, sourceURL, analyzer.name, analyzer.options)
			report.Attempts = append(report.Attempts, attempt)
			if attempt.Err == nil {
				report.SuccessIndex = len(report.Attempts) - 1
				return report, nil
			}
		}
		return report, fmt.Errorf("all probe analyzers failed")
	default:
		return report, fmt.Errorf("unsupported source mode %q", sourceMode)
	}
}

type vlessProxyProbeAnalyzer struct {
	name    string
	options vlessFetchOptions
}

func vlessProxyProbeAnalyzers(ctx context.Context, sourceURL string, options vlessFetchOptions) []vlessProxyProbeAnalyzer {
	options = normalizeVLESSFetchOptions(options)

	analyzers := make([]vlessProxyProbeAnalyzer, 0, 8)
	seen := map[string]struct{}{}
	add := func(name string, next vlessFetchOptions) {
		next = normalizeVLESSFetchOptions(next)
		key := strings.Join([]string{
			next.URL,
			next.HostHeader,
			next.TLSServerName,
			next.UserAgent,
			fmt.Sprintf("%t", next.InsecureTLS),
			fmt.Sprintf("%t", next.DisableHTTP2),
		}, "\x00")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		analyzers = append(analyzers, vlessProxyProbeAnalyzer{name: name, options: next})
	}

	add("proxy-default", vlessFetchOptions{
		UserAgent: options.UserAgent,
		Timeout:   options.Timeout,
	})
	if options.HostHeader != "" || options.TLSServerName != "" || options.InsecureTLS {
		add("proxy-explicit-options", options)
	}
	add("proxy-insecure-tls", vlessFetchOptions{
		UserAgent:   options.UserAgent,
		InsecureTLS: true,
		Timeout:     options.Timeout,
	})
	add("proxy-browser-user-agent", vlessFetchOptions{
		UserAgent: "Mozilla/5.0",
		Timeout:   options.Timeout,
	})
	add("proxy-v2rayn-user-agent", vlessFetchOptions{
		UserAgent: "v2rayN/6.0",
		Timeout:   options.Timeout,
	})
	add("proxy-http1", vlessFetchOptions{
		UserAgent:    options.UserAgent,
		DisableHTTP2: true,
		Timeout:      options.Timeout,
	})

	for _, name := range certificateDNSNames(ctx, sourceURL, options.Timeout) {
		add("proxy-certificate-host-"+name, vlessFetchOptions{
			HostHeader:    name,
			TLSServerName: name,
			UserAgent:     options.UserAgent,
			Timeout:       options.Timeout,
		})
		add("proxy-certificate-host-http1-"+name, vlessFetchOptions{
			HostHeader:    name,
			TLSServerName: name,
			UserAgent:     options.UserAgent,
			DisableHTTP2:  true,
			Timeout:       options.Timeout,
		})
		add("proxy-certificate-host-insecure-"+name, vlessFetchOptions{
			HostHeader:    name,
			TLSServerName: name,
			UserAgent:     options.UserAgent,
			InsecureTLS:   true,
			Timeout:       options.Timeout,
		})
		if rewritten, ok := rewriteURLHost(sourceURL, name); ok {
			add("proxy-certificate-url-"+name, vlessFetchOptions{
				HostHeader:    name,
				TLSServerName: name,
				UserAgent:     options.UserAgent,
				Timeout:       options.Timeout,
				URL:           rewritten,
			})
		}
	}

	return analyzers
}

func inspectVLESSDirect(name string, sourceURL string) vlessProbeAttempt {
	normalized, payloadFormat, err := subscription.NormalizePayload([]byte(sourceURL))
	if err != nil {
		return vlessProbeAttempt{Name: name, Err: err}
	}
	profiles, err := subscription.ParseProfiles(normalized)
	return vlessProbeAttempt{
		Name:          name,
		PayloadFormat: payloadFormat,
		Profiles:      profiles,
		Err:           err,
	}
}

func inspectVLESSProxy(ctx context.Context, sourceURL string, name string, options vlessFetchOptions) vlessProbeAttempt {
	fetchURL := sourceURL
	if options.URL != "" {
		fetchURL = options.URL
	}
	fetch, err := fetchVLESSSubscriptionForProbe(ctx, fetchURL, options)
	attempt := vlessProbeAttempt{
		Name:        name,
		URL:         fetchURL,
		Status:      fetch.Status,
		StatusCode:  fetch.StatusCode,
		ContentType: fetch.ContentType,
		Err:         err,
	}
	if err != nil {
		return attempt
	}

	normalized, payloadFormat, err := subscription.NormalizePayload(fetch.Body)
	if err != nil {
		attempt.Err = err
		return attempt
	}
	profiles, err := subscription.ParseProfiles(normalized)
	attempt.PayloadFormat = payloadFormat
	attempt.Profiles = profiles
	attempt.Err = err
	return attempt
}

func fetchVLESSSubscriptionForProbe(ctx context.Context, sourceURL string, options vlessFetchOptions) (vlessFetchResult, error) {
	options = normalizeVLESSFetchOptions(options)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return vlessFetchResult{}, err
	}
	if options.UserAgent != "" {
		req.Header.Set("User-Agent", options.UserAgent)
	}
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.8")
	if options.HostHeader != "" {
		req.Host = options.HostHeader
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if options.DisableHTTP2 {
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if options.InsecureTLS || options.TLSServerName != "" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: options.InsecureTLS,
			ServerName:         options.TLSServerName,
		}
	}

	client := &http.Client{
		Timeout:   options.Timeout,
		Transport: transport,
	}

	resp, err := client.Do(req)
	if err != nil {
		return vlessFetchResult{}, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	result := vlessFetchResult{
		Status:      resp.Status,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}
	if readErr != nil {
		return result, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("subscription request failed with status %s", resp.Status)
	}
	return result, nil
}

func normalizeVLESSFetchOptions(options vlessFetchOptions) vlessFetchOptions {
	if options.UserAgent == "" {
		options.UserAgent = "vpn-core/0.1"
	}
	if options.Timeout <= 0 {
		options.Timeout = 8 * time.Second
	}
	return options
}

func certificateDNSNames(ctx context.Context, sourceURL string, timeout time.Duration) []string {
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil
	}
	host := parsed.Hostname()
	if host == "" {
		return nil
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	timeout = normalizeVLESSFetchOptions(vlessFetchOptions{Timeout: timeout}).Timeout

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	names := make([]string, 0, len(state.PeerCertificates[0].DNSNames)+1)
	seen := map[string]struct{}{}
	for _, name := range state.PeerCertificates[0].DNSNames {
		name = strings.TrimSpace(strings.ToLower(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func rewriteURLHost(raw string, host string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || host == "" {
		return "", false
	}
	if strings.EqualFold(parsed.Hostname(), host) {
		return "", false
	}
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else {
		parsed.Host = host
	}
	return parsed.String(), true
}

func inferVLESSProbeSourceMode(sourceURL string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(sourceURL)), "vless://") {
		return "direct"
	}
	return "proxy"
}

func printVLESSProbeAttempts(w io.Writer, sourceURL string, attempts []vlessProbeAttempt) {
	if len(attempts) == 0 {
		return
	}
	fmt.Fprintln(w, "attempts:")
	for _, attempt := range attempts {
		state := "ok"
		if attempt.Err != nil {
			state = "failed"
		}
		fmt.Fprintf(w, "- %s: %s", attempt.Name, state)
		if attempt.Status != "" {
			fmt.Fprintf(w, " http_status=%s", attempt.Status)
		}
		if attempt.ContentType != "" {
			fmt.Fprintf(w, " content_type=%q", attempt.ContentType)
		}
		if attempt.PayloadFormat != "" {
			fmt.Fprintf(w, " payload_format=%s profiles=%d", attempt.PayloadFormat, len(attempt.Profiles))
		}
		if attempt.Err != nil {
			fmt.Fprintf(w, " error=%q", redactVLESSProbeText(attempt.Err.Error(), sourceURL, attempt.URL))
		}
		fmt.Fprintln(w)
	}
}

func redactVLESSProbeText(text string, rawURLs ...string) string {
	for _, rawURL := range rawURLs {
		if rawURL == "" {
			continue
		}
		text = strings.ReplaceAll(text, rawURL, redactURLValue(rawURL))
	}
	return text
}

func redactURLValue(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<redacted-url>"
	}

	redacted := parsed.Scheme + "://" + parsed.Host
	if parsed.Path == "/" {
		redacted += "/"
	} else if parsed.Path != "" {
		redacted += "/<redacted>"
	}
	if parsed.RawQuery != "" {
		redacted += "?<redacted>"
	}
	return redacted
}

func emptyLabel(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func presentLabel(value string) string {
	if value == "" {
		return "absent"
	}
	return "present"
}
