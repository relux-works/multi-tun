package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/anyconnect/openconnect"
	"multi-tun/desktop/internal/diag"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/session"
)

// Every command test installs the dependency factory before calling App.Run;
// none may inspect the real daemon, interfaces, sessions, DNS, routes or files.
func TestDoctorTraceCLI(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fixture\n")) }))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	old := diagnosticsDepsCLI
	defer func() { diagnosticsDepsCLI = old }()
	calls := 0
	diagnosticsDepsCLI = func(path string, timeout time.Duration) diag.Deps {
		calls++
		if path != "" && path != "fixture.json" {
			t.Errorf("path: %s", path)
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}}}
		return diag.Deps{
			Now: time.Now, HTTPClient: client,
			Configuration: func(context.Context) diag.Configuration {
				return diag.Configuration{Present: true, HelperRequired: true, ConfigPath: "fixture.json"}
			},
			VPNCore:    func(context.Context) diag.VPNCoreHealth { return diag.VPNCoreHealth{Reachable: true} },
			Guard:      func(context.Context) diag.GuardHealth { return diag.GuardHealth{} },
			Interfaces: func(context.Context) ([]diag.TUNInterfaceInfo, error) { return nil, nil },
			Sessions:   func(context.Context) ([]diag.SessionHealth, error) { return nil, nil },
			ScutilDNS: func(context.Context) (string, error) {
				return "DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.53\n", nil
			},
			ResolveIP: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			},
			RouteGet: func(context.Context, string) (string, error) {
				return "destination: default\ngateway: 192.0.2.254\ninterface: en0\n", nil
			},
			ReadFile: func(string) ([]byte, error) {
				return []byte(`{"dns":{"final":"local"},"route":{"final":"proxy"}}`), nil
			},
		}
	}
	for _, tc := range []struct {
		args []string
		code int
		json bool
	}{
		{[]string{"doctor"}, 0, false},
		{[]string{"doctor", "--json"}, 0, true},
		{[]string{"trace", "example.com", "--json"}, 0, true},
		{[]string{"trace", "--json", "example.com"}, 0, true},
		{[]string{"trace", "example.com", "--config", "fixture.json", "--timeout", "2s", "--http-scheme", "http", "--no-http", "--json"}, 0, true},
		{[]string{"trace", "--config=fixture.json", "--json", "example.com", "--no-http"}, 0, true},
		{[]string{"trace"}, 2, false},
		{[]string{"trace", "--json"}, 2, false},
		{[]string{"trace", "first.test", "second.test"}, 2, false},
		{[]string{"trace", "example.com", "--timeout", "0s"}, 2, false},
		{[]string{"trace", "example.com", "--http-scheme", "ftp"}, 2, false},
		{[]string{"trace", "user:pass@example.com", "--json"}, 2, false},
		{[]string{"trace", "example.com", "--config"}, 2, false},
		{[]string{"doctor", "unexpected"}, 2, false},
		{[]string{"trace", "example.com", "--unknown"}, 2, false},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := NewWithName(&out, &errOut, "tun-wave").Run(tc.args)
			if code != tc.code {
				t.Fatalf("exit %d want %d\nstdout=%s\nstderr=%s", code, tc.code, out.String(), errOut.String())
			}
			if tc.json {
				var data map[string]json.RawMessage
				if err := json.Unmarshal(out.Bytes(), &data); err != nil {
					t.Fatalf("invalid JSON: %v: %s", err, out.String())
				}
				if _, ok := data["verdict"]; !ok {
					t.Fatal("missing verdict")
				}
				if !strings.Contains(out.String(), "\n  \"") {
					t.Fatal("JSON not indented")
				}
			}
		})
	}
	if calls != 6 {
		t.Fatalf("invalid args constructed host dependencies: %d calls", calls)
	}
}
func TestDoctorCLIExitAndMissingConfig(t *testing.T) {
	old := diagnosticsDepsCLI
	defer func() { diagnosticsDepsCLI = old }()
	for _, reachable := range []bool{false, true} {
		diagnosticsDepsCLI = func(string, time.Duration) diag.Deps {
			return diag.Deps{Configuration: func(context.Context) diag.Configuration {
				return diag.Configuration{Present: true, HelperRequired: true}
			}, VPNCore: func(context.Context) diag.VPNCoreHealth { return diag.VPNCoreHealth{Reachable: reachable} }}
		}
		var out, errOut bytes.Buffer
		code := New(&out, &errOut).Run([]string{"doctor", "--json"})
		want := 1
		if reachable {
			want = 0
		}
		if code != want {
			t.Fatalf("exit %d want %d: %s", code, want, out.String())
		}
	}
	path := filepath.Join(t.TempDir(), "missing.json")
	// Exercise only the real config loader callback, then inject all other reads.
	real := newDiagnosticsDeps(path, time.Second)
	diagnosticsDepsCLI = func(string, time.Duration) diag.Deps {
		return diag.Deps{Configuration: real.Configuration, VPNCore: func(context.Context) diag.VPNCoreHealth { return diag.VPNCoreHealth{Reachable: true} }}
	}
	var out, errOut bytes.Buffer
	if code := New(&out, &errOut).Run([]string{"doctor", "--json"}); code != 0 {
		t.Fatalf("missing config exit=%d: %s %s", code, out.String(), errOut.String())
	}
	var report diag.DoctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "config" && c.Status == "warn" && c.Detail == "missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing warning: %+v", report.Checks)
	}
}
func TestDiagnosticAuthRedaction(t *testing.T) {
	secret := "private-secret-marker"
	cfg := config.ProjectConfig{Source: config.SourceConfig{URL: "https://example.test/?token=" + secret}}
	a := diagnosticAuth("fixture", cfg)
	data, _ := json.Marshal(a)
	if a.Storage != "plaintext_url" || a.Status != "warn" || strings.Contains(string(data), secret) || strings.Contains(string(data), "https://") {
		t.Fatalf("redaction: %s", data)
	}
	cfg.Source.Auth = &config.SourceAuthConfig{Mode: "keychain", Record: secret, Service: secret}
	a = diagnosticAuth("fixture", cfg)
	data, _ = json.Marshal(a)
	if a.Storage != "keychain" || strings.Contains(string(data), secret) {
		t.Fatalf("keychain redaction: %s", data)
	}
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Source.Auth = &config.SourceAuthConfig{Mode: "file", Path: path}
	a = diagnosticAuth("fixture", cfg)
	if a.Status != "ok" || a.Storage != "file" {
		t.Fatalf("file metadata: %+v", a)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	a = diagnosticAuth("fixture", cfg)
	if a.Status != "error" {
		t.Fatal("accepted public credential permissions")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(t.TempDir(), "cred-link")
	if err := os.Symlink(path, linkPath); err != nil {
		t.Fatal(err)
	}
	cfg.Source.Auth = &config.SourceAuthConfig{Mode: "file", Path: linkPath}
	a = diagnosticAuth("fixture", cfg)
	if a.Status != "error" {
		t.Fatal("accepted symlink credential file")
	}
}
func TestDiagnosticWriterFailure(t *testing.T) {
	if err := writeDiagnostic(diagnosticFailWriter{}, true, diag.DoctorReport{}, ""); err == nil {
		t.Fatal("JSON write failure ignored")
	}
	if err := writeDiagnostic(diagnosticFailWriter{}, false, nil, "text"); err == nil {
		t.Fatal("text write failure ignored")
	}
}

type diagnosticFailWriter struct{}

func (diagnosticFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestDiagnosticSessionsScansEveryCache(t *testing.T) {
	// PID zero means no process lookup or daemon request is needed. Every cache
	// and the openconnect default cache is confined to this test's temp directory.
	root := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", root)
	cfg := config.ProjectConfig{Servers: map[string]config.ServerConfig{}}
	for i, kind := range []string{"sing-box", "xray", "amnezia-awg"} {
		name := []string{"first", "second", "third"}[i]
		cache := filepath.Join(root, name)
		cfg.Servers[name] = config.ServerConfig{CacheDir: cache, Engine: &config.EngineConfig{Type: kind}}
		path := session.CurrentPath(cache)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		body := `{"id":"fixture","pid":0,"interface_name":"utun233","engine":"` + kind + `","config_path":"active.json"}`
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := openconnect.CurrentPath(openconnect.DefaultCacheDir())
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"id":"overlay","pid":0,"interface":"utun4"}`), 0600); err != nil {
		t.Fatal(err)
	}
	reports, err := diagnosticSessions(cfg, true)
	if err != nil || len(reports) != 4 {
		t.Fatalf("scan: %+v %v", reports, err)
	}
	seen := map[string]bool{}
	for _, r := range reports {
		if r.State != "stale" || r.SessionID == "" || r.Interface == "" {
			t.Fatalf("stale cache omitted: %+v", r)
		}
		seen[r.Kind] = true
	}
	for _, kind := range []string{"sing-box", "xray", "amnezia-awg", "openconnect"} {
		if !seen[kind] {
			t.Errorf("missing %s", kind)
		}
	}
	if err := os.WriteFile(session.CurrentPath(cfg.Servers["second"].CacheDir), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	reports, err = diagnosticSessions(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range reports {
		if r.Name == "second" && r.State == "unknown" && r.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatal("corrupt session cache omitted")
	}
}
