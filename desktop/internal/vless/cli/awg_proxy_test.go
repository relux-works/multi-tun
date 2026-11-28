package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/awg"
	"multi-tun/desktop/internal/vless/config"
)

func syntheticAWGKey(n byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32))
}

func syntheticCLIAWG() *amnezia.AWGConfig {
	return &amnezia.AWGConfig{
		Name: "USA East", CountryCode: "US", EndpointHost: "203.0.113.9", EndpointPort: 51820,
		PrivateKey: syntheticAWGKey(1), PublicKey: syntheticAWGKey(2), PresharedKey: syntheticAWGKey(3),
		Address: []string{"192.0.2.2/32"}, DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		MTU: 1400, PersistentKeepalive: 25, PersistentKeepaliveRaw: "25-35",
		Jc: 4, Jmin: 40, Jmax: 70, S1: 10, S2: 20, S3: 30, S4: 40,
		H1: "100-200", H2: "300", H3: "400", H4: "500",
		I1: "<b 0x01>", I2: "<b 0x02>", I3: "<b 0x03>", I4: "<b 0x04>", I5: "<b 0x05>",
		HeaderProtectionKey: syntheticAWGKey(4), ContentPaddingAddition: "10-20",
		RekeyAfterTime: "120-140", RekeyTimeout: "5-7", RejectAfterTime: "180-200",
		KeepaliveTimeout: "10-15", MaxHandshakeAttempts: "18-20", RandomTrailers: "true", DisableCookies: "false",
	}
}

func TestBuildAWGRuntimeConfig(t *testing.T) {
	c := syntheticCLIAWG()
	got, err := buildAWGRuntimeConfig(config.ProjectConfig{}, c)
	if err != nil {
		t.Fatal(err)
	}
	want := awg.RuntimeConfig{
		Listen: "127.0.0.1:20809", MTU: 1400, Endpoint: "203.0.113.9:51820",
		PrivateKey: syntheticAWGKey(1), PublicKey: syntheticAWGKey(2), PresharedKey: syntheticAWGKey(3),
		Addresses: []string{"192.0.2.2/32"}, DNS: []string{"1.1.1.1"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		PersistentKeepalive: "25-35", Jc: 4, Jmin: 40, Jmax: 70, S1: 10, S2: 20, S3: 30, S4: 40,
		H1: "100-200", H2: "300", H3: "400", H4: "500",
		I1: "<b 0x01>", I2: "<b 0x02>", I3: "<b 0x03>", I4: "<b 0x04>", I5: "<b 0x05>",
		HeaderProtectionKey: syntheticAWGKey(4), ContentPaddingAddition: "10-20",
		RekeyAfterTime: "120-140", RekeyTimeout: "5-7", RejectAfterTime: "180-200",
		KeepaliveTimeout: "10-15", MaxHandshakeAttempts: "18-20", RandomTrailers: "true", DisableCookies: "false",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("runtime mapping lost AWG fields")
	}
	c.MTU, c.PersistentKeepaliveRaw, c.EndpointHost = 0, "", "::1"
	got, err = buildAWGRuntimeConfig(config.ProjectConfig{}, c)
	if err != nil || got.MTU != 1280 || got.PersistentKeepalive != "25" || got.Endpoint != "[::1]:51820" {
		t.Fatal("defaults, integer keepalive or IPv6 endpoint lost")
	}
	c.PersistentKeepalive = 0
	got, err = buildAWGRuntimeConfig(config.ProjectConfig{}, c)
	if err != nil || got.PersistentKeepalive != "" {
		t.Fatal("absent keepalive not preserved")
	}
	c.PrivateKey = "synthetic-malformed-private-key"
	if _, err := buildAWGRuntimeConfig(config.ProjectConfig{}, c); err == nil || strings.Contains(err.Error(), c.PrivateKey) {
		t.Fatal("invalid runtime key not refused safely")
	}
	if _, err := buildAWGRuntimeConfig(config.ProjectConfig{}, nil); !amnezia.IsRefusalCode(err, amnezia.CodeKeyInvalid) {
		t.Fatal("missing runtime configuration accepted")
	}
}

func TestAWGProxyFlagsAndDelegation(t *testing.T) {
	cfg, err := buildAWGRuntimeConfig(config.ProjectConfig{}, syntheticCLIAWG())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "awg.json")
	if err := awg.WriteRuntimeConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"private_key":"synthetic-secret","unexpected":"synthetic-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	old := runAWGProxyFunc
	t.Cleanup(func() { runAWGProxyFunc = old })
	for _, tc := range []struct {
		name        string
		args        []string
		want, calls int
		fail        bool
	}{
		{"missing", nil, 2, 0, false},
		{"missing-value", []string{"-c"}, 2, 0, false},
		{"empty", []string{"-c", ""}, 2, 0, false},
		{"unknown", []string{"--synthetic-secret"}, 2, 0, false},
		{"extra", []string{"-c", path, "synthetic-secret"}, 2, 0, false},
		{"missing-file", []string{"-c", "synthetic-secret"}, 1, 0, false},
		{"malformed", []string{"-c", bad}, 1, 0, false},
		{"clean-shutdown", []string{"-c", path}, 0, 1, false},
		{"runtime-error", []string{"-c", path}, 1, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			runAWGProxyFunc = func(ctx context.Context, actual awg.RuntimeConfig, logs io.Writer) error {
				calls++
				if ctx.Err() != nil || ctx.Done() == nil || !reflect.DeepEqual(actual, cfg) || logs == nil {
					t.Fatal("sidecar delegation lost context, config or log writer")
				}
				if tc.fail {
					return errors.New("synthetic-secret")
				}
				return nil
			}
			runAmneziaCLI(t, tc.want, []string{"synthetic-secret", cfg.PrivateKey, cfg.PresharedKey, cfg.HeaderProtectionKey}, append([]string{"_awg-proxy"}, tc.args...)...)
			if calls != tc.calls {
				t.Fatalf("proxy calls = %d, want %d", calls, tc.calls)
			}
		})
	}
}

func TestAWGSidecarExecutable(t *testing.T) {
	path, err := defaultAWGSidecarExecutable()
	if err != nil || !filepath.IsAbs(path) {
		t.Fatal("sidecar executable not resolved")
	}
	if _, err := exec.LookPath(path); err != nil {
		t.Fatal("resolved sidecar cannot pass executable preflight")
	}
}
