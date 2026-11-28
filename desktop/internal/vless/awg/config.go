// Package awg implements the userspace AmneziaWG SOCKS5 sidecar.
package awg

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const DefaultMTU = 1280

type RuntimeConfig struct {
	Listen                 string   `json:"listen"`
	MTU                    int      `json:"mtu,omitempty"`
	Addresses              []string `json:"addresses"`
	DNS                    []string `json:"dns,omitempty"`
	Endpoint               string   `json:"endpoint"`
	PrivateKey             string   `json:"private_key"`
	PublicKey              string   `json:"public_key"`
	PresharedKey           string   `json:"preshared_key,omitempty"`
	AllowedIPs             []string `json:"allowed_ips,omitempty"`
	PersistentKeepalive    string   `json:"persistent_keepalive,omitempty"`
	Jc                     int      `json:"jc,omitempty"`
	Jmin                   int      `json:"jmin,omitempty"`
	Jmax                   int      `json:"jmax,omitempty"`
	S1                     int      `json:"s1,omitempty"`
	S2                     int      `json:"s2,omitempty"`
	S3                     int      `json:"s3,omitempty"`
	S4                     int      `json:"s4,omitempty"`
	H1                     string   `json:"h1,omitempty"`
	H2                     string   `json:"h2,omitempty"`
	H3                     string   `json:"h3,omitempty"`
	H4                     string   `json:"h4,omitempty"`
	I1                     string   `json:"i1,omitempty"`
	I2                     string   `json:"i2,omitempty"`
	I3                     string   `json:"i3,omitempty"`
	I4                     string   `json:"i4,omitempty"`
	I5                     string   `json:"i5,omitempty"`
	HeaderProtectionKey    string   `json:"header_protection_key,omitempty"`
	ContentPaddingAddition string   `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         string   `json:"rekey_after_time,omitempty"`
	RekeyTimeout           string   `json:"rekey_timeout,omitempty"`
	RejectAfterTime        string   `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       string   `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   string   `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         string   `json:"random_trailers,omitempty"`
	DisableCookies         string   `json:"disable_cookies,omitempty"`
}

func splitEndpoint(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", "", errors.New("invalid host:port")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", "", errors.New("port must be between 1 and 65535")
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if len(host) > 253 {
			return "", "", errors.New("invalid endpoint host")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", "", errors.New("invalid endpoint host")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return "", "", errors.New("invalid endpoint host")
				}
			}
		}
	}
	return host, port, nil
}

func keyHex(name, value string) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("%s must be a base64 encoded 32-byte key", name)
	}
	return hex.EncodeToString(key), nil
}

func configStrings(c RuntimeConfig) [][2]string {
	return [][2]string{
		{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4},
		{"i1", c.I1}, {"i2", c.I2}, {"i3", c.I3}, {"i4", c.I4}, {"i5", c.I5},
		{"content_padding_addition", c.ContentPaddingAddition}, {"rekey_after_time", c.RekeyAfterTime},
		{"rekey_timeout", c.RekeyTimeout}, {"reject_after_time", c.RejectAfterTime},
		{"keepalive_timeout", c.KeepaliveTimeout}, {"max_handshake_attempts", c.MaxHandshakeAttempts},
		{"random_trailers", c.RandomTrailers}, {"disable_cookies", c.DisableCookies},
	}
}

func ValidateRuntimeConfig(c RuntimeConfig) error {
	host, _, err := splitEndpoint(c.Listen)
	addr, parseErr := netip.ParseAddr(host)
	if err != nil || parseErr != nil || !addr.IsLoopback() {
		return errors.New("listen must be a loopback IP with port 1..65535")
	}
	if _, _, err := splitEndpoint(c.Endpoint); err != nil {
		return errors.New("invalid endpoint host:port")
	}
	if len(c.Addresses) == 0 {
		return errors.New("at least one address is required")
	}
	for _, value := range c.Addresses {
		if _, err := parseAddress(value); err != nil {
			return errors.New("invalid interface address")
		}
	}
	for _, value := range c.DNS {
		if _, err := netip.ParseAddr(value); err != nil {
			return errors.New("invalid DNS address")
		}
	}
	if c.MTU > 65535 || c.MTU > 0 && c.MTU < 576 {
		return errors.New("MTU must be between 576 and 65535")
	}
	for _, key := range [][2]string{{"private_key", c.PrivateKey}, {"public_key", c.PublicKey}, {"preshared_key", c.PresharedKey}, {"header_protection_key", c.HeaderProtectionKey}} {
		if key[1] == "" && (key[0] == "preshared_key" || key[0] == "header_protection_key") {
			continue
		}
		if _, err := keyHex(key[0], key[1]); err != nil {
			return err
		}
	}
	for _, value := range c.AllowedIPs {
		if _, err := netip.ParsePrefix(value); err != nil {
			return errors.New("invalid allowed IP prefix")
		}
	}
	for _, pair := range append(configStrings(c), [2]string{"persistent_keepalive_interval", c.PersistentKeepalive}) {
		if strings.ContainsAny(pair[1], "\r\n\x00") {
			return fmt.Errorf("invalid %s", pair[0])
		}
	}
	for _, n := range []int{c.Jc, c.Jmin, c.Jmax, c.S1, c.S2, c.S3, c.S4} {
		if n < 0 {
			return errors.New("AWG numeric parameters must not be negative")
		}
	}
	return nil
}

func parseAddress(value string) (netip.Addr, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}
	return netip.ParseAddr(value)
}

func WriteRuntimeConfig(path string, cfg RuntimeConfig) error {
	if err := ValidateRuntimeConfig(cfg); err != nil {
		return err
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return errors.New("encode runtime config")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create runtime config directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".awg-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func ReadRuntimeConfig(path string) (RuntimeConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, err
	}
	var cfg RuntimeConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&cfg); err != nil {
		return RuntimeConfig{}, errors.New("invalid runtime config JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return RuntimeConfig{}, errors.New("unexpected trailing runtime config JSON")
	}
	if err := ValidateRuntimeConfig(cfg); err != nil {
		return RuntimeConfig{}, err
	}
	return cfg, nil
}

func BuildUAPI(c RuntimeConfig, resolvedEndpoint string) (string, error) {
	if err := ValidateRuntimeConfig(c); err != nil {
		return "", err
	}
	ep, err := netip.ParseAddrPort(resolvedEndpoint)
	if err != nil || ep.Port() == 0 || strings.ContainsAny(resolvedEndpoint, "\r\n\x00") {
		return "", errors.New("resolved endpoint must be a literal IP:port")
	}
	var b strings.Builder
	emit := func(name, value string) { fmt.Fprintf(&b, "%s=%s\n", name, value) }
	private, _ := keyHex("private_key", c.PrivateKey)
	emit("private_key", private)
	for _, pair := range []struct {
		name  string
		value int
	}{{"jc", c.Jc}, {"jmin", c.Jmin}, {"jmax", c.Jmax}, {"s1", c.S1}, {"s2", c.S2}, {"s3", c.S3}, {"s4", c.S4}} {
		if pair.value != 0 {
			emit(pair.name, strconv.Itoa(pair.value))
		}
	}
	for _, pair := range configStrings(c) {
		if pair[1] != "" {
			emit(pair[0], pair[1])
		}
	}
	if c.HeaderProtectionKey != "" {
		key, _ := keyHex("header_protection_key", c.HeaderProtectionKey)
		emit("header_protection_key", key)
	}
	public, _ := keyHex("public_key", c.PublicKey)
	emit("public_key", public)
	if c.PresharedKey != "" {
		key, _ := keyHex("preshared_key", c.PresharedKey)
		emit("preshared_key", key)
	}
	emit("endpoint", ep.String())
	allowed := c.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}
	for _, value := range allowed {
		prefix, _ := netip.ParsePrefix(value)
		emit("allowed_ip", prefix.Masked().String())
	}
	if c.PersistentKeepalive != "" {
		emit("persistent_keepalive_interval", c.PersistentKeepalive)
	}
	return b.String(), nil
}
