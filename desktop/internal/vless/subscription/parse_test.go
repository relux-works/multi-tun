package subscription

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"multi-tun/desktop/internal/vless/model"
)

func stableAliasProfiles() []model.Profile {
	return []model.Profile{
		{ID: "us-old", Name: "🇺🇸 США | ИИ | Gemini", Host: "203.0.113.10", Port: 443, Network: "tcp"},
		{ID: "de", Name: "🇩🇪 Германия", Host: "203.0.113.20", Port: 443, Network: "grpc"},
	}
}

// The country alias survives a provider display-name rename because identity comes from the flag/country, not the name or hash id.
func TestResolveProfileMatchCountrySurvivesRename(t *testing.T) {
	before := stableAliasProfiles()
	after := append([]model.Profile(nil), before...)
	after[0].Name = "🇺🇸 США"

	for _, profiles := range [][]model.Profile{before, after} {
		resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: &ProfileMatch{Country: "us"}})
		if err != nil {
			t.Fatalf("ResolveProfileWithOptions() error = %v", err)
		}
		if resolution.Profile.ID != "us-old" || !resolution.Matched {
			t.Fatalf("resolution = %+v, want matched us-old", resolution)
		}
	}
}

// The country alias follows a rotated provider id and endpoint while preserving the requested country.
func TestResolveProfileMatchCountryFollowsRotation(t *testing.T) {
	profiles := stableAliasProfiles()
	profiles[0] = model.Profile{ID: "us-new", Name: "United States", Host: "203.0.113.99", Port: 8443, Network: "tcp"}

	resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: &ProfileMatch{Country: "US"}})
	if err != nil {
		t.Fatalf("ResolveProfileWithOptions() error = %v", err)
	}
	if resolution.Profile.ID != "us-new" || resolution.Profile.Endpoint() != "203.0.113.99:8443" {
		t.Fatalf("profile = %+v, want rotated US endpoint", resolution.Profile)
	}
}

// Missing matches fail with the available provider candidates so removal is actionable.
func TestResolveProfileMatchRemovalListsCandidates(t *testing.T) {
	profiles := []model.Profile{{ID: "de", Name: "🇩🇪 Германия", Host: "203.0.113.20", Port: 443}}

	_, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: &ProfileMatch{Country: "US"}})
	if err == nil || !strings.Contains(err.Error(), "Германия (de)") {
		t.Fatalf("error = %v, want listed candidate", err)
	}
}

// pick=only rejects ambiguity with both candidates, while pick=first preserves subscription order as the positive control.
func TestResolveProfileMatchOnlyRejectsAmbiguityAndFirstSelectsOrder(t *testing.T) {
	profiles := []model.Profile{
		{ID: "us-a", Name: "🇺🇸 USA A", Host: "203.0.113.1", Port: 443},
		{ID: "us-b", Name: "🇺🇸 USA B", Host: "203.0.113.2", Port: 443},
	}
	match := &ProfileMatch{Country: "US"}

	_, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: match})
	if err == nil || !strings.Contains(err.Error(), "USA A (us-a)") || !strings.Contains(err.Error(), "USA B (us-b)") {
		t.Fatalf("only error = %v, want both candidates", err)
	}
	resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: match, Pick: "first"})
	if err != nil || resolution.Profile.ID != "us-a" {
		t.Fatalf("first resolution = %+v, error = %v, want us-a", resolution, err)
	}
}

// pick=probe chooses the fastest successful injected TCP dial and never needs a real network.
func TestResolveProfileMatchProbeChoosesFastestReachable(t *testing.T) {
	profiles := []model.Profile{
		{ID: "slow", Name: "🇺🇸 USA slow", Host: "203.0.113.1", Port: 443},
		{ID: "fast", Name: "🇺🇸 USA fast", Host: "203.0.113.2", Port: 443},
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		delay := 40 * time.Millisecond
		if strings.HasPrefix(address, "203.0.113.2:") {
			delay = 5 * time.Millisecond
		}
		select {
		case <-time.After(delay):
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: &ProfileMatch{Country: "US"}, Pick: "probe", DialContext: dial, ProbeBudget: 100 * time.Millisecond})
	if err != nil || resolution.Profile.ID != "fast" {
		t.Fatalf("resolution = %+v, error = %v, want fast", resolution, err)
	}
}

// Equal probe durations choose the earlier subscription entry deterministically across repeated concurrent runs.
func TestResolveProfileMatchProbeBreaksDurationTiesBySubscriptionOrder(t *testing.T) {
	profiles := []model.Profile{
		{ID: "first", Name: "🇺🇸 USA first", Host: "203.0.113.1", Port: 443},
		{ID: "second", Name: "🇺🇸 USA second", Host: "203.0.113.2", Port: 443},
	}
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	fixedNow := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	for run := 0; run < 200; run++ {
		resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{
			Match:       &ProfileMatch{Country: "US"},
			Pick:        "probe",
			DialContext: dial,
			ProbeNow:    func() time.Time { return fixedNow },
		})
		if err != nil || resolution.Profile.ID != "first" {
			t.Fatalf("run %d resolution = %+v, error = %v, want first", run, resolution, err)
		}
	}
}

// pick=probe reports every matched candidate when all injected dials are unreachable.
func TestResolveProfileMatchProbeRejectsAllUnreachable(t *testing.T) {
	profiles := []model.Profile{
		{ID: "a", Name: "🇺🇸 USA A", Host: "203.0.113.1", Port: 443},
		{ID: "b", Name: "🇺🇸 USA B", Host: "203.0.113.2", Port: 443},
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unreachable") }

	_, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: &ProfileMatch{Country: "US"}, Pick: "probe", DialContext: dial, ProbeBudget: 20 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "USA A (a)") || !strings.Contains(err.Error(), "USA B (b)") {
		t.Fatalf("error = %v, want all unreachable candidates", err)
	}
}

// Exclude, RE2 name_pattern, and transport criteria each remove nonconforming entries while retaining a valid positive control.
func TestResolveProfileMatchFiltersExcludePatternAndTransport(t *testing.T) {
	profiles := []model.Profile{
		{ID: "lte", Name: "🇺🇸 USA LTE Gemini", Host: "203.0.113.1", Port: 443, Network: "tcp"},
		{ID: "bridge", Name: "🇺🇸 USA Мост Gemini", Host: "203.0.113.2", Port: 443, Network: "tcp"},
		{ID: "grpc", Name: "🇺🇸 USA Gemini", Host: "203.0.113.3", Port: 443, Network: "grpc"},
		{ID: "tcp", Name: "🇺🇸 USA Gemini", Host: "203.0.113.4", Port: 443, Network: "tcp"},
		{ID: "other", Name: "🇺🇸 USA Claude", Host: "203.0.113.5", Port: 443, Network: "tcp"},
	}
	match := &ProfileMatch{Country: "US", NamePattern: `(?i)gemini`, Exclude: []string{"LTE", "Мост"}, Transport: "tcp"}

	resolution, err := ResolveProfileWithOptions(profiles, SelectOptions{Match: match})
	if err != nil || resolution.Profile.ID != "tcp" {
		t.Fatalf("resolution = %+v, error = %v, want tcp", resolution, err)
	}
}

// Country names require whole-word boundaries, preventing Russia inside Belarussian from becoming RU while a standalone Russia remains valid.
func TestCountryCodeUsesWholeWords(t *testing.T) {
	if got := CountryCode("Belarussian relay"); got != "" {
		t.Fatalf("CountryCode(Belarussian) = %q, want empty", got)
	}
	if got := CountryCode("fast Russia relay"); got != "RU" {
		t.Fatalf("CountryCode(Russia) = %q, want RU", got)
	}
}

// The built-in Russian/English vocabulary covers the supported countries and a flag takes precedence over contradictory text.
func TestCountryCodeMapsSupportedNamesAndPrefersFlag(t *testing.T) {
	tests := map[string]string{
		"США": "US", "United States": "US", "USA": "US",
		"Германия": "DE", "Germany": "DE", "Нидерланды": "NL", "Netherlands": "NL",
		"Финляндия": "FI", "Finland": "FI", "Турция": "TR", "Turkey": "TR",
		"Польша": "PL", "Poland": "PL", "Франция": "FR", "France": "FR",
		"Швеция": "SE", "Sweden": "SE", "Швейцария": "CH", "Switzerland": "CH",
		"Эстония": "EE", "Estonia": "EE", "Литва": "LT", "Lithuania": "LT",
		"Латвия": "LV", "Latvia": "LV", "Норвегия": "NO", "Norway": "NO",
		"Люксембург": "LU", "Luxembourg": "LU", "Россия": "RU", "Russia": "RU",
		"Азербайджан": "AZ", "Azerbaijan": "AZ", "Великобритания": "GB", "United Kingdom": "GB", "UK": "GB",
		"Казахстан": "KZ", "Kazakhstan": "KZ", "Япония": "JP", "Japan": "JP",
		"Сингапур": "SG", "Singapore": "SG",
	}
	for name, want := range tests {
		if got := CountryCode("fast " + name + " relay"); got != want {
			t.Errorf("CountryCode(%q) = %q, want %q", name, got, want)
		}
	}
	if got := CountryCode("🇺🇸 Germany"); got != "US" {
		t.Fatalf("CountryCode(flag priority) = %q, want US", got)
	}
}

func TestNormalizePayloadPlain(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	normalized, payloadFormat, err := NormalizePayload(raw)
	if err != nil {
		t.Fatalf("NormalizePayload returned error: %v", err)
	}
	if payloadFormat != "plain" {
		t.Fatalf("payloadFormat = %q, want plain", payloadFormat)
	}
	if normalized == "" {
		t.Fatal("normalized payload is empty")
	}
}

func TestNormalizePayloadBase64(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.base64.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	normalized, payloadFormat, err := NormalizePayload(raw)
	if err != nil {
		t.Fatalf("NormalizePayload returned error: %v", err)
	}
	if payloadFormat != "base64" {
		t.Fatalf("payloadFormat = %q, want base64", payloadFormat)
	}
	if normalized == "" {
		t.Fatal("normalized payload is empty")
	}
}

func TestParseProfiles(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}
	if got, want := len(profiles), 2; got != want {
		t.Fatalf("len(profiles) = %d, want %d", got, want)
	}

	first := profiles[0]
	if got, want := first.Host, "203.0.113.77"; got != want {
		t.Fatalf("first.Host = %q, want %q", got, want)
	}
	if got, want := first.Network, "grpc"; got != want {
		t.Fatalf("first.Network = %q, want %q", got, want)
	}
	if got, want := first.Security, "reality"; got != want {
		t.Fatalf("first.Security = %q, want %q", got, want)
	}
	if got, want := first.ServiceName, "grpcservice"; got != want {
		t.Fatalf("first.ServiceName = %q, want %q", got, want)
	}
}

func TestParseVLESSURIExtractsPostQuantumAndSpiderXParams(t *testing.T) {
	t.Parallel()

	profile, err := ParseVLESSURI("vless://00000000-0000-0000-0000-000000000000@example.com:443?type=tcp&security=reality&encryption=mlkem768x25519plus.native.0rtt.example&spx=%2Fabc123&flow=xtls-rprx-vision#pq")
	if err != nil {
		t.Fatalf("ParseVLESSURI returned error: %v", err)
	}
	if got, want := profile.Encryption, "mlkem768x25519plus.native.0rtt.example"; got != want {
		t.Fatalf("Encryption = %q, want %q", got, want)
	}
	if got, want := profile.SpiderX, "/abc123"; got != want {
		t.Fatalf("SpiderX = %q, want %q", got, want)
	}
	if got, want := profile.Flow, "xtls-rprx-vision"; got != want {
		t.Fatalf("Flow = %q, want %q", got, want)
	}
}

func TestSelectProfile(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	profiles, err := ParseProfiles(string(raw))
	if err != nil {
		t.Fatalf("ParseProfiles returned error: %v", err)
	}

	profile, err := SelectProfile(profiles, "backup")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.Port, 8444; got != want {
		t.Fatalf("profile.Port = %d, want %d", got, want)
	}
}

func TestSelectProfileEmptySelectorRequiresExplicitChoiceForMultiProfile(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "grpc",
			Name:    "provider grpc default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "tcp",
			Name:    "provider tcp backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	_, err := SelectProfile(profiles, "")
	if err == nil {
		t.Fatal("SelectProfile returned nil error")
	}
	if !strings.Contains(err.Error(), "configure selector or transport") {
		t.Fatalf("SelectProfile error = %q, want selector or transport guidance", err)
	}
}

func TestSelectProfileWhitespaceSelectorRequiresExplicitChoiceForMultiProfile(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{ID: "grpc", Host: "example.com", Port: 8443, Network: "grpc"},
		{ID: "tcp", Host: "example.com", Port: 8444, Network: "tcp"},
	}

	_, err := SelectProfile(profiles, " \t\n ")
	if err == nil {
		t.Fatal("SelectProfile returned nil error")
	}
	if !strings.Contains(err.Error(), "configure selector or transport") {
		t.Fatalf("SelectProfile error = %q, want selector or transport guidance", err)
	}
}

func TestSelectProfileTransportCanChooseTCP(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "grpc",
			Name:    "provider grpc default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "tcp",
			Name:    "provider tcp backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	profile, err := SelectProfileWithOptions(profiles, SelectOptions{Transport: "tcp"})
	if err != nil {
		t.Fatalf("SelectProfileWithOptions returned error: %v", err)
	}
	if got, want := profile.ID, "tcp"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

func TestSelectProfileTransportCanChooseGRPC(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "austria-grpc",
			Name:    "provider default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "austria-tcp",
			Name:    "provider backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	profile, err := SelectProfileWithOptions(profiles, SelectOptions{Transport: "grpc"})
	if err != nil {
		t.Fatalf("SelectProfileWithOptions returned error: %v", err)
	}
	if got, want := profile.ID, "austria-grpc"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

func TestSelectProfileTransportRequiresSelectorWhenAmbiguous(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{ID: "tcp-a", Host: "a.example.com", Port: 8444, Network: "tcp"},
		{ID: "tcp-b", Host: "b.example.com", Port: 8444, Network: "tcp"},
	}

	_, err := SelectProfileWithOptions(profiles, SelectOptions{Transport: "tcp"})
	if err == nil {
		t.Fatal("SelectProfileWithOptions returned nil error")
	}
	if !strings.Contains(err.Error(), `transport "tcp" matched multiple profiles`) {
		t.Fatalf("SelectProfileWithOptions error = %q, want ambiguous transport", err)
	}
}

func TestSelectProfileExplicitSelectorCanChooseTransportName(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{
			ID:      "austria-grpc",
			Name:    "provider default",
			Host:    "example.com",
			Port:    8443,
			Network: "grpc",
		},
		{
			ID:      "austria-tcp",
			Name:    "provider backup",
			Host:    "example.com",
			Port:    8444,
			Network: "tcp",
		},
	}

	profile, err := SelectProfile(profiles, "grpc")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.ID, "austria-grpc"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

func TestSelectProfileSingleProfileDoesNotRequireSelector(t *testing.T) {
	t.Parallel()

	profiles := []model.Profile{
		{ID: "only", Host: "example.com", Port: 8444, Network: "tcp"},
	}

	profile, err := SelectProfile(profiles, "")
	if err != nil {
		t.Fatalf("SelectProfile returned error: %v", err)
	}
	if got, want := profile.ID, "only"; got != want {
		t.Fatalf("profile.ID = %q, want %q", got, want)
	}
}

// Proves: non-vless entries in a mixed subscription are skipped while vless entries
// still parse, a malformed vless entry still fails, and a payload with no vless
// entries is still an error (synthetic URIs only).
func TestParseProfilesSkipsUnsupportedSchemes(t *testing.T) {
	good := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#ok"
	mixed := "hysteria2://pw@example.com:443#hy2\n" + good + "\n"

	profiles, err := ParseProfiles(mixed)
	if err != nil {
		t.Fatalf("ParseProfiles(mixed) error = %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profiles = %d, want 1 (hysteria2 skipped)", len(profiles))
	}

	if _, err := ParseProfiles("hysteria2://pw@example.com:443#hy2\n"); err == nil {
		t.Fatal("ParseProfiles(only hysteria2) = nil error, want no-profiles error")
	}
	if _, err := ParseProfiles("vless://nouser.example.com:443#bad\n"); err == nil {
		t.Fatal("ParseProfiles(malformed vless) = nil error, want error")
	}
}
