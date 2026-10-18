package subscription

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"multi-tun/desktop/internal/vless/model"
)

func NormalizePayload(body []byte) (string, string, error) {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return "", "", errors.New("empty subscription payload")
	}

	if strings.Contains(trimmed, "://") {
		return trimmed, "plain", nil
	}

	compact := strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "").Replace(trimmed)
	for _, decoder := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		decoded, err := decoder(compact)
		if err != nil {
			continue
		}
		normalized := strings.TrimSpace(string(decoded))
		if strings.Contains(normalized, "://") {
			return normalized, "base64", nil
		}
	}

	return "", "", errors.New("unsupported subscription payload format")
}

func ParseProfiles(payload string) ([]model.Profile, error) {
	lines := strings.Split(payload, "\n")
	profiles := make([]model.Profile, 0, len(lines))
	for _, line := range lines {
		candidate := strings.TrimSpace(line)
		if candidate == "" {
			continue
		}
		if strings.HasPrefix(candidate, "#") || strings.HasPrefix(candidate, "//") {
			continue
		}

		// Mixed subscriptions may carry other protocols (hysteria2, trojan, ...)
		// that this tool cannot render; skip them instead of failing the whole payload.
		if scheme, _, found := strings.Cut(candidate, "://"); found && !strings.EqualFold(scheme, "vless") {
			continue
		}

		profile, err := ParseVLESSURI(candidate)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}

	if len(profiles) == 0 {
		return nil, errors.New("no profiles found in subscription payload")
	}

	return profiles, nil
}

func ParseVLESSURI(raw string) (model.Profile, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return model.Profile{}, err
	}
	if parsed.Scheme != "vless" {
		return model.Profile{}, fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.User == nil {
		return model.Profile{}, errors.New("missing user info in vless uri")
	}

	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		return model.Profile{}, fmt.Errorf("invalid port in vless uri: %w", err)
	}

	queryValues := parsed.Query()
	query := make(map[string]string, len(queryValues))
	for key := range queryValues {
		query[key] = queryValues.Get(key)
	}

	name := parsed.Fragment
	if decoded, err := url.QueryUnescape(name); err == nil && decoded != "" {
		name = decoded
	}

	profile := model.Profile{
		ID:          profileID(raw),
		Name:        name,
		URI:         raw,
		Protocol:    "vless",
		UUID:        parsed.User.Username(),
		Host:        parsed.Hostname(),
		Port:        port,
		Security:    queryValues.Get("security"),
		Network:     firstNonEmpty(queryValues.Get("type"), queryValues.Get("network"), "tcp"),
		ServiceName: firstNonEmpty(queryValues.Get("serviceName"), queryValues.Get("service_name")),
		Authority:   queryValues.Get("authority"),
		SNI:         firstNonEmpty(queryValues.Get("sni"), queryValues.Get("serverName")),
		Fingerprint: firstNonEmpty(queryValues.Get("fp"), queryValues.Get("fingerprint")),
		PublicKey:   firstNonEmpty(queryValues.Get("pbk"), queryValues.Get("publicKey")),
		ShortID:     firstNonEmpty(queryValues.Get("sid"), queryValues.Get("shortId")),
		Flow:        queryValues.Get("flow"),
		Encryption:  queryValues.Get("encryption"),
		SpiderX:     queryValues.Get("spx"),
		Query:       query,
	}

	if profile.Host == "" {
		return model.Profile{}, errors.New("missing host in vless uri")
	}
	if profile.UUID == "" {
		return model.Profile{}, errors.New("missing uuid in vless uri")
	}

	return profile, nil
}

type SelectOptions struct {
	Selector    string
	Transport   string
	Match       *ProfileMatch
	Pick        string
	DialContext func(context.Context, string, string) (net.Conn, error)
	ProbeBudget time.Duration
}

type ProfileMatch struct {
	Country     string
	NamePattern string
	Exclude     []string
	Transport   string
}

type ProfileResolution struct {
	Profile model.Profile
	Reason  string
	Matched bool
}

func SelectProfile(profiles []model.Profile, selector string) (model.Profile, error) {
	return SelectProfileWithOptions(profiles, SelectOptions{Selector: selector})
}

func SelectProfileWithOptions(profiles []model.Profile, options SelectOptions) (model.Profile, error) {
	resolution, err := ResolveProfileWithOptions(profiles, options)
	return resolution.Profile, err
}

func ResolveProfileWithOptions(profiles []model.Profile, options SelectOptions) (ProfileResolution, error) {
	if len(profiles) == 0 {
		return ProfileResolution{}, errors.New("no profiles available")
	}
	if options.Match != nil {
		return resolveMatchedProfile(profiles, options)
	}

	selector := strings.TrimSpace(options.Selector)
	transport := normalizeProfileTransport(options.Transport)
	candidates := profiles
	if transport != "" {
		candidates = filterProfilesByTransport(profiles, transport)
		if len(candidates) == 0 {
			return ProfileResolution{}, fmt.Errorf("profile transport %q did not match any profile", strings.TrimSpace(options.Transport))
		}
	}

	if selector == "" {
		if len(candidates) == 1 {
			return ProfileResolution{Profile: candidates[0]}, nil
		}
		if transport != "" {
			return ProfileResolution{}, fmt.Errorf("profile transport %q matched multiple profiles; configure selector", strings.TrimSpace(options.Transport))
		}
		return ProfileResolution{}, errors.New("multiple subscription profiles available; configure selector or transport")
	}

	profile, err := selectProfileFromCandidates(candidates, selector)
	return ProfileResolution{Profile: profile}, err
}

func resolveMatchedProfile(profiles []model.Profile, options SelectOptions) (ProfileResolution, error) {
	match := options.Match
	pattern, err := compileOptionalPattern(match.NamePattern)
	if err != nil {
		return ProfileResolution{}, fmt.Errorf("invalid match name_pattern: %w", err)
	}

	candidates := make([]model.Profile, 0, len(profiles))
	for _, profile := range profiles {
		if profileMatches(profile, *match, options.Transport, pattern) {
			candidates = append(candidates, profile)
		}
	}
	criteria := describeMatch(*match, options.Transport)
	if len(candidates) == 0 {
		return ProfileResolution{}, fmt.Errorf("match %s found no profiles; subscription candidates: %s", criteria, describeCandidates(profiles))
	}

	pick := strings.ToLower(strings.TrimSpace(options.Pick))
	if pick == "" {
		pick = "only"
	}
	switch pick {
	case "only":
		if len(candidates) != 1 {
			return ProfileResolution{}, fmt.Errorf("match %s requires exactly one profile but found %d: %s", criteria, len(candidates), describeCandidates(candidates))
		}
		return ProfileResolution{Profile: candidates[0], Reason: "match " + criteria + "; pick=only", Matched: true}, nil
	case "first":
		return ProfileResolution{Profile: candidates[0], Reason: "match " + criteria + "; pick=first", Matched: true}, nil
	case "probe":
		profile, err := probeProfiles(candidates, options)
		if err != nil {
			return ProfileResolution{}, fmt.Errorf("match %s; pick=probe: %w; candidates: %s", criteria, err, describeCandidates(candidates))
		}
		return ProfileResolution{Profile: profile, Reason: "match " + criteria + "; pick=probe fastest reachable", Matched: true}, nil
	default:
		return ProfileResolution{}, fmt.Errorf("unsupported pick %q", options.Pick)
	}
}

func compileOptionalPattern(value string) (*regexp.Regexp, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return regexp.Compile(value)
}

func profileMatches(profile model.Profile, match ProfileMatch, selectionTransport string, pattern *regexp.Regexp) bool {
	if country := strings.ToUpper(strings.TrimSpace(match.Country)); country != "" && CountryCode(profile.DisplayName()) != country {
		return false
	}
	if pattern != nil && !pattern.MatchString(profile.DisplayName()) {
		return false
	}
	lowerName := strings.ToLower(profile.DisplayName())
	for _, excluded := range match.Exclude {
		if excluded = strings.ToLower(strings.TrimSpace(excluded)); excluded != "" && strings.Contains(lowerName, excluded) {
			return false
		}
	}
	profileNetwork := profileTransport(profile)
	if transport := strings.TrimSpace(match.Transport); transport != "" && profileNetwork != normalizeProfileTransport(transport) {
		return false
	}
	if transport := strings.TrimSpace(selectionTransport); transport != "" && profileNetwork != normalizeProfileTransport(transport) {
		return false
	}
	return true
}

func probeProfiles(candidates []model.Profile, options SelectOptions) (model.Profile, error) {
	dial := options.DialContext
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	budget := options.ProbeBudget
	if budget <= 0 {
		budget = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	type result struct {
		profile model.Profile
		err     error
	}
	results := make(chan result, len(candidates))
	for _, candidate := range candidates {
		candidate := candidate
		go func() {
			address := net.JoinHostPort(candidate.Host, strconv.Itoa(candidate.Port))
			connection, err := dial(ctx, "tcp", address)
			if connection != nil {
				_ = connection.Close()
			}
			results <- result{profile: candidate, err: err}
		}()
	}

	for range candidates {
		select {
		case result := <-results:
			if result.err == nil {
				cancel()
				return result.profile, nil
			}
		case <-ctx.Done():
			return model.Profile{}, errors.New("no candidate was reachable within 2s total budget")
		}
	}
	return model.Profile{}, errors.New("no candidate was reachable within 2s total budget")
}

func describeMatch(match ProfileMatch, selectionTransport string) string {
	parts := make([]string, 0, 4)
	if country := strings.ToUpper(strings.TrimSpace(match.Country)); country != "" {
		parts = append(parts, "country="+country)
	}
	if pattern := strings.TrimSpace(match.NamePattern); pattern != "" {
		parts = append(parts, "name_pattern="+pattern)
	}
	if excludes := nonEmptyValues(match.Exclude); len(excludes) > 0 {
		parts = append(parts, "exclude="+strings.Join(excludes, ","))
	}
	if transport := strings.TrimSpace(match.Transport); transport != "" {
		parts = append(parts, "match.transport="+normalizeProfileTransport(transport))
	}
	if transport := strings.TrimSpace(selectionTransport); transport != "" {
		parts = append(parts, "transport="+normalizeProfileTransport(transport))
	}
	return strings.Join(parts, ",")
}

func describeCandidates(profiles []model.Profile) string {
	values := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		values = append(values, fmt.Sprintf("%s (%s)", profile.DisplayName(), profile.ID))
	}
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "; ")
}

func nonEmptyValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

var countryNames = []struct {
	name string
	code string
}{
	{"united states", "US"}, {"сша", "US"}, {"usa", "US"},
	{"германия", "DE"}, {"germany", "DE"},
	{"нидерланды", "NL"}, {"netherlands", "NL"},
	{"финляндия", "FI"}, {"finland", "FI"},
	{"турция", "TR"}, {"turkey", "TR"},
	{"польша", "PL"}, {"poland", "PL"},
	{"франция", "FR"}, {"france", "FR"},
	{"швеция", "SE"}, {"sweden", "SE"},
	{"швейцария", "CH"}, {"switzerland", "CH"},
	{"эстония", "EE"}, {"estonia", "EE"},
	{"литва", "LT"}, {"lithuania", "LT"},
	{"латвия", "LV"}, {"latvia", "LV"},
	{"норвегия", "NO"}, {"norway", "NO"},
	{"люксембург", "LU"}, {"luxembourg", "LU"},
	{"россия", "RU"}, {"russia", "RU"},
	{"азербайджан", "AZ"}, {"azerbaijan", "AZ"},
	{"великобритания", "GB"}, {"united kingdom", "GB"}, {"uk", "GB"},
	{"казахстан", "KZ"}, {"kazakhstan", "KZ"},
	{"япония", "JP"}, {"japan", "JP"},
	{"сингапур", "SG"}, {"singapore", "SG"},
}

// CountryCode derives country identity only from a flag or whole country-name words.
func CountryCode(displayName string) string {
	runes := []rune(displayName)
	for index := 0; index+1 < len(runes); index++ {
		if regionalIndicator(runes[index]) && regionalIndicator(runes[index+1]) {
			return string([]byte{'A' + byte(runes[index]-0x1F1E6), 'A' + byte(runes[index+1]-0x1F1E6)})
		}
	}

	lower := []rune(strings.ToLower(displayName))
	for _, entry := range countryNames {
		if containsWholePhrase(lower, []rune(entry.name)) {
			return entry.code
		}
	}
	return ""
}

func regionalIndicator(value rune) bool {
	return value >= 0x1F1E6 && value <= 0x1F1FF
}

func containsWholePhrase(value, phrase []rune) bool {
	if len(phrase) == 0 || len(value) < len(phrase) {
		return false
	}
	for start := 0; start+len(phrase) <= len(value); start++ {
		if string(value[start:start+len(phrase)]) != string(phrase) {
			continue
		}
		beforeOK := start == 0 || !isWordRune(value[start-1])
		after := start + len(phrase)
		afterOK := after == len(value) || !isWordRune(value[after])
		if beforeOK && afterOK {
			return true
		}
	}
	return false
}

func isWordRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) || value == '_'
}

func selectProfileFromCandidates(profiles []model.Profile, selector string) (model.Profile, error) {
	needle := strings.ToLower(selector)
	exactMatches := make([]model.Profile, 0, 1)
	for _, profile := range profiles {
		if lowerExactProfileKey(profile) == needle ||
			strings.ToLower(profile.ID) == needle ||
			strings.ToLower(profile.DisplayName()) == needle ||
			profileTransport(profile) == needle {
			exactMatches = append(exactMatches, profile)
		}
	}
	if len(exactMatches) == 1 {
		return exactMatches[0], nil
	}
	if len(exactMatches) > 1 {
		return model.Profile{}, fmt.Errorf("profile selector %q is ambiguous", selector)
	}

	containsMatches := make([]model.Profile, 0, 1)
	for _, profile := range profiles {
		if strings.Contains(strings.ToLower(profile.DisplayName()), needle) ||
			strings.Contains(strings.ToLower(profile.Endpoint()), needle) ||
			strings.Contains(strings.ToLower(profile.ID), needle) {
			containsMatches = append(containsMatches, profile)
		}
	}
	if len(containsMatches) == 1 {
		return containsMatches[0], nil
	}
	if len(containsMatches) > 1 {
		return model.Profile{}, fmt.Errorf("profile selector %q matched multiple profiles", selector)
	}

	return model.Profile{}, fmt.Errorf("profile selector %q did not match any profile", selector)
}

func filterProfilesByTransport(profiles []model.Profile, transport string) []model.Profile {
	matches := make([]model.Profile, 0, len(profiles))
	for _, profile := range profiles {
		if profileTransport(profile) == transport {
			matches = append(matches, profile)
		}
	}
	return matches
}

func profileTransport(profile model.Profile) string {
	transport := normalizeProfileTransport(profile.Network)
	if transport == "" {
		return "tcp"
	}
	return transport
}

func normalizeProfileTransport(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func lowerExactProfileKey(profile model.Profile) string {
	return strings.ToLower(profile.Endpoint())
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func profileID(raw string) string {
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:6])
}
