package subscription

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"vpn-config/internal/model"
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

func SelectProfile(profiles []model.Profile, selector string) (model.Profile, error) {
	if len(profiles) == 0 {
		return model.Profile{}, errors.New("no profiles available")
	}
	if selector == "" {
		return profiles[0], nil
	}

	needle := strings.ToLower(strings.TrimSpace(selector))
	exactMatches := make([]model.Profile, 0, 1)
	for _, profile := range profiles {
		if lowerExactProfileKey(profile) == needle ||
			strings.ToLower(profile.ID) == needle ||
			strings.ToLower(profile.DisplayName()) == needle {
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
