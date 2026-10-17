package subscription

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"multi-tun/desktop/internal/vless/model"
)

const (
	snapshotFileName = "snapshot.json"
	rawFileName      = "subscription.txt"
)

type CacheSnapshot struct {
	SourceURL     string          `json:"source_url"`
	SourceMode    string          `json:"source_mode,omitempty"`
	FetchedAt     time.Time       `json:"fetched_at"`
	PayloadFormat string          `json:"payload_format"`
	Raw           string          `json:"raw"`
	Profiles      []model.Profile `json:"profiles"`
}

// TransientFetchError marks a subscription fetch failure that may succeed on a
// later attempt (transport error, HTTP 5xx or 429). Only these allow callers to
// fall back to a cached snapshot; a 4xx means the subscription itself was
// refused and must not be papered over with stale credentials.
type TransientFetchError struct {
	Err error
}

func (e *TransientFetchError) Error() string { return e.Err.Error() }

func (e *TransientFetchError) Unwrap() error { return e.Err }

// IsTransientFetchError reports whether err wraps a TransientFetchError.
func IsTransientFetchError(err error) bool {
	var transient *TransientFetchError
	return errors.As(err, &transient)
}

// FetchOptions customizes how a subscription is requested. Some providers only
// serve real profiles to specific client User-Agents or device headers.
type FetchOptions struct {
	UserAgent string
	Headers   map[string]string
}

func Fetch(ctx context.Context, subscriptionURL string) ([]byte, error) {
	return FetchWithOptions(ctx, subscriptionURL, FetchOptions{})
}

func FetchWithOptions(ctx context.Context, subscriptionURL string, options FetchOptions) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, nil)
	if err != nil {
		return nil, errors.New("invalid subscription URL")
	}
	userAgent := strings.TrimSpace(options.UserAgent)
	if userAgent == "" {
		userAgent = "vless-tun/0.1"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.8")
	for name, value := range options.Headers {
		if name = strings.TrimSpace(name); name != "" {
			req.Header.Set(name, value)
		}
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		// *url.Error embeds the full request URL, and subscription URLs carry
		// account keys; keep only the transport cause.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, &TransientFetchError{Err: fmt.Errorf("subscription request failed: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("subscription request failed with status %s", resp.Status)
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			return nil, &TransientFetchError{Err: err}
		}
		return nil, err
	}

	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func Refresh(ctx context.Context, sourceMode, sourceURL, cacheDir string) (CacheSnapshot, error) {
	return RefreshWithOptions(ctx, sourceMode, sourceURL, cacheDir, FetchOptions{})
}

func RefreshWithOptions(ctx context.Context, sourceMode, sourceURL, cacheDir string, options FetchOptions) (CacheSnapshot, error) {
	normalized, payloadFormat, err := resolveSourcePayload(ctx, sourceMode, sourceURL, options)
	if err != nil {
		return CacheSnapshot{}, err
	}

	profiles, err := ParseProfiles(normalized)
	if err != nil {
		return CacheSnapshot{}, err
	}

	snapshot := CacheSnapshot{
		SourceURL:     sourceURL,
		SourceMode:    sourceMode,
		FetchedAt:     time.Now().UTC(),
		PayloadFormat: payloadFormat,
		Raw:           normalized,
		Profiles:      profiles,
	}

	if err := SaveCache(cacheDir, snapshot); err != nil {
		return CacheSnapshot{}, err
	}

	return snapshot, nil
}

func resolveSourcePayload(ctx context.Context, sourceMode, sourceURL string, options FetchOptions) (string, string, error) {
	switch sourceMode {
	case "direct":
		normalized, _, err := NormalizePayload([]byte(sourceURL))
		if err != nil {
			return "", "", err
		}
		return normalized, "direct", nil
	case "", "proxy":
		body, err := FetchWithOptions(ctx, sourceURL, options)
		if err != nil {
			return "", "", err
		}
		return NormalizePayload(body)
	default:
		return "", "", fmt.Errorf("unsupported source mode %q", sourceMode)
	}
}

func SaveCache(cacheDir string, snapshot CacheSnapshot) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	rawPath := filepath.Join(cacheDir, rawFileName)
	if err := os.WriteFile(rawPath, []byte(snapshot.Raw), 0o600); err != nil {
		return err
	}

	jsonPath := filepath.Join(cacheDir, snapshotFileName)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(jsonPath, data, 0o600)
}

func LoadCache(cacheDir string) (CacheSnapshot, error) {
	path := filepath.Join(cacheDir, snapshotFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return CacheSnapshot{}, err
	}

	var snapshot CacheSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return CacheSnapshot{}, err
	}
	return snapshot, nil
}
