package subscription

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"vpn-config/internal/model"
)

const (
	snapshotFileName = "snapshot.json"
	rawFileName      = "subscription.txt"
)

type CacheSnapshot struct {
	SourceURL     string          `json:"source_url"`
	FetchedAt     time.Time       `json:"fetched_at"`
	PayloadFormat string          `json:"payload_format"`
	Raw           string          `json:"raw"`
	Profiles      []model.Profile `json:"profiles"`
}

func Fetch(ctx context.Context, subscriptionURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vless-tun/0.1")
	req.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.8")

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription request failed with status %s", resp.Status)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func Refresh(ctx context.Context, subscriptionURL, cacheDir string) (CacheSnapshot, error) {
	body, err := Fetch(ctx, subscriptionURL)
	if err != nil {
		return CacheSnapshot{}, err
	}

	normalized, payloadFormat, err := NormalizePayload(body)
	if err != nil {
		return CacheSnapshot{}, err
	}

	profiles, err := ParseProfiles(normalized)
	if err != nil {
		return CacheSnapshot{}, err
	}

	snapshot := CacheSnapshot{
		SourceURL:     subscriptionURL,
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
