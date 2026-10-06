package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefreshSupportsDirectSourceMode(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	sourceURL := "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&type=tcp#demo"

	snapshot, err := Refresh(context.Background(), "direct", sourceURL, cacheDir)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got, want := snapshot.SourceMode, "direct"; got != want {
		t.Fatalf("snapshot.SourceMode = %q, want %q", got, want)
	}
	if got, want := snapshot.SourceURL, sourceURL; got != want {
		t.Fatalf("snapshot.SourceURL = %q, want %q", got, want)
	}
	if got, want := snapshot.PayloadFormat, "direct"; got != want {
		t.Fatalf("snapshot.PayloadFormat = %q, want %q", got, want)
	}
	if len(snapshot.Profiles) != 1 {
		t.Fatalf("len(snapshot.Profiles) = %d, want 1", len(snapshot.Profiles))
	}
	if got, want := snapshot.Profiles[0].Host, "example.com"; got != want {
		t.Fatalf("snapshot.Profiles[0].Host = %q, want %q", got, want)
	}
}

// Proves: configured User-Agent and extra headers reach the subscription server,
// and without options the legacy "vless-tun/0.1" User-Agent is still sent
// (httptest server only; does not cover real provider behavior).
func TestFetchWithOptionsSendsConfiguredHeaders(t *testing.T) {
	var gotUA, gotHWID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotHWID = r.Header.Get("X-Hwid")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	if _, err := FetchWithOptions(context.Background(), server.URL, FetchOptions{
		UserAgent: "v2RayTun/5.0",
		Headers:   map[string]string{"x-hwid": "abc123"},
	}); err != nil {
		t.Fatalf("FetchWithOptions() error = %v", err)
	}
	if gotUA != "v2RayTun/5.0" || gotHWID != "abc123" {
		t.Fatalf("headers = UA %q HWID %q, want v2RayTun/5.0 and abc123", gotUA, gotHWID)
	}

	if _, err := Fetch(context.Background(), server.URL); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if gotUA != "vless-tun/0.1" || gotHWID != "" {
		t.Fatalf("default fetch leaked options: UA %q HWID %q", gotUA, gotHWID)
	}
}
