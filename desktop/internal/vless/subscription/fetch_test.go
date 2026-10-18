package subscription

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Subscription URLs carry account keys, so a transport failure must report the
// cause without echoing the URL (path token or query key).
func TestFetchErrorDoesNotLeakSubscriptionURL(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer is not a hijacker")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatalf("Hijack() error = %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	const secret = "s3cr3t-account-token"
	_, err := Fetch(context.Background(), server.URL+"/sub/"+secret+"?key="+secret)
	if err == nil {
		t.Fatal("Fetch() error = nil, want transport failure")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("Fetch() error = %q, leaks the subscription URL", err.Error())
	}
	if !strings.Contains(err.Error(), "subscription request failed") || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("Fetch() error = %q, want the transport cause", err.Error())
	}
}

// A malformed URL is rejected without echoing it back.
func TestFetchInvalidURLDoesNotLeakIt(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-account-token"
	_, err := Fetch(context.Background(), "http://bad host/"+secret)
	if err == nil {
		t.Fatal("Fetch() error = nil, want invalid URL error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Fetch() error = %q, leaks the subscription URL", err.Error())
	}
}
