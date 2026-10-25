package vpncore

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func maintenanceRequest(t *testing.T, d *serviceDaemon, request Request) Response {
	t.Helper()
	response, _ := maintenanceEncodedRequest(t, d, request)
	return response
}

func maintenanceEncodedRequest(t *testing.T, d *serviceDaemon, request Request) (Response, []byte) {
	t.Helper()
	server, client := unixSocketPair(t)
	id := d.requests.enqueue()
	done := make(chan struct{})
	go func() { d.handleConn(server, id); close(done) }()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var rights []byte
	if request.Action == "singbox.start" {
		log := openSecurityTestLog(t, "drain.log")
		rights = unix.UnixRights(int(log.Fd()))
	}
	writeUnixPayload(t, client, append(payload, '\n'), rights)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var encoded json.RawMessage
	if err := json.NewDecoder(client).Decode(&encoded); err != nil {
		t.Fatal(err)
	}
	<-done
	var response Response
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	return response, encoded
}

func TestMaintenancePingDrainStateAndLegacyCompatibility(t *testing.T) {
	// Wire ping reports active UTC-second expiry without any token bytes; old response fields still decode, and inactive/expired status stays clean.
	d := newMaintenanceTestDaemon(t)
	for _, mode := range []string{"clean", "active", "expired"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "active" {
				if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
					t.Fatal(r.Error)
				}
			} else if mode == "expired" {
				d.setMaintenanceState(d.drainToken, time.Now().Add(-time.Second))
			}
			r, encoded := maintenanceEncodedRequest(t, d, Request{Action: "ping"})
			if !r.OK || r.DaemonPID != os.Getpid() || r.HelperSnapshot == nil || r.MaintenanceDrain == nil || r.MaintenanceDrain.Active != (mode == "active") {
				t.Fatal("ping lost existing fields or misreported drain")
			}
			if mode == "active" {
				if r.MaintenanceDrain.ExpiresAt != d.drainUntil.UTC().Format(time.RFC3339) {
					t.Fatal("ping expiry is not UTC RFC3339 seconds")
				}
			} else if r.MaintenanceDrain.ExpiresAt != "" {
				t.Fatal("inactive drain exposes an expiry")
			}
			if r.Token != "" || strings.Contains(string(encoded), `"token"`) || (d.drainToken != "" && strings.Contains(string(encoded), d.drainToken)) {
				t.Fatal("ping encoded the ownership token")
			}
			// Exact pre-extension Response fields: unknown optional status is ignored.
			var legacy struct {
				Token          string          `json:"token,omitempty"`
				OK             bool            `json:"ok"`
				Error          string          `json:"error,omitempty"`
				DaemonPID      int             `json:"daemon_pid,omitempty"`
				PID            int             `json:"pid,omitempty"`
				Handle         string          `json:"handle,omitempty"`
				Path           string          `json:"path,omitempty"`
				HelperSnapshot *HelperSnapshot `json:"helper_snapshot,omitempty"`
			}
			if err := json.Unmarshal(encoded, &legacy); err != nil || !legacy.OK || legacy.DaemonPID != r.DaemonPID || legacy.HelperSnapshot == nil || legacy.Token != "" || legacy.Error != "" {
				t.Fatal("legacy ping decode changed")
			}
		})
	}
	encoded, err := json.Marshal(Response{OK: true})
	if err != nil || strings.Contains(string(encoded), "maintenance_drain") {
		t.Fatal("drain field is not optional")
	}
}

func TestMaintenancePingDuringMutation(t *testing.T) {
	// Ping remains available with mutation held and safely snapshots concurrent drain/renew/release transitions under the race detector.
	d := newMaintenanceTestDaemon(t)
	d.mutation.Lock()
	response := maintenanceRequest(t, d, Request{Action: "ping"})
	d.mutation.Unlock()
	if !response.OK || response.MaintenanceDrain == nil {
		t.Fatal("ping unavailable during mutation")
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	started := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				state := d.maintenanceDrainState()
				if state.Active {
					if _, err := time.Parse(time.RFC3339, state.ExpiresAt); err != nil {
						t.Error("concurrent snapshot lost active expiry")
					}
				} else if state.ExpiresAt != "" {
					t.Error("concurrent inactive snapshot retained expiry")
				}
			}
		}
	}()
	<-started
	for i := 0; i < 20; i++ {
		d.mutation.Lock()
		token, err := d.drain(0)
		if err == nil {
			err = d.renew(token, 0)
		}
		if err == nil {
			err = d.undrain(token)
		}
		d.mutation.Unlock()
		if err != nil {
			t.Errorf("fixture drain/renew/release failed: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestMaintenanceDrainBlocksMutationsAndAllowsPing(t *testing.T) {
	// An idle drain rejects non-maintenance mutations and repeated drain before handlers run, while ping stays available.
	previousResolver, previousOrder := resolverDirVPNCore, networkServiceOrderVPNCore
	resolverDirVPNCore = t.TempDir()
	marker := filepath.Join(resolverDirVPNCore, "fixture-resolver")
	if err := os.WriteFile(marker, []byte("# Added by openconnect-tun DNS shim\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	networkServiceOrderVPNCore = func() ([]byte, error) { return nil, nil }
	t.Cleanup(func() { resolverDirVPNCore, networkServiceOrderVPNCore = previousResolver, previousOrder })
	d := newMaintenanceTestDaemon(t)
	if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
		t.Fatal(r.Error)
	}
	for _, action := range []string{"maintenance.drain", "singbox.start", "tcpdump.start", "dns.scutil", "dns.networksetup", "resolver.cleanup", "signal"} {
		r := maintenanceRequest(t, d, Request{Action: action})
		if r.OK || r.Error != "vpn core is draining for maintenance" {
			t.Errorf("%s: %+v", action, r)
		}
	}
	if r := maintenanceRequest(t, d, Request{Action: "ping"}); !r.OK || r.HelperSnapshot == nil {
		t.Fatal(r)
	}
	if len(d.children.children) != 0 {
		t.Fatal("draining created a child")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("draining touched resolver fixture: %v", err)
	}
}

func TestMaintenanceDrainRefusesRegisteredChildren(t *testing.T) {
	// Registered sing-box/tcpdump children refuse drain with exact counts and leave the drain state unchanged.
	for _, kinds := range [][]string{{"sing-box"}, {"tcpdump"}, {"sing-box", "sing-box", "tcpdump"}} {
		d := newMaintenanceTestDaemon(t)
		counts := map[string]int{}
		for _, kind := range kinds {
			if _, err := d.children.add(0, false, "", kind); err != nil {
				t.Fatal(err)
			}
			counts[kind]++
		}
		r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
		if r.OK || !d.drainUntil.IsZero() {
			t.Fatalf("busy drain changed state: %+v", r)
		}
		for kind, count := range counts {
			want := fmt.Sprintf("%d %s", count, kind)
			if !strings.Contains(r.Error, want) {
				t.Errorf("%q lacks %q", r.Error, want)
			}
		}
		if len(d.children.children) != len(kinds) {
			t.Fatal("busy drain changed children")
		}
	}
}

func TestMaintenanceDrainRefusesInFlightRequests(t *testing.T) {
	// Both unread queued requests and tracked active requests (including ping) refuse drain without changing state.
	for _, action := range []string{"pending", "dns.scutil", "ping"} {
		d := newMaintenanceTestDaemon(t)
		id := d.requests.enqueue()
		if action != "pending" {
			d.requests.begin(id, action)
		}
		r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
		if r.OK || !strings.Contains(r.Error, "1 other request(s) in flight") || !d.drainUntil.IsZero() {
			t.Fatalf("%s: %+v", action, r)
		}
		if action == "pending" {
			d.requests.abandon(id)
		} else {
			d.requests.complete(id, true)
		}
		if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
			t.Fatal(r)
		}
	}
}

func TestMaintenanceDrainExpiryAndUndrain(t *testing.T) {
	// Expiry and owned undrain restore mutation dispatch; repeated release is refused and new deadlines match the acquisition interval plus TTL.
	previousTTL := maintenanceDrainTTL
	t.Cleanup(func() { maintenanceDrainTTL = previousTTL })
	for _, mode := range []string{"expiry", "undrain"} {
		previousTTL := maintenanceDrainTTL
		if mode == "expiry" {
			maintenanceDrainTTL = 10 * time.Millisecond
		}
		d := newMaintenanceTestDaemon(t)
		drain := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
		if !drain.OK {
			t.Fatal(drain)
		}
		if mode == "expiry" {
			time.Sleep(time.Until(d.drainUntil) + time.Millisecond)
		} else {
			if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: drain.Token}); !r.OK {
				t.Fatal(r)
			}
			if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: drain.Token}); r.OK || !strings.Contains(r.Error, "expired or inactive") {
				t.Fatal(r)
			}
		}
		before := time.Now()
		if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
			t.Fatal(r)
		}
		after := time.Now()
		if d.drainUntil.Before(before.Add(maintenanceDrainTTL)) || d.drainUntil.After(after.Add(maintenanceDrainTTL)) {
			t.Fatal("expiry is outside acquisition interval plus TTL")
		}
		maintenanceDrainTTL = previousTTL
	}
}

func TestMaintenanceDrainSerializesWithSingBoxStart(t *testing.T) {
	// The real RPC dispatch serializes drain/start; a start registers a fixture child, so the two cannot both succeed.
	for range 30 {
		d := newMaintenanceTestDaemon(t)
		d.startSingBox = func(request Request, log *os.File) (int, string, error) {
			defer log.Close()
			if _, err := validateSingBoxConfig(request.ConfigJSON); err != nil {
				return 0, "", err
			}
			handle, err := d.children.add(0, false, "", "sing-box")
			return 0, handle, err
		}
		var wg sync.WaitGroup
		var drain, start Response
		wg.Add(2)
		go func() { defer wg.Done(); drain = maintenanceRequest(t, d, Request{Action: "maintenance.drain"}) }()
		go func() {
			defer wg.Done()
			start = maintenanceRequest(t, d, Request{Action: "singbox.start", ConfigJSON: []byte(`{}`)})
		}()
		wg.Wait()
		if drain.OK && start.OK {
			t.Fatal("drain and start both succeeded")
		}
		if !start.OK && !drain.OK {
			t.Fatalf("neither succeeded: drain=%+v start=%+v", drain, start)
		}
		if start.OK && !strings.Contains(drain.Error, "sing-box") && !strings.Contains(drain.Error, "request(s) in flight") {
			t.Fatal(drain)
		}
		if drain.OK && start.Error != "vpn core is draining for maintenance" {
			t.Fatal(start)
		}
	}
}

func TestMaintenanceTypedSchema(t *testing.T) {
	// Drain is fieldless; undrain/renew require a well-formed token alone, and no other action accepts tokens.
	for _, action := range []string{"maintenance.drain", "maintenance.undrain", "maintenance.renew"} {
		base := Request{Action: action}
		if action != "maintenance.drain" {
			base.Token = strings.Repeat("a", 64)
		}
		if !knownAction(action) || validateRequestShape(base) != nil {
			t.Fatal(action)
		}
		fields := []Request{{ConfigJSON: []byte("{}")}, {Stdin: "x"}, {LogMaxLines: 1}, {Handle: "x"}, {Signal: "TERM"}, {SetPGID: true}, {Service: "x"}, {Servers: []string{"x"}}, {Interface: "x"}, {Filter: []string{"x"}}, {ApplePCAPNG: true}, {RunAsUser: true}}
		for _, request := range fields {
			request.Action, request.Token = action, base.Token
			if err := validateRequestShape(request); err == nil || !strings.Contains(err.Error(), "typed schema") {
				t.Fatalf("accepted %+v: %v", request, err)
			}
		}
		if action == "maintenance.drain" {
			continue
		}
		for _, token := range []string{"", "short", strings.Repeat("g", 64), strings.Repeat("A", 64), strings.Repeat("a", 66)} {
			if r := maintenanceRequest(t, newMaintenanceTestDaemon(t), Request{Action: action, Token: token}); r.OK || !strings.Contains(r.Error, "token is required") {
				t.Fatal(r)
			}
		}
	}
	for _, action := range []string{"ping", "maintenance.drain", "singbox.start", "tcpdump.start", "dns.scutil", "dns.networksetup", "resolver.cleanup", "signal"} {
		if err := validateRequestShape(Request{Action: action, Token: strings.Repeat("a", 64)}); err == nil {
			t.Fatal(action)
		}
	}
}

func TestMaintenanceStaleUndrainPreservesSuccessor(t *testing.T) {
	// After A expires and B drains, A's late release cannot cancel B or admit a start.
	d := newMaintenanceTestDaemon(t)
	a := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
	if !a.OK || !validMaintenanceToken(a.Token) {
		t.Fatal(a)
	}
	d.drainUntil = time.Now().Add(-time.Second) // Deterministic monotonic expiry, no sleep.
	b := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
	if !b.OK || !validMaintenanceToken(b.Token) || b.Token == a.Token {
		t.Fatal(b)
	}
	until := d.drainUntil
	r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: a.Token})
	if r.OK || !strings.Contains(r.Error, "token does not match") || d.drainToken != b.Token || d.drainUntil != until {
		t.Fatalf("stale release changed successor: %+v", r)
	}
	if r := maintenanceRequest(t, d, Request{Action: "singbox.start"}); r.OK || r.Error != "vpn core is draining for maintenance" {
		t.Fatal(r)
	}
	if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: b.Token}); !r.OK {
		t.Fatal(r)
	}
	if r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"}); !r.OK {
		t.Fatal(r)
	}
}

func TestMaintenanceRenewOwnershipAndIdleness(t *testing.T) {
	// Only the active idle owner can renew. Wrong/busy refusals preserve the lease; expired/inactive tokens have no ownership state.
	for _, mode := range []string{"valid", "wrong", "expired", "inactive", "queued", "active", "child"} {
		t.Run(mode, func(t *testing.T) {
			d := newMaintenanceTestDaemon(t)
			drain := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
			if !drain.OK || !validMaintenanceToken(drain.Token) {
				t.Fatal(drain)
			}
			token := drain.Token
			switch mode {
			case "wrong":
				token = strings.Repeat("f", 64)
				if token == drain.Token {
					token = strings.Repeat("e", 64)
				}
			case "expired":
				d.drainUntil = time.Now().Add(-time.Second)
			case "inactive":
				if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: token}); !r.OK {
					t.Fatal(r)
				}
			case "queued", "active":
				id := d.requests.enqueue()
				if mode == "active" {
					d.requests.begin(id, "ping")
				}
			case "child":
				if _, err := d.children.add(0, false, "", "sing-box"); err != nil {
					t.Fatal(err)
				}
			}
			until := d.drainUntil
			r := maintenanceRequest(t, d, Request{Action: "maintenance.renew", Token: token})
			if mode == "valid" {
				if !r.OK || r.Token != token || !d.drainUntil.After(until) || time.Until(d.drainUntil) > maintenanceDrainTTL {
					t.Fatal(r)
				}
				if r := maintenanceRequest(t, d, Request{Action: "singbox.start"}); r.OK || r.Error != "vpn core is draining for maintenance" {
					t.Fatal(r)
				}
			} else {
				want := "busy"
				if mode == "wrong" {
					want = "token does not match"
				}
				if mode == "expired" || mode == "inactive" {
					want = "expired or inactive"
				}
				if mode == "expired" || mode == "inactive" {
					until = time.Time{}
					if d.drainToken != "" {
						t.Fatal("expired/inactive ownership token retained")
					}
				}
				if r.OK || !strings.Contains(r.Error, want) || d.drainUntil != until {
					t.Fatal(r)
				}
				// A refused release must also leave the same lease untouched.
				if mode == "wrong" || mode == "expired" || mode == "inactive" {
					if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: token}); r.OK || !strings.Contains(r.Error, want) || d.drainUntil != until {
						t.Fatal(r)
					}
				}
			}
		})
	}
}

func TestMaintenanceDrainTokenFormatFreshness(t *testing.T) {
	// Eight successful acquisitions return distinct 256-bit lowercase hex tokens that their owner can release.
	d := newMaintenanceTestDaemon(t)
	seen := map[string]bool{}
	for range 8 {
		r := maintenanceRequest(t, d, Request{Action: "maintenance.drain"})
		decoded, err := hex.DecodeString(r.Token)
		if !r.OK || err != nil || len(decoded) != 32 || strings.ToLower(r.Token) != r.Token || seen[r.Token] {
			t.Fatalf("invalid/reused drain token: ok=%v bytes=%d error=%v", r.OK, len(decoded), err)
		}
		seen[r.Token] = true
		if r := maintenanceRequest(t, d, Request{Action: "maintenance.undrain", Token: r.Token}); !r.OK {
			t.Fatal(r)
		}
	}
}
