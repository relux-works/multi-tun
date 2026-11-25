package session

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Claim: every start option a restart needs is copied into the record, survives the JSON round trip
// used for the record file, and is independent of the caller's slices afterwards. Limit: this covers
// recordStartOptions, which Start calls on the record it persists; Start itself is not run here.
func TestRecordStartOptionsPersistsEveryField(t *testing.T) {
	opts := StartOptions{
		TunAddresses: []string{"172.20.9.1/30"}, OverlayDNSActive: true,
		OverlayDNSDomains: []string{"corp.example"}, SystemDNSServers: []string{"9.9.9.9"},
	}
	var rec CurrentSession
	recordStartOptions(&rec, opts)
	opts.TunAddresses[0], opts.OverlayDNSDomains[0], opts.SystemDNSServers[0] = "x", "x", "x"
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var back CurrentSession
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	want := CurrentSession{StartOptionsRecorded: true, TunAddresses: []string{"172.20.9.1/30"}, OverlayDNSActive: true,
		OverlayDNSDomains: []string{"corp.example"}, SystemDNSServers: []string{"9.9.9.9"}}
	if !reflect.DeepEqual(back, want) {
		t.Fatalf("round-tripped record = %+v, want %+v", back, want)
	}
	// Negative control: a record written without recordStartOptions does not claim the fields.
	var old CurrentSession
	if json.Unmarshal([]byte(`{"id":"x","pid":1}`), &old); old.StartOptionsRecorded || old.TunAddresses != nil {
		t.Fatalf("old record claims recorded options: %+v", old)
	}
}
