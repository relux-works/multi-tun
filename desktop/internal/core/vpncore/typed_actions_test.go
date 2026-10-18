package vpncore

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/singbox"
	"multi-tun/desktop/internal/vless/subscription"
)

func TestSingBoxConfigValidationRejectsFilesystemControllersAndUnsafeInbounds(t *testing.T) {
	// This negative table proves each forbidden filesystem/control-plane key, remote rule set, and non-loopback proxy inbound is rejected.
	cases := map[string]string{
		"experimental":       `{"experimental":{}}`,
		"log output":         `{"log":{"output":"/tmp/x"}}`,
		"cache file":         `{"route":{"cache_file":"/tmp/x"}}`,
		"nested path":        `{"outbounds":[{"type":"direct","nested":{"path":"/tmp/x"}}]}`,
		"remote rule set":    `{"route":{"rule_set":[{"type":"remote","url":"https://example.test/rules"}]}}`,
		"non-loopback mixed": `{"inbounds":[{"type":"mixed","listen":"0.0.0.0"}]}`,
		// sing-box matches keys case-insensitively, so case variants must be refused too.
		"case log output":     `{"log":{"Output":"/tmp/x"}}`,
		"case top-level":      `{"Experimental":{}}`,
		"case nested path":    `{"outbounds":[{"type":"direct","nested":{"PATH":"/tmp/x"}}]}`,
		"case rule set type":  `{"route":{"rule_set":[{"Type":"remote","url":"https://example.test/r"}]}}`,
		"case colliding keys": `{"route":{"rule_set":[{"type":"inline","Type":"remote"}]}}`,
		"case inbound listen": `{"inbounds":[{"type":"mixed","Listen":"0.0.0.0"}]}`,
		"case top-level dup":  `{"log":{},"LOG":{"output":"/tmp/x"}}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateSingBoxConfig([]byte(raw)); err == nil {
				t.Fatalf("validateSingBoxConfig(%s) error = nil", raw)
			}
		})
	}
}

func TestSingBoxConfigValidationAcceptsCurrentVLESSRenderer(t *testing.T) {
	// This positive control proves the current vless-tun renderer fixture remains inside the strict PR B schema.
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "fixtures", "dancevpn.subscription.plain.txt"))
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := subscription.ParseProfiles(string(raw))
	if err != nil || len(profiles) == 0 {
		t.Fatalf("ParseProfiles() profiles=%d error=%v", len(profiles), err)
	}
	data, err := singbox.Render(config.Default(), profiles[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateSingBoxConfig(data); err != nil {
		t.Fatalf("validate current rendered config: %v", err)
	}
}

func TestSCUtilValidationRejectsOutsideGrammar(t *testing.T) {
	// This negative table proves global keys, command substitution tokens, and trailing junk cannot reach scutil.
	for _, input := range []string{
		"set State:/Network/Global/DNS\n",
		"d.add X `id`\n",
		"d.init trailing\n",
	} {
		if err := validateSCUtilInput(input); err == nil {
			t.Fatalf("validateSCUtilInput(%q) error = nil", input)
		}
	}
}

func TestSCUtilValidationAcceptsCurrentVLESSInput(t *testing.T) {
	// This positive control proves the exact apply/remove grammar emitted by vless-tun remains accepted.
	uuid := "01234567-89AB-CDEF-0123-456789ABCDEF"
	input := strings.Join([]string{
		"d.init",
		"d.add ConfirmedServiceID " + uuid,
		"d.add InterfaceName utun7",
		"d.add ServerAddresses * 1.1.1.1 2606:4700:4700::1111",
		"set State:/Network/Service/" + uuid + "/DNS",
		"d.init",
		"d.add Addresses * 198.18.0.1",
		"d.add InterfaceName utun7",
		"d.add Router 198.18.0.1",
		"set State:/Network/Service/" + uuid + "/IPv4",
		"remove State:/Network/Service/" + uuid + "/DNS",
		"remove State:/Network/Service/" + uuid + "/IPv4",
	}, "\n") + "\n"
	if err := validateSCUtilInput(input); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkSetupValidationHasPositiveAndNegativeControls(t *testing.T) {
	// This proves only a listed service plus IPs (or Empty) passes, while unknown services and non-IP servers fail.
	order := []byte("(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n")
	if err := validateNetworkSetup("Wi-Fi", []string{"1.1.1.1", "2606:4700:4700::1111"}, order); err != nil {
		t.Fatalf("valid setup: %v", err)
	}
	if err := validateNetworkSetup("Wi-Fi", []string{"Empty"}, order); err != nil {
		t.Fatalf("valid Empty setup: %v", err)
	}
	for _, tc := range []struct {
		service string
		servers []string
	}{{"Ethernet", []string{"1.1.1.1"}}, {"Wi-Fi", []string{"not-an-ip"}}} {
		if err := validateNetworkSetup(tc.service, tc.servers, order); err == nil {
			t.Fatalf("validateNetworkSetup(%q,%v) error = nil", tc.service, tc.servers)
		}
	}
}

func TestResolverCleanupRemovesOnlyMarkedRegularFiles(t *testing.T) {
	// This proves cleanup removes the two owned marker families while leaving unmarked files and symlinks untouched.
	dir := t.TempDir()
	marked := filepath.Join(dir, "marked")
	public := filepath.Join(dir, "public")
	unmarked := filepath.Join(dir, "unmarked")
	for path, data := range map[string]string{marked: "# Added by openconnect-tun DNS shim\nnameserver 1.1.1.1\n", public: "# Added by openconnect-tun public bypass x\n", unmarked: "nameserver 8.8.8.8\n"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(marked, link); err != nil {
		t.Fatal(err)
	}
	previous := resolverDirVPNCore
	resolverDirVPNCore = dir
	t.Cleanup(func() { resolverDirVPNCore = previous })
	if err := newServiceDaemon(ServiceConfig{}, 501, 20).handleResolverCleanup(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{marked, public} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s still exists: %v", path, err)
		}
	}
	for _, path := range []string{unmarked, link} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("%s removed: %v", path, err)
		}
	}
}

func TestTCPDumpCommandValidationAndExactPositiveCommand(t *testing.T) {
	// This proves shell-bearing interface/filter values and option injection are refused, while the valid argv is fixed and exact.
	want := []string{"/usr/sbin/tcpdump", "-i", "lo0", "-s", "0", "-U", "--apple-pcapng", "-Z", "alexis", "-w", "/runtime/capture.pcap", "tcp", "and", "host", "127.0.0.1"}
	got, err := buildTCPDumpCommand("lo0", []string{"tcp", "and", "host", "127.0.0.1"}, true, "alexis", "/runtime/capture.pcap")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("command=%v error=%v want=%v", got, err, want)
	}
	for _, tc := range []struct {
		iface  string
		filter []string
	}{{"lo0;id", []string{"tcp"}}, {"lo0", []string{"$HOME"}}, {"lo0", []string{"tcp;id"}}, {"lo0", []string{"-w"}}} {
		if _, err := buildTCPDumpCommand(tc.iface, tc.filter, false, "", "/runtime/capture.pcap"); err == nil {
			t.Fatalf("unsafe command accepted: %#v", tc)
		}
	}
}

func TestTCPDumpRunAsUserIsDerivedFromPeerUID(t *testing.T) {
	// This seam proves the request carries only a boolean and the daemon derives -Z from its authenticated client uid.
	previousLookup := lookupUserVPNCore
	lookupUserVPNCore = func(id string) (*user.User, error) {
		if id != "501" {
			t.Fatalf("lookup id=%q", id)
		}
		return &user.User{Username: "derived-user"}, nil
	}
	t.Cleanup(func() { lookupUserVPNCore = previousLookup })
	account, err := lookupUserVPNCore("501")
	if err != nil || account.Username != "derived-user" {
		t.Fatalf("account=%#v err=%v", account, err)
	}
}

func TestTCPDumpRefusesCallerControlledRunAsIdentity(t *testing.T) {
	// This negative control proves omitting run_as_user cannot produce a root-running capture or accept a caller-supplied -Z value.
	d := newServiceDaemon(ServiceConfig{RuntimeDir: t.TempDir()}, 501, 20)
	if _, _, err := d.handleTCPDumpStart(Request{Interface: "lo0", Filter: []string{"tcp"}}); err == nil || !strings.Contains(err.Error(), "run_as_user=true") {
		t.Fatalf("handleTCPDumpStart() error = %v", err)
	}
}

// Duplicate keys resolve last-wins in the validator; the bytes handed to
// sing-box are the re-encoded tree, so an earlier hidden value never reaches it.
func TestSingBoxConfigValidationWritesCanonicalTree(t *testing.T) {
	raw := `{"log":{"output":"/etc/sudoers.d/x"},"log":{"level":"warn"}}`
	canonical, err := validateSingBoxConfig([]byte(raw))
	if err != nil {
		t.Fatalf("validateSingBoxConfig() error = %v, want the last-wins tree accepted", err)
	}
	if strings.Contains(string(canonical), "output") || strings.Contains(string(canonical), "sudoers") {
		t.Fatalf("canonical config = %s, still carries the shadowed value", canonical)
	}
	if !strings.Contains(string(canonical), `"level":"warn"`) {
		t.Fatalf("canonical config = %s, lost the effective value", canonical)
	}
}
