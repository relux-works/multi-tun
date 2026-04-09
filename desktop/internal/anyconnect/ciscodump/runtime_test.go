package ciscodump

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildTCPDumpCommand_SplitsFilter(t *testing.T) {
	t.Parallel()

	got := buildTCPDumpCommand("/usr/sbin/tcpdump", "lo0", "/tmp/cisco.pcap", "tcp and host 127.0.0.1 and port 60808", "alexis")
	want := []string{
		"/usr/sbin/tcpdump",
		"-i", "lo0",
		"-s", "0",
		"-U",
		"-Z", "alexis",
		"-w", "/tmp/cisco.pcap",
		"tcp", "and", "host", "127.0.0.1", "and", "port", "60808",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildTCPDumpCommand() = %#v, want %#v", got, want)
	}
}

func TestBuildTCPDumpCommand_EnablesApplePCAPNGForPktap(t *testing.T) {
	t.Parallel()

	got := buildTCPDumpCommand("/usr/sbin/tcpdump", "pktap,all", "/tmp/cisco.pcap", "tcp or udp", "alexis")
	want := []string{
		"/usr/sbin/tcpdump",
		"-i", "pktap,all",
		"-s", "0",
		"-U",
		"--apple-pcapng",
		"-Z", "alexis",
		"-w", "/tmp/cisco.pcap",
		"tcp", "or", "udp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildTCPDumpCommand() = %#v, want %#v", got, want)
	}
}

func TestInterestingProcessLinesFromOutput_FiltersCiscoProcesses(t *testing.T) {
	t.Parallel()

	output := strings.Join([]string{
		"101 1 101 00:00:01 /opt/cisco/anyconnect/bin/vpnagentd",
		"102 1 102 00:00:01 /bin/zsh -lc sleep 1",
		"103 1 103 00:00:01 /Users/alexis/.cisco/hostscan/bin64/cscan",
		"104 1 104 00:00:01 /Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/MacOS/Cisco AnyConnect Secure Mobility Client",
		"105 1 105 00:00:01 /Applications/AnyConnect.app/Wrapper/AnyConnect.app/PlugIns/ACExtension.appex/ACExtension",
	}, "\n")

	got := interestingProcessLinesFromOutput(output)
	want := []string{
		"101 1 101 00:00:01 /opt/cisco/anyconnect/bin/vpnagentd",
		"103 1 103 00:00:01 /Users/alexis/.cisco/hostscan/bin64/cscan",
		"104 1 104 00:00:01 /Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app/Contents/MacOS/Cisco AnyConnect Secure Mobility Client",
		"105 1 105 00:00:01 /Applications/AnyConnect.app/Wrapper/AnyConnect.app/PlugIns/ACExtension.appex/ACExtension",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("interestingProcessLinesFromOutput() = %#v, want %#v", got, want)
	}
}

func TestProcessSnapshotDigest_IgnoresElapsedTime(t *testing.T) {
	t.Parallel()

	first := []string{
		"2910 2906 2906 00:00:01 /opt/cisco/anyconnect/bin/vpn -s",
		"872 1 872 1-03:15:40 /opt/cisco/anyconnect/bin/vpnagentd -execv_instance",
	}
	second := []string{
		"2910 2906 2906 00:00:09 /opt/cisco/anyconnect/bin/vpn -s",
		"872 1 872 1-03:15:48 /opt/cisco/anyconnect/bin/vpnagentd -execv_instance",
	}

	if got, want := processSnapshotDigest(first), processSnapshotDigest(second); got != want {
		t.Fatalf("processSnapshotDigest() changed on elapsed time only: %q != %q", got, want)
	}
}

func TestFilterLoopbackNetstatLines_KeepsLoopbackOnly(t *testing.T) {
	t.Parallel()

	output := strings.Join([]string{
		"Active Internet connections",
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
		"tcp4       0      0  127.0.0.1.62824        127.0.0.1.29754        ESTABLISHED vpn:2910",
		"tcp4       0      0  10.0.0.5.51432         198.51.100.241.443      ESTABLISHED",
		"tcp6       0      0  ::1.5000               ::1.6000               ESTABLISHED packet-extension:39502",
	}, "\n")

	got := filterLoopbackNetstatLines(output, []int{2910})
	want := []string{
		"Active Internet connections",
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
		"tcp4       0      0  127.0.0.1.62824        127.0.0.1.29754        ESTABLISHED vpn:2910",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterLoopbackNetstatLines() = %#v, want %#v", got, want)
	}
}

func TestFilterLoopbackLsofLines_KeepsLoopbackOnly(t *testing.T) {
	t.Parallel()

	output := strings.Join([]string{
		"COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
		"vpnagentd  872   root    5u  IPv4 0x1      0t0  TCP 127.0.0.1:29754 (LISTEN)",
		"curl      1412 alexis    7u  IPv4 0x2      0t0  TCP 10.0.0.5:51432->198.51.100.241:443 (ESTABLISHED)",
		"helper    1550 alexis    9u  IPv6 0x3      0t0  TCP [::1]:5000->[::1]:6000 (ESTABLISHED)",
	}, "\n")

	got := filterLoopbackLsofLines(output)
	want := []string{
		"COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
		"vpnagentd  872   root    5u  IPv4 0x1      0t0  TCP 127.0.0.1:29754 (LISTEN)",
		"helper    1550 alexis    9u  IPv6 0x3      0t0  TCP [::1]:5000->[::1]:6000 (ESTABLISHED)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterLoopbackLsofLines() = %#v, want %#v", got, want)
	}
}

func TestNormalizeNetstatLines_StripsVolatileCounters(t *testing.T) {
	t.Parallel()

	lines := []string{
		"Active Internet connections",
		"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)",
		"tcp4       0      0  127.0.0.1.29754        127.0.0.1.62824        ESTABLISHED          904          585  408064  146988        vpnagentd:872    00182",
	}

	got := normalizeNetstatLines(lines)
	want := []string{
		"tcp4 127.0.0.1.29754 127.0.0.1.62824 ESTABLISHED vpnagentd:872",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeNetstatLines() = %#v, want %#v", got, want)
	}
}

func TestNormalizeLsofSocketOutput_StripsVolatileColumns(t *testing.T) {
	t.Parallel()

	output := strings.Join([]string{
		"COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME",
		"vpnagentd  872   root    5u  IPv4 0x1      0t0  TCP 127.0.0.1:29754 (LISTEN)",
		"vpn       2910 alexis   23u  IPv4 0x2      0t0  TCP 127.0.0.1:62824->127.0.0.1:29754 (ESTABLISHED)",
	}, "\n")

	got := normalizeLsofSocketOutput(output)
	want := []string{
		"vpnagentd 872 127.0.0.1:29754 (LISTEN)",
		"vpn 2910 127.0.0.1:62824->127.0.0.1:29754 (ESTABLISHED)",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeLsofSocketOutput() = %#v, want %#v", got, want)
	}
}

func TestReadResolverDirSnapshotIncludesFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	first := filepath.Join(dir, "corp.example")
	second := filepath.Join(dir, "search.tailscale")
	if err := os.WriteFile(first, []byte("nameserver 10.0.0.53\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(first) error = %v", err)
	}
	if err := os.WriteFile(second, []byte("# Added by tailscaled\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(second) error = %v", err)
	}

	got, err := readResolverDirSnapshot(dir)
	if err != nil {
		t.Fatalf("readResolverDirSnapshot() error = %v", err)
	}
	for _, needle := range []string{
		"directory: " + dir,
		"--- " + first,
		"nameserver 10.0.0.53",
		"--- " + second,
		"# Added by tailscaled",
	} {
		if !strings.Contains(got, needle) {
			t.Fatalf("resolver snapshot missing %q:\n%s", needle, got)
		}
	}
}

func TestResolveProbeHosts_UsesDefaultsUnlessDisabled(t *testing.T) {
	t.Parallel()

	if got := resolveProbeHosts(nil, false); !reflect.DeepEqual(got, defaultProbeHosts) {
		t.Fatalf("resolveProbeHosts(nil, false) = %#v, want %#v", got, defaultProbeHosts)
	}
	if got := resolveProbeHosts(nil, true); got != nil {
		t.Fatalf("resolveProbeHosts(nil, true) = %#v, want nil", got)
	}
}

func TestResolveProbeNameservers_DeduplicatesTrimmedValues(t *testing.T) {
	t.Parallel()

	got := resolveProbeNameservers([]string{" 10.23.16.4 ", "", "10.23.0.23", "10.23.16.4"}, false)
	want := []string{"10.23.16.4", "10.23.0.23"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolveProbeNameservers() = %#v, want %#v", got, want)
	}
}

func TestShouldStartOCSCLoopbackCapture_OnlySkipsLegacyLoopbackPrimary(t *testing.T) {
	t.Parallel()

	if got := shouldStartOCSCLoopbackCapture(defaultOCSCInterface, defaultOCSCFilter); got {
		t.Fatalf("shouldStartOCSCLoopbackCapture(loopback default) = %t, want false", got)
	}
	if got := shouldStartOCSCLoopbackCapture(defaultInterface, defaultFilter); !got {
		t.Fatalf("shouldStartOCSCLoopbackCapture(default primary) = %t, want true", got)
	}
}
