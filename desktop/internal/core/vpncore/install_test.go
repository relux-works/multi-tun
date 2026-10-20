package vpncore

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestInstallServiceRefusesDigestMismatchBeforePrivilege(t *testing.T) {
	// This proves a validly shaped but incorrect digest triggers no sudo check or privileged command.
	binary := writeInstallTestBinary(t)
	var privileged []string
	sudoChecks := 0
	withInstallSeams(t, func() error { sudoChecks++; return nil }, func(name string, args ...string) ([]byte, error) {
		privileged = append(privileged, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	err := InstallService(testInstallConfig(t), binary, 501, 20, strings.Repeat("0", 64))
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("InstallService() error = %v, want digest mismatch", err)
	}
	if sudoChecks != 0 || len(privileged) != 0 {
		t.Fatalf("privileged work occurred before refusal: sudo=%d commands=%v", sudoChecks, privileged)
	}
}

func TestInstallServiceRefusesMalformedDigestBeforePrivilege(t *testing.T) {
	// This proves malformed uppercase/short digests are rejected before any privileged seam is entered.
	binary := writeInstallTestBinary(t)
	called := false
	withInstallSeams(t, func() error { called = true; return nil }, func(string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	})
	for _, value := range []string{"", "abc", strings.Repeat("A", 64)} {
		if err := InstallService(testInstallConfig(t), binary, 501, 20, value); err == nil {
			t.Fatalf("InstallService(%q) error = nil", value)
		}
	}
	if called {
		t.Fatal("malformed digest reached a privileged seam")
	}
}

func TestInstallServiceInstallsPackageAndReplacesLaunchServiceInOrder(t *testing.T) {
	// This proves a secure helper parent permits the exact staged install and bounded launchd replacement sequence.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatalf("InstallDigest() error = %v", err)
	}
	var commands []string
	printCalls := 0
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if err := performFakeInstall(name, args, nil); err != nil {
			return nil, err
		}
		if name == "launchctl" && len(args) > 0 && args[0] == "print" {
			printCalls++
			if printCalls == 2 {
				return nil, launchctlTestError(113, nil)
			}
		}
		return nil, nil
	})
	previousSleep := installSleepVPNCore
	installSleepVPNCore = func(_ time.Duration) {}
	t.Cleanup(func() { installSleepVPNCore = previousSleep })
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	if err := InstallService(cfg, binary, 501, 20, digest); err != nil {
		t.Fatalf("InstallService() error = %v", err)
	}
	if len(commands) != 13 {
		t.Fatalf("commands = %v, want 13 ordered commands", commands)
	}
	wantKinds := []string{"rm -rf", "install -d", "chmod -N", "install -d", "install -o", "install -o", "install -o", "install -o", "launchctl bootout", "launchctl print", "launchctl print", "launchctl enable", "launchctl bootstrap"}
	gotKinds := make([]string, 0, len(wantKinds))
	for _, command := range commands {
		for _, prefix := range wantKinds {
			if strings.HasPrefix(command, prefix) {
				gotKinds = append(gotKinds, prefix)
				break
			}
		}
	}
	if !reflect.DeepEqual(gotKinds, wantKinds) {
		t.Fatalf("command order = %v, want %v; raw=%v", gotKinds, wantKinds, commands)
	}
	for index, want := range []string{
		"rm -rf " + cfg.HelperDir,
		"install -d -o root -g wheel -m 0755 " + cfg.HelperDir,
		"chmod -N " + cfg.HelperDir,
		"install -d -o root -g wheel -m 0755 " + filepath.Join(cfg.HelperDir, "bin"),
		" -m 0755 ",
		" -m 0755 ",
		" -m 0644 ",
		" -m 0644 ",
	} {
		if !strings.Contains(commands[index], want) {
			t.Fatalf("commands[%d] = %q, want fragment %q", index, commands[index], want)
		}
	}
	if !strings.HasSuffix(commands[4], " "+cfg.BinaryPath()) || !strings.HasSuffix(commands[5], " "+cfg.ToolPath("sing-box")) || !strings.HasSuffix(commands[6], " "+cfg.ManifestPath()) || !strings.HasSuffix(commands[7], " "+cfg.PlistPath) {
		t.Fatalf("installed destinations are wrong: %v", commands[:8])
	}
	for index, want := range []string{
		"launchctl bootout system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl print system/" + cfg.Label,
		"launchctl enable system/" + cfg.Label,
		"launchctl bootstrap system " + cfg.PlistPath,
	} {
		if commands[index+8] != want {
			t.Fatalf("commands[%d] = %q, want %q", index+8, commands[index+8], want)
		}
	}
}

func TestCompatibilityCleanupStillTargetsLegacyService(t *testing.T) {
	// This proves hardened installation retains the exact legacy launchd/socket cleanup without touching the new helper directory.
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "launchctl" && len(args) > 0 && args[0] == "print" {
			return nil, launchctlTestError(113, nil)
		}
		return nil, nil
	})
	if err := cleanupCompatibilityServices(DefaultServiceConfig()); err != nil {
		t.Fatalf("cleanupCompatibilityServices() error = %v", err)
	}
	want := []string{
		"launchctl bootout system/" + legacyOpenConnectHelperLabel,
		"launchctl print system/" + legacyOpenConnectHelperLabel,
		"rm -f " + legacyOpenConnectHelperPlistPath + " " + legacyOpenConnectHelperSocketPath,
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("legacy cleanup commands = %v, want %v", commands, want)
	}
}

func writeInstallTestBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vpn-core")
	if err := os.WriteFile(path, []byte("test vpn-core binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallPackagePinsResolvedSingBoxInManifestAndDigest(t *testing.T) {
	// This proves symlink-resolved sing-box bytes are listed in bin/ and changing them changes the install digest.
	dir := t.TempDir()
	realTool := filepath.Join(dir, "sing-box-real")
	linkTool := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(realTool, []byte("#!/bin/sh\nprintf 'sing-box version v1\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTool, linkTool); err != nil {
		t.Fatal(err)
	}
	previous := lookPathInstallVPNCore
	lookPathInstallVPNCore = func(name string) (string, error) {
		if name != "sing-box" {
			t.Fatalf("lookPath(%q)", name)
		}
		return linkTool, nil
	}
	t.Cleanup(func() { lookPathInstallVPNCore = previous })
	binary := writeInstallTestBinary(t)
	first, err := prepareInstallPackage(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(first.dir)
	manifestData, err := os.ReadFile(first.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifest(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range manifest.Files {
		if entry.Path == "bin/sing-box" && entry.SHA256 == first.tools[0].SHA256 {
			found = true
		}
	}
	resolvedTool, err := filepath.EvalSymlinks(realTool)
	if err != nil {
		t.Fatal(err)
	}
	if !found || first.tools[0].SourcePath != resolvedTool {
		t.Fatalf("package tools=%#v manifest=%#v", first.tools, manifest)
	}
	if err := os.WriteFile(realTool, []byte("#!/bin/sh\nprintf 'sing-box version v2\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	second, err := prepareInstallPackage(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(second.dir)
	if first.digest == second.digest {
		t.Fatal("install digest did not change with sing-box bytes")
	}
}

func TestInstallPlanMetadataAndDigestUseBytesStagedBeforePATHSourceSwap(t *testing.T) {
	// This race seam proves a PATH tool replacement after the one staging copy cannot change the plan's size, SHA, manifest, or digest metadata, and that the staged tool is never executed.
	dir := t.TempDir()
	pathTool := filepath.Join(dir, "sing-box")
	marker := filepath.Join(dir, "executed")
	v1 := []byte("#!/bin/sh\ntouch " + marker + "\n")
	v2 := []byte("#!/bin/sh\nprintf 'sing-box version swapped-v2\\n'\n")
	if err := os.WriteFile(pathTool, v1, 0o755); err != nil {
		t.Fatal(err)
	}
	resolvedTool, err := filepath.EvalSymlinks(pathTool)
	if err != nil {
		t.Fatal(err)
	}
	previousLookup := lookPathInstallVPNCore
	previousAfterStage := afterStageInstallToolVPNCore
	lookPathInstallVPNCore = func(string) (string, error) { return pathTool, nil }
	var swapErr error
	afterStageInstallToolVPNCore = func(source, staged string) {
		if source != resolvedTool || filepath.Base(staged) != "sing-box" {
			t.Fatalf("stage seam source=%q staged=%q", source, staged)
		}
		swapErr = os.WriteFile(source, v2, 0o755)
	}
	t.Cleanup(func() {
		lookPathInstallVPNCore = previousLookup
		afterStageInstallToolVPNCore = previousAfterStage
	})

	plan, err := PrepareInstallPlan(writeInstallTestBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	if swapErr != nil {
		t.Fatal(swapErr)
	}
	tools := plan.PinnedTools()
	if len(tools) != 1 || tools[0].Size != int64(len(v1)) {
		t.Fatalf("plan tools = %#v", tools)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged tool was executed during planning (marker stat err=%v)", err)
	}
	staged, err := os.ReadFile(tools[0].Path)
	if err != nil || !reflect.DeepEqual(staged, v1) {
		t.Fatalf("staged bytes = %q, error = %v", staged, err)
	}
	stagedSHA, err := hashFile(tools[0].Path)
	if err != nil || stagedSHA != tools[0].SHA256 {
		t.Fatalf("staged sha = %q, metadata = %q, error = %v", stagedSHA, tools[0].SHA256, err)
	}
	manifestData, err := os.ReadFile(plan.pkg.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifest(manifestData)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 2 || manifest.Files[1].SHA256 != tools[0].SHA256 {
		t.Fatalf("manifest = %#v, tools = %#v", manifest, tools)
	}
	binaryData, err := os.ReadFile(plan.pkg.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := []byte("works.relux.vpn-core.pkg/v1\x00")
	digestBytes = binary.BigEndian.AppendUint64(digestBytes, uint64(len(binaryData)))
	digestBytes = append(digestBytes, binaryData...)
	digestBytes = binary.BigEndian.AppendUint64(digestBytes, uint64(len(manifestData)))
	digestBytes = append(digestBytes, manifestData...)
	wantDigest := sha256.Sum256(digestBytes)
	if plan.Digest() != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("plan digest = %q, want framed digest of staged bytes %x", plan.Digest(), wantDigest)
	}
}

func TestPackageDigestMatchesFixedVectors(t *testing.T) {
	// This proves the framing matches vectors computed by independent implementations
	// (Python hashlib + struct.pack(">Q")): the shared mac-infra vectors (posted in
	// #mac-infra-lobby/vpn-core-root-install-h03) plus one local vector, including
	// the empty package and non-UTF-8 binary bytes.
	for _, tc := range []struct {
		name             string
		binary, manifest string
		want             string
		unframed         string
	}{
		{"mac-infra 1 empty", "", "", "48f4cf7557a6821acf170fc388daba69ad0d9d8a04fae38053e86126539f6b1d", ""},
		{"mac-infra 2", "ab", "c", "7ab31c62ae8201c0b1f863be472881cce7ee7ec82cbe8a727077536f37a29232", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"mac-infra 3", "a", "bc", "9e0b399700882203bab875094e4867ab6edb2bb5738bdda78a87bb36e7ec96d2", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"mac-infra 4", "vpn-core\x00\xff", "{\"version\":1}\n", "b4a2a21540e568c0aa15ced42cff78fd96c67a561d831b7fe1fc647fa85e99db", "230585662613f457e6addb9f6fa4b3bfc9e0d81edbeb0d8707be8b9b19f7fd96"},
		{"local", "vpn-core\x00bytes", "{\"version\":1}\n", "8dde545b36c2bbcc6e763d517f584b61a1a7fda7fd014de5e6244459c6211808", ""},
	} {
		got, err := packageDigest(strings.NewReader(tc.binary), int64(len(tc.binary)), []byte(tc.manifest))
		if err != nil || got != tc.want {
			t.Fatalf("%s: packageDigest() = %q, %v; want %q", tc.name, got, err, tc.want)
		}
		if tc.unframed != "" {
			// The published unframed value must really be the old formula, and must differ.
			sum := sha256.Sum256([]byte(tc.binary + tc.manifest))
			if hex.EncodeToString(sum[:]) != tc.unframed || got == tc.unframed {
				t.Fatalf("%s: unframed = %x, framed = %q, vector unframed = %q", tc.name, sum, got, tc.unframed)
			}
		}
	}
}

func TestPackageDigestLengthFramingSeparatesBoundary(t *testing.T) {
	// This proves moving a byte across the binary/manifest boundary changes the digest,
	// while the unframed concatenation (the control) cannot tell the two packages apart.
	first, err := packageDigest(strings.NewReader("ab"), 2, []byte("c"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := packageDigest(strings.NewReader("a"), 1, []byte("bc"))
	if err != nil {
		t.Fatal(err)
	}
	if first != "7ab31c62ae8201c0b1f863be472881cce7ee7ec82cbe8a727077536f37a29232" || second != "9e0b399700882203bab875094e4867ab6edb2bb5738bdda78a87bb36e7ec96d2" {
		t.Fatalf("framed digests = %q / %q", first, second)
	}
	if sha256.Sum256([]byte("ab"+"c")) != sha256.Sum256([]byte("a"+"bc")) {
		t.Fatal("control: unframed concatenations unexpectedly differ")
	}
}

func TestPackageDigestRefusesSizeMismatch(t *testing.T) {
	// This proves the binary is hashed only when its length equals the declared size,
	// so the length prefix can never describe bytes other than the ones hashed.
	for _, tc := range []struct {
		data string
		size int64
	}{{"abc", 4}, {"abcd", 3}, {"", -1}} {
		if got, err := packageDigest(strings.NewReader(tc.data), tc.size, nil); err == nil {
			t.Fatalf("packageDigest(%q, %d) = %q, want error", tc.data, tc.size, got)
		}
	}
	if _, err := packageDigest(strings.NewReader("abc"), 3, nil); err != nil {
		t.Fatalf("control: exact size refused: %v", err)
	}
}

func TestInstallServiceRefusesUnframedDigestBeforePrivilege(t *testing.T) {
	// This proves a digest computed the old unframed way, sha256(vpn-core || manifest.json),
	// over the exact staged bytes is refused before any sudo check or privileged command.
	binaryPath := writeInstallTestBinary(t)
	plan, err := PrepareInstallPlan(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	binaryData, err := os.ReadFile(plan.pkg.binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(plan.pkg.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	framed := plan.Digest()
	plan.Close()
	unframedSum := sha256.Sum256(append(append([]byte(nil), binaryData...), manifestData...))
	unframed := hex.EncodeToString(unframedSum[:])
	if unframed == framed {
		t.Fatal("control: unframed and framed digests coincide")
	}
	var privileged []string
	sudoChecks := 0
	withInstallSeams(t, func() error { sudoChecks++; return nil }, func(name string, args ...string) ([]byte, error) {
		privileged = append(privileged, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	err = InstallService(testInstallConfig(t), binaryPath, 501, 20, unframed)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("InstallService(unframed) error = %v, want digest mismatch", err)
	}
	if sudoChecks != 0 || len(privileged) != 0 {
		t.Fatalf("privileged work occurred before refusal: sudo=%d commands=%v", sudoChecks, privileged)
	}
}

func TestToolDriftReportsDifferenceAndSuppressesEquality(t *testing.T) {
	// This proves status drift emits short pinned/PATH hashes only on a real content mismatch.
	dir := t.TempDir()
	cfg := ServiceConfig{HelperDir: filepath.Join(dir, "helper")}
	if err := os.MkdirAll(cfg.HelperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pathTool := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(pathTool, []byte("same\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sha, err := hashFile(pathTool)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, _ := json.Marshal(Manifest{Version: manifestVersion, Files: []ManifestFile{{Path: "bin/sing-box", SHA256: sha}}})
	if err := os.WriteFile(cfg.ManifestPath(), manifestData, 0o644); err != nil {
		t.Fatal(err)
	}
	previous := lookPathInstallVPNCore
	lookPathInstallVPNCore = func(string) (string, error) { return pathTool, nil }
	t.Cleanup(func() { lookPathInstallVPNCore = previous })
	drift, err := ToolDrift(cfg)
	if err != nil || len(drift) != 0 {
		t.Fatalf("equal drift=%v err=%v", drift, err)
	}
	if err := os.WriteFile(pathTool, []byte("different\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	drift, err = ToolDrift(cfg)
	if err != nil || len(drift) != 1 || !strings.HasPrefix(drift[0], "drift: sing-box pinned=") || !strings.Contains(drift[0], " path=") {
		t.Fatalf("different drift=%v err=%v", drift, err)
	}
}

func testInstallConfig(t *testing.T) ServiceConfig {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	return ServiceConfig{
		Label:      "works.relux.test-vpn-core",
		PlistPath:  filepath.Join(root, "service.plist"),
		SocketPath: filepath.Join(root, "run", "service.sock"),
		HelperDir:  filepath.Join(root, "helper"),
	}
}

func withInstallSeams(t *testing.T, ensure func() error, run func(string, ...string) ([]byte, error)) {
	t.Helper()
	previousEnsure := ensureSudoCredentialsVPNCore
	previousRun := runPrivilegedCommandVPNCore
	ensureSudoCredentialsVPNCore = ensure
	runPrivilegedCommandVPNCore = run
	t.Cleanup(func() {
		ensureSudoCredentialsVPNCore = previousEnsure
		runPrivilegedCommandVPNCore = previousRun
	})
}

// performFakeInstall emulates `install` for the recorded privileged commands so
// the post-install verification reads real destination files. tamper, when set,
// rewrites the copied bytes for destinations whose base name it returns true for.
func performFakeInstall(name string, args []string, tamper func(dest string) []byte) error {
	if name == "rm" {
		for _, path := range args[1:] {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
		return nil
	}
	if name != "install" || len(args) < 2 || args[0] == "-d" {
		if name == "install" && len(args) > 0 && args[0] == "-d" {
			return os.MkdirAll(args[len(args)-1], 0o755)
		}
		return nil
	}
	source, dest := args[len(args)-2], args[len(args)-1]
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if tamper != nil {
		if replaced := tamper(dest); replaced != nil {
			data = replaced
		}
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func withInstallVerification(t *testing.T, owner ownerLookup, checkACL func(string, int) error) {
	t.Helper()
	previous := installVerificationDepsVPNCore
	installVerificationDepsVPNCore = func() verificationDependencies {
		return verificationDependencies{
			owner:    owner,
			group:    func(string, *unix.Stat_t) (uint32, error) { return 0, nil },
			checkACL: checkACL,
		}
	}
	t.Cleanup(func() { installVerificationDepsVPNCore = previous })
}

func launchctlTestError(exitCode int, output []byte) error {
	return &commandError{Name: "launchctl", Args: []string{"print"}, ExitCode: exitCode, Output: output, Err: errors.New("exit status")}
}

func TestInstallServiceRefusesSymlinkedHelperParentBeforePrivilege(t *testing.T) {
	// This proves a symlinked intermediate helper parent is refused before any privileged command runs.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	realParent := filepath.Join(filepath.Dir(cfg.HelperDir), "real-parent")
	if err := os.Mkdir(realParent, 0o755); err != nil {
		t.Fatal(err)
	}
	linkedParent := filepath.Join(filepath.Dir(cfg.HelperDir), "linked-parent")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatal(err)
	}
	cfg.HelperDir = filepath.Join(linkedParent, "helper")
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	})
	if err := InstallService(cfg, binary, 501, 20, digest); err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("InstallService() error = %v, want symlinked-parent refusal", err)
	}
	if len(commands) != 0 {
		t.Fatalf("privileged commands = %v, want none", commands)
	}
}

func TestUninstallServiceRefusesUnsafeHelperParentBeforePrivilege(t *testing.T) {
	// These cases prove group-writable and non-root helper parents are refused before any privileged command runs.
	for _, test := range []struct {
		name  string
		setup func(t *testing.T, cfg ServiceConfig) ownerLookup
		want  string
	}{
		{
			name: "group-writable",
			setup: func(t *testing.T, cfg ServiceConfig) ownerLookup {
				if err := os.Chmod(filepath.Dir(cfg.HelperDir), 0o775); err != nil {
					t.Fatal(err)
				}
				return func(string, *unix.Stat_t) (uint32, error) { return 0, nil }
			},
			want: "group/world-writable",
		},
		{
			name: "non-root",
			setup: func(_ *testing.T, cfg ServiceConfig) ownerLookup {
				return func(path string, _ *unix.Stat_t) (uint32, error) {
					if path == filepath.Dir(cfg.HelperDir) {
						return 501, nil
					}
					return 0, nil
				}
			},
			want: "want root",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testInstallConfig(t)
			withInstallVerification(t, test.setup(t, cfg), func(string, int) error { return nil })
			var commands []string
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				commands = append(commands, strings.Join(append([]string{name}, args...), " "))
				return nil, nil
			})
			if err := UninstallService(cfg); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("UninstallService() error = %v, want %q", err, test.want)
			}
			if len(commands) != 0 {
				t.Fatalf("privileged commands = %v, want none", commands)
			}
		})
	}
}

// A staged file swapped between hashing and the privileged copy is caught on
// the root-owned destination; launchd is never touched and the files are removed.
func TestInstallServiceRefusesSwappedStagedFiles(t *testing.T) {
	for _, target := range []string{"vpn-core", "manifest.json", "service.plist"} {
		t.Run(target, func(t *testing.T) {
			binary := writeInstallTestBinary(t)
			digest, err := InstallDigest(binary)
			if err != nil {
				t.Fatalf("InstallDigest() error = %v", err)
			}
			cfg := testInstallConfig(t)
			withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
			var commands []string
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				commands = append(commands, strings.Join(append([]string{name}, args...), " "))
				return nil, performFakeInstall(name, args, func(dest string) []byte {
					if filepath.Base(dest) == target {
						return []byte("attacker payload\n")
					}
					return nil
				})
			})
			err = InstallService(cfg, binary, 501, 20, digest)
			if err == nil || !strings.Contains(err.Error(), "nothing was bootstrapped") {
				t.Fatalf("InstallService() error = %v, want verification refusal", err)
			}
			joined := strings.Join(commands, "\n")
			if strings.Contains(joined, "launchctl") {
				t.Fatalf("launchctl was invoked after a failed verification: %v", commands)
			}
			if !strings.Contains(joined, "rm -rf "+cfg.HelperDir) || !strings.Contains(joined, "rm -f "+cfg.PlistPath) {
				t.Fatalf("installed files were not removed: %v", commands)
			}
		})
	}
}

// Destinations that end up owned by a non-root user are refused the same way.
func TestInstallServiceRefusesNonRootOwnedDestinations(t *testing.T) {
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatalf("InstallDigest() error = %v", err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(path string, _ *unix.Stat_t) (uint32, error) {
		if path == cfg.HelperDir {
			return 501, nil
		}
		return 0, nil
	}, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "want root") {
		t.Fatalf("InstallService() error = %v, want root-owner refusal", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl bootstrap") {
		t.Fatalf("bootstrap ran despite failed verification: %v", commands)
	}
}

func TestInstallServiceRefusesHelperSymlinkThatSurvivesPrivilegedPreparation(t *testing.T) {
	// This proves a pre-existing helper symlink cannot survive preparation and reach launchctl even if the privileged removal seam is subverted.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	target := t.TempDir()
	if err := os.Symlink(target, cfg.HelperDir); err != nil {
		t.Fatal(err)
	}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "rm" && len(args) > 1 && args[0] == "-rf" && args[1] == cfg.HelperDir {
			return nil, nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "without following symlinks") {
		t.Fatalf("InstallService() error = %v, want symlink refusal", err)
	}
	joined := strings.Join(commands, "\n")
	if !strings.Contains(joined, "rm -rf "+cfg.HelperDir) {
		t.Fatalf("final helper symlink was refused before intended removal: %v", commands)
	}
	if strings.Contains(joined, "launchctl") {
		t.Fatalf("launchctl was invoked for symlinked helper: %v", commands)
	}
}

func TestInstallServiceRefusesWriteACLOnHelperDirectory(t *testing.T) {
	// This proves a write ACL on the freshly created helper directory aborts installation and cleanup before launchctl.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(path string, _ int) error {
		if path == cfg.HelperDir {
			return errors.New("write-capable ACL entry")
		}
		return nil
	})
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "write-capable ACL") {
		t.Fatalf("InstallService() error = %v, want ACL refusal", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl") {
		t.Fatalf("launchctl was invoked for ACL failure: %v", commands)
	}
}

func TestInstallServiceFailsWhenBootoutLeavesServiceLoaded(t *testing.T) {
	// This proves a failed bootout cannot be ignored when launchd continues to report the service loaded, and bootstrap never runs.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	var commands []string
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		if name == "launchctl" && args[0] == "bootout" {
			return nil, errors.New("bootout refused")
		}
		if name == "launchctl" && args[0] == "print" {
			return []byte("still loaded"), nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("InstallService() error = %v, want loaded-service failure", err)
	}
	if strings.Contains(strings.Join(commands, "\n"), "launchctl bootstrap") {
		t.Fatalf("bootstrap ran while old service stayed loaded: %v", commands)
	}
}

func TestUninstallServiceFailsWhenBootoutLeavesServiceLoaded(t *testing.T) {
	// This proves uninstall reports a bootout failure when launchd retains the label even if path cleanup succeeds.
	cfg := testInstallConfig(t)
	if err := os.Mkdir(cfg.HelperDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.PlistPath, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "bootout" {
			return nil, errors.New("bootout refused")
		}
		if name == "launchctl" && args[0] == "print" {
			return []byte("still loaded"), nil
		}
		return nil, performFakeInstall(name, args, nil)
	})
	if err := UninstallService(cfg); err == nil || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("UninstallService() error = %v, want loaded-service failure", err)
	}
}

func TestUninstallServiceToleratesVerifiedAbsentState(t *testing.T) {
	// This proves bootout/removal command failures are tolerated only when launchd and every configured service path are verified absent.
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(113, nil)
		}
		return nil, errors.New("already absent")
	})
	if err := UninstallService(cfg); err != nil {
		t.Fatalf("UninstallService() error = %v for verified absent state", err)
	}
}

func TestForgetLaunchdLabelRecognizesOnlyExplicitAbsence(t *testing.T) {
	// These cases prove only exit 113 or launchd's service-not-found output is classified as absence.
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "exit-113", err: launchctlTestError(113, []byte("other output"))},
		{name: "service-not-found-output", err: launchctlTestError(1, []byte("Could not find service \"system/example\""))},
	} {
		t.Run(test.name, func(t *testing.T) {
			withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
				if name == "launchctl" && args[0] == "print" {
					return nil, test.err
				}
				return nil, nil
			})
			if err := forgetLaunchdLabel("works.relux.test"); err != nil {
				t.Fatalf("forgetLaunchdLabel() error = %v", err)
			}
		})
	}
}

func TestForgetLaunchdLabelKeepsPollingAfterNonAbsentError(t *testing.T) {
	// This proves a transient non-absence print error keeps polling and can be followed by confirmed absence.
	previousNow := installNowVPNCore
	previousSleep := installSleepVPNCore
	base := time.Unix(1, 0)
	installNowVPNCore = func() time.Time { return base }
	installSleepVPNCore = func(time.Duration) {}
	t.Cleanup(func() {
		installNowVPNCore = previousNow
		installSleepVPNCore = previousSleep
	})
	printCalls := 0
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			printCalls++
			if printCalls == 1 {
				return nil, launchctlTestError(1, []byte("Operation not permitted"))
			}
			return nil, launchctlTestError(113, nil)
		}
		return nil, nil
	})
	if err := forgetLaunchdLabel("works.relux.test"); err != nil {
		t.Fatalf("forgetLaunchdLabel() error = %v", err)
	}
	if printCalls != 2 {
		t.Fatalf("launchctl print calls = %d, want 2", printCalls)
	}
}

func TestInstallServicePropagatesLaunchctlPrintPermissionFailure(t *testing.T) {
	// This proves install fails instead of treating a non-absence launchctl print error as a forgotten service.
	binary := writeInstallTestBinary(t)
	digest, err := InstallDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(1, []byte("Operation not permitted"))
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err = InstallService(cfg, binary, 501, 20, digest)
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("InstallService() error = %v, want bounded permission failure", err)
	}
}

func TestUninstallServicePropagatesLaunchctlPrintPermissionFailure(t *testing.T) {
	// This proves uninstall fails after the bounded poll when launchctl print reports a non-absence error.
	cfg := testInstallConfig(t)
	withInstallVerification(t, func(string, *unix.Stat_t) (uint32, error) { return 0, nil }, func(string, int) error { return nil })
	withExpiredInstallClock(t)
	withInstallSeams(t, func() error { return nil }, func(name string, args ...string) ([]byte, error) {
		if name == "launchctl" && args[0] == "print" {
			return nil, launchctlTestError(1, []byte("Operation not permitted"))
		}
		return nil, performFakeInstall(name, args, nil)
	})
	err := UninstallService(cfg)
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") || !strings.Contains(err.Error(), "did not forget") {
		t.Fatalf("UninstallService() error = %v, want bounded permission failure", err)
	}
}

func TestRunCommandPreservesFailureOutputAndExitCode(t *testing.T) {
	// This proves command failures retain raw output and the process exit code for launchd absence classification.
	output, err := runCommand("/bin/sh", "-c", "printf 'Could not find service'; exit 113")
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("runCommand() error = %T %v, want *commandError", err, err)
	}
	if commandErr.ExitCode != 113 || string(commandErr.Output) != "Could not find service" || string(output) != "Could not find service" {
		t.Fatalf("runCommand() = (%q, exit=%d, raw=%q), want preserved output and exit 113", output, commandErr.ExitCode, commandErr.Output)
	}
}

func withExpiredInstallClock(t *testing.T) {
	t.Helper()
	previousNow := installNowVPNCore
	previousSleep := installSleepVPNCore
	base := time.Unix(1, 0)
	calls := 0
	installNowVPNCore = func() time.Time {
		calls++
		if calls == 1 {
			return base
		}
		return base.Add(launchctlForgetTimeout)
	}
	installSleepVPNCore = func(time.Duration) {}
	t.Cleanup(func() {
		installNowVPNCore = previousNow
		installSleepVPNCore = previousSleep
	})
}
