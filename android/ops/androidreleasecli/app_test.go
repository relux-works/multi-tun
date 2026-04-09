package androidreleasecli

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"multi-tun/internal/keychain"
)

func TestRunSetupWritesConfigAndSeedsKeychainPlaceholders(t *testing.T) {
	originalSet := keychainSetWithOptionsAndroidRelease
	originalExists := keychainExistsAndroidRelease
	originalGet := keychainGetAndroidRelease
	t.Cleanup(func() {
		keychainSetWithOptionsAndroidRelease = originalSet
		keychainExistsAndroidRelease = originalExists
		keychainGetAndroidRelease = originalGet
	})

	root := newAndroidProjectRoot(t)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)

	type write struct {
		value string
		label string
	}
	writes := map[string]write{}
	keychainSetWithOptionsAndroidRelease = func(account, value string, options keychain.SetOptions) error {
		writes[account] = write{value: value, label: options.Label}
		return nil
	}
	keychainExistsAndroidRelease = func(account string) bool { return false }
	keychainGetAndroidRelease = func(account string) (string, error) {
		return "", fmt.Errorf("unexpected get for %s", account)
	}

	exitCode := app.Run([]string{"setup", "--project-root", root})
	if exitCode != 0 {
		t.Fatalf("Run(setup) exitCode = %d, stderr=%s", exitCode, stderr.String())
	}

	configPath := filepath.Join(root, "android", "keystore.properties")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(configPath) error = %v", err)
	}
	if string(raw) != "storeFile=keystore/upload.jks\nkeyAlias=upload\n" {
		t.Fatalf("config body = %q", string(raw))
	}
	if got := writes[storePasswordKeychainAccount].value; got != placeholderSecret {
		t.Fatalf("store password placeholder = %q", got)
	}
	if got := writes[keyPasswordKeychainAccount].value; got != placeholderSecret {
		t.Fatalf("key password placeholder = %q", got)
	}
	if !strings.Contains(stdout.String(), "configured "+configPath) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunBundleFailsWhenPlaceholderSecretsRemain(t *testing.T) {
	originalGet := keychainGetAndroidRelease
	t.Cleanup(func() {
		keychainGetAndroidRelease = originalGet
	})

	root := newAndroidProjectRoot(t)
	configPath := filepath.Join(root, "android", "keystore.properties")
	if err := os.WriteFile(configPath, []byte("storeFile=keystore/upload.jks\nkeyAlias=upload\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "android", "keystore"), 0o755); err != nil {
		t.Fatalf("MkdirAll(keystore) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "android", "keystore", "upload.jks"), []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile(keystore) error = %v", err)
	}

	keychainGetAndroidRelease = func(account string) (string, error) {
		return placeholderSecret, nil
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	exitCode := app.Run([]string{"bundle", "--project-root", root})
	if exitCode != 1 {
		t.Fatalf("Run(bundle) exitCode = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "placeholder secret still set") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunBundleInjectsSecretsIntoGradleEnvironment(t *testing.T) {
	originalGet := keychainGetAndroidRelease
	originalExec := execCommandAndroidRelease
	t.Cleanup(func() {
		keychainGetAndroidRelease = originalGet
		execCommandAndroidRelease = originalExec
	})

	root := newAndroidProjectRoot(t)
	configPath := filepath.Join(root, "android", "keystore.properties")
	if err := os.WriteFile(configPath, []byte("storeFile=keystore/upload.jks\nkeyAlias=upload\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "android", "keystore"), 0o755); err != nil {
		t.Fatalf("MkdirAll(keystore) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "android", "keystore", "upload.jks"), []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile(keystore) error = %v", err)
	}

	keychainGetAndroidRelease = func(account string) (string, error) {
		switch account {
		case storePasswordKeychainAccount:
			return "store-secret", nil
		case keyPasswordKeychainAccount:
			return "key-secret", nil
		default:
			return "", fmt.Errorf("unexpected account %s", account)
		}
	}

	execCommandAndroidRelease = func(name string, args ...string) *exec.Cmd {
		cmdArgs := append([]string{"-test.run=TestHelperProcessAndroidRelease", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_ANDROID_RELEASE=1")
		return cmd
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	exitCode := app.Run([]string{"bundle", "--project-root", root})
	if exitCode != 0 {
		t.Fatalf("Run(bundle) exitCode = %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle: "+filepath.Join(root, "android", "app", "build", "outputs", "bundle", "release", "app-release.aab")) {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "native_debug_symbols: "+filepath.Join(root, "android", "app", "build", "outputs", "native-debug-symbols", "release", "native-debug-symbols.zip")) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunPublishInjectsPlayCredentialsAndTrack(t *testing.T) {
	originalGet := keychainGetAndroidRelease
	originalExec := execCommandAndroidRelease
	t.Cleanup(func() {
		keychainGetAndroidRelease = originalGet
		execCommandAndroidRelease = originalExec
	})

	root := newAndroidProjectRoot(t)
	configPath := filepath.Join(root, "android", "keystore.properties")
	if err := os.WriteFile(configPath, []byte("storeFile=keystore/upload.jks\nkeyAlias=upload\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(configPath) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "android", "keystore"), 0o755); err != nil {
		t.Fatalf("MkdirAll(keystore) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "android", "keystore", "upload.jks"), []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile(keystore) error = %v", err)
	}

	publisherJSONPath := filepath.Join(root, "publisher.json")
	if err := os.WriteFile(publisherJSONPath, []byte("{\"type\":\"service_account\"}"), 0o600); err != nil {
		t.Fatalf("WriteFile(publisherJSONPath) error = %v", err)
	}

	keychainGetAndroidRelease = func(account string) (string, error) {
		switch account {
		case storePasswordKeychainAccount:
			return "store-secret", nil
		case keyPasswordKeychainAccount:
			return "key-secret", nil
		default:
			return "", fmt.Errorf("unexpected account %s", account)
		}
	}

	execCommandAndroidRelease = func(name string, args ...string) *exec.Cmd {
		cmdArgs := append([]string{"-test.run=TestHelperProcessAndroidRelease", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS_ANDROID_RELEASE=1")
		return cmd
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := New(&stdout, &stderr)
	exitCode := app.Run([]string{
		"publish",
		"--project-root", root,
		"--publisher-json", publisherJSONPath,
		"--track", "internal",
	})
	if exitCode != 0 {
		t.Fatalf("Run(publish) exitCode = %d, stderr=%s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "published ") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestHelperProcessAndroidRelease(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS_ANDROID_RELEASE") != "1" {
		return
	}
	args := os.Args
	sep := 0
	for idx, arg := range args {
		if arg == "--" {
			sep = idx
			break
		}
	}
	if sep == 0 || len(args) <= sep+1 {
		fmt.Fprintln(os.Stderr, "missing helper args")
		os.Exit(2)
	}

	command := args[sep+1]
	commandArgs := args[sep+2:]
	if !strings.HasSuffix(command, "gradlew") {
		fmt.Fprintf(os.Stderr, "unexpected command %q\n", command)
		os.Exit(2)
	}
	androidDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	outputPath := filepath.Join(androidDir, "app", "build", "outputs", "bundle", "release", "app-release.aab")
	switch {
	case len(commandArgs) == 1 && commandArgs[0] == ":app:bundleRelease":
		if os.Getenv("VLESS_TUN_ANDROID_STORE_PASSWORD") != "store-secret" {
			fmt.Fprintln(os.Stderr, "missing store password env")
			os.Exit(2)
		}
		if os.Getenv("VLESS_TUN_ANDROID_KEY_PASSWORD") != "key-secret" {
			fmt.Fprintln(os.Stderr, "missing key password env")
			os.Exit(2)
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile(outputPath, []byte("bundle"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		nativeLibPath := filepath.Join(androidDir, "app", "build", "intermediates", "merged_native_libs", "release", "mergeReleaseNativeLibs", "out", "lib", "arm64-v8a", "libbox.so")
		if err := os.MkdirAll(filepath.Dir(nativeLibPath), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile(nativeLibPath, []byte("symbols"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case len(commandArgs) == 4 &&
		commandArgs[0] == ":app:publishReleaseBundle" &&
		commandArgs[1] == "--artifact-dir" &&
		strings.HasSuffix(commandArgs[2], filepath.ToSlash("android/app/build/outputs/bundle/release")) &&
		commandArgs[3] == "-PVLESS_TUN_ANDROID_PLAY_TRACK=internal":
		if os.Getenv("ANDROID_PUBLISHER_CREDENTIALS") != "{\"type\":\"service_account\"}" {
			fmt.Fprintln(os.Stderr, "missing publisher credentials env")
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unexpected args %v\n", commandArgs)
		os.Exit(2)
	}
	os.Exit(0)
}

func newAndroidProjectRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	androidDir := filepath.Join(root, "android")
	if err := os.MkdirAll(androidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(androidDir) error = %v", err)
	}
	gradlewPath := filepath.Join(androidDir, "gradlew")
	if err := os.WriteFile(gradlewPath, []byte("#!/usr/bin/env bash\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(gradlew) error = %v", err)
	}
	return root
}

func TestPackageNativeDebugSymbolsPrefersAGPOutput(t *testing.T) {
	root := newAndroidProjectRoot(t)
	layout, err := resolveLayout(root)
	if err != nil {
		t.Fatalf("resolveLayout error = %v", err)
	}

	agpPath := filepath.Join(
		root,
		"android",
		"app",
		"build",
		"intermediates",
		"native_symbol_tables",
		"release",
		"extractReleaseNativeSymbolTables",
		"out",
		"lib",
		"arm64-v8a",
		"libbox.so",
	)
	mergedPath := filepath.Join(
		root,
		"android",
		"app",
		"build",
		"intermediates",
		"merged_native_libs",
		"release",
		"mergeReleaseNativeLibs",
		"out",
		"lib",
		"arm64-v8a",
		"libbox.so",
	)
	if err := os.MkdirAll(filepath.Dir(agpPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(agpPath) error = %v", err)
	}
	if err := os.WriteFile(agpPath, []byte("from-agp"), 0o600); err != nil {
		t.Fatalf("WriteFile(agpPath) error = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(mergedPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(mergedPath) error = %v", err)
	}
	if err := os.WriteFile(mergedPath, []byte("from-merged"), 0o600); err != nil {
		t.Fatalf("WriteFile(mergedPath) error = %v", err)
	}

	zipPath, fallbackUsed, err := packageNativeDebugSymbols(layout)
	if err != nil {
		t.Fatalf("packageNativeDebugSymbols error = %v", err)
	}
	if fallbackUsed {
		t.Fatalf("fallbackUsed = true, want false")
	}
	if zipPath != layout.nativeSymbolsPath {
		t.Fatalf("zipPath = %q, want %q", zipPath, layout.nativeSymbolsPath)
	}

	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("zip.OpenReader error = %v", err)
	}
	defer archive.Close()

	if len(archive.File) != 1 {
		t.Fatalf("archive file count = %d, want 1", len(archive.File))
	}
	if archive.File[0].Name != "arm64-v8a/libbox.so" {
		t.Fatalf("entry name = %q", archive.File[0].Name)
	}
	raw := readZipEntry(t, archive.File[0])
	if string(raw) != "from-agp" {
		t.Fatalf("entry body = %q", string(raw))
	}
}

func TestPackageNativeDebugSymbolsFallsBackToMergedNativeLibs(t *testing.T) {
	root := newAndroidProjectRoot(t)
	layout, err := resolveLayout(root)
	if err != nil {
		t.Fatalf("resolveLayout error = %v", err)
	}

	mergedPath := filepath.Join(
		root,
		"android",
		"app",
		"build",
		"intermediates",
		"merged_native_libs",
		"release",
		"mergeReleaseNativeLibs",
		"out",
		"lib",
		"arm64-v8a",
		"libbox.so",
	)
	if err := os.MkdirAll(filepath.Dir(mergedPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(mergedPath) error = %v", err)
	}
	if err := os.WriteFile(mergedPath, []byte("from-merged"), 0o600); err != nil {
		t.Fatalf("WriteFile(mergedPath) error = %v", err)
	}

	zipPath, fallbackUsed, err := packageNativeDebugSymbols(layout)
	if err != nil {
		t.Fatalf("packageNativeDebugSymbols error = %v", err)
	}
	if !fallbackUsed {
		t.Fatalf("fallbackUsed = false, want true")
	}
	if zipPath != layout.nativeSymbolsPath {
		t.Fatalf("zipPath = %q, want %q", zipPath, layout.nativeSymbolsPath)
	}

	archive, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("zip.OpenReader error = %v", err)
	}
	defer archive.Close()

	if len(archive.File) != 1 {
		t.Fatalf("archive file count = %d, want 1", len(archive.File))
	}
	if archive.File[0].Name != "arm64-v8a/libbox.so" {
		t.Fatalf("entry name = %q", archive.File[0].Name)
	}
	raw := readZipEntry(t, archive.File[0])
	if string(raw) != "from-merged" {
		t.Fatalf("entry body = %q", string(raw))
	}
}

func readZipEntry(t *testing.T, file *zip.File) []byte {
	t.Helper()
	reader, err := file.Open()
	if err != nil {
		t.Fatalf("file.Open error = %v", err)
	}
	defer reader.Close()

	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("io.ReadAll error = %v", err)
	}
	return raw
}
