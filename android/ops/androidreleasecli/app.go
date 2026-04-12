package androidreleasecli

import (
	"archive/zip"
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"multi-tun/internal/keychain"
)

const (
	defaultStoreFile             = "keystore/upload.jks"
	defaultKeyAlias              = "upload"
	placeholderSecret            = "__SET_ME__"
	storePasswordKeychainAccount = "works.relux.android.vlesstun.app/release-store-password"
	keyPasswordKeychainAccount   = "works.relux.android.vlesstun.app/release-key-password"
	releaseNotesFilename         = "release-notes.txt"
)

type App struct {
	stdout io.Writer
	stderr io.Writer
}

type layout struct {
	projectRoot       string
	androidDir        string
	gradlewPath       string
	keystoreConfig    string
	bundlePath        string
	nativeSymbolsPath string
}

type signingMetadata struct {
	StoreFile     string
	KeyAlias      string
	StorePassword string
	KeyPassword   string
}

var (
	keychainSetWithOptionsAndroidRelease = keychain.SetWithOptions
	keychainGetAndroidRelease            = keychain.Get
	keychainExistsAndroidRelease         = keychain.Exists
	execCommandAndroidRelease            = exec.Command
	lookPathAndroidRelease               = exec.LookPath
)

func New(stdout, stderr io.Writer) *App {
	return &App{stdout: stdout, stderr: stderr}
}

func (a *App) Run(args []string) int {
	if len(args) == 0 {
		a.printUsage()
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		a.printUsage()
		return 0
	case "setup":
		return a.runSetup(args[1:])
	case "generate-keystore":
		return a.runGenerateKeystore(args[1:])
	case "bundle":
		return a.runBundle(args[1:])
	case "publish":
		return a.runPublish(args[1:])
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", args[0])
		a.printUsage()
		return 2
	}
}

func (a *App) runSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	projectRoot := fs.String("project-root", ".", "Repository root that contains android/")
	storeFile := fs.String("store-file", defaultStoreFile, "Keystore path relative to android/")
	keyAlias := fs.String("key-alias", defaultKeyAlias, "Upload key alias")
	force := fs.Bool("force", false, "Overwrite android/keystore.properties and reseed placeholders")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	layout, err := resolveLayout(*projectRoot)
	if err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 1
	}

	configBody := renderKeystoreProperties(*storeFile, *keyAlias)
	if err := writeKeystoreProperties(layout.keystoreConfig, configBody, *force); err != nil {
		fmt.Fprintf(a.stderr, "setup failed: %v\n", err)
		return 1
	}

	entries := []struct {
		account string
		label   string
		kind    string
	}{
		{
			account: storePasswordKeychainAccount,
			label:   "multi-tun Android release keystore password",
			kind:    "multi-tun Android release secret",
		},
		{
			account: keyPasswordKeychainAccount,
			label:   "multi-tun Android release key password",
			kind:    "multi-tun Android release secret",
		},
	}
	for _, entry := range entries {
		value := placeholderSecret
		if !*force && keychainExistsAndroidRelease(entry.account) {
			current, err := keychainGetAndroidRelease(entry.account)
			if err != nil {
				fmt.Fprintf(a.stderr, "setup failed: read keychain %q: %v\n", entry.account, err)
				return 1
			}
			value = current
		}
		if err := keychainSetWithOptionsAndroidRelease(entry.account, value, keychain.SetOptions{
			Label:   entry.label,
			Kind:    entry.kind,
			Comment: "Used by android-release bundle for Play test-track signing",
		}); err != nil {
			fmt.Fprintf(a.stderr, "setup failed: seed keychain %q: %v\n", entry.account, err)
			return 1
		}
	}

	fmt.Fprintf(a.stdout, "configured %s\n", layout.keystoreConfig)
	fmt.Fprintf(a.stdout, "store_file: %s\n", *storeFile)
	fmt.Fprintf(a.stdout, "key_alias: %s\n", *keyAlias)
	fmt.Fprintf(a.stdout, "store_password_keychain_account: %s\n", storePasswordKeychainAccount)
	fmt.Fprintf(a.stdout, "key_password_keychain_account: %s\n", keyPasswordKeychainAccount)
	fmt.Fprintln(a.stdout, "next:")
	fmt.Fprintln(a.stdout, "  android-release generate-keystore")
	fmt.Fprintln(a.stdout, "  replace placeholder secrets in macOS Keychain")
	fmt.Fprintln(a.stdout, "  android-release bundle")
	return 0
}

func (a *App) runGenerateKeystore(args []string) int {
	fs := flag.NewFlagSet("generate-keystore", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	projectRoot := fs.String("project-root", ".", "Repository root that contains android/")
	storeFile := fs.String("store-file", defaultStoreFile, "Keystore path relative to android/")
	keyAlias := fs.String("key-alias", defaultKeyAlias, "Upload key alias")
	validityDays := fs.Int("validity-days", 10000, "Certificate validity in days")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	layout, err := resolveLayout(*projectRoot)
	if err != nil {
		fmt.Fprintf(a.stderr, "generate-keystore failed: %v\n", err)
		return 1
	}

	keytoolPath, err := resolveKeytool()
	if err != nil {
		fmt.Fprintf(a.stderr, "generate-keystore failed: %v\n", err)
		return 1
	}

	targetPath := *storeFile
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(layout.androidDir, filepath.FromSlash(*storeFile))
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		fmt.Fprintf(a.stderr, "generate-keystore failed: mkdir keystore dir: %v\n", err)
		return 1
	}

	cmd := execCommandAndroidRelease(
		keytoolPath,
		"-genkeypair",
		"-v",
		"-keystore", targetPath,
		"-alias", *keyAlias,
		"-storetype", "PKCS12",
		"-keyalg", "RSA",
		"-keysize", "4096",
		"-validity", fmt.Sprintf("%d", *validityDays),
	)
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(a.stderr, "generate-keystore failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "generated %s\n", targetPath)
	return 0
}

func (a *App) runBundle(args []string) int {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	projectRoot := fs.String("project-root", ".", "Repository root that contains android/")
	clean := fs.Bool("clean", false, "Run :app:clean before bundleRelease")
	storePasswordAccount := fs.String("store-password-account", storePasswordKeychainAccount, "Keychain account for keystore password")
	keyPasswordAccount := fs.String("key-password-account", keyPasswordKeychainAccount, "Keychain account for key password")
	releaseNotes := fs.String("release-notes", "", "Inline release notes text to copy next to the release bundle")
	releaseNotesFile := fs.String("release-notes-file", "", "Path to a text file whose contents should be copied next to the release bundle")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	releaseNotesBody, err := resolveReleaseNotes(*releaseNotes, *releaseNotesFile)
	if err != nil {
		fmt.Fprintf(a.stderr, "bundle failed: %v\n", err)
		return 1
	}

	layout, err := a.bundleRelease(*projectRoot, *clean, *storePasswordAccount, *keyPasswordAccount, releaseNotesBody)
	if err != nil {
		fmt.Fprintf(a.stderr, "bundle failed: %v\n", err)
		return 1
	}

	if _, err := os.Stat(layout.bundlePath); err != nil {
		fmt.Fprintf(a.stderr, "bundle failed: output not found: %s\n", layout.bundlePath)
		return 1
	}

	fmt.Fprintf(a.stdout, "bundle: %s\n", layout.bundlePath)
	return 0
}

func (a *App) runPublish(args []string) int {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.SetOutput(a.stderr)

	projectRoot := fs.String("project-root", ".", "Repository root that contains android/")
	track := fs.String("track", "internal", "Google Play track to publish to")
	publisherJSON := fs.String("publisher-json", "", "Path to Google Play service account JSON key")
	clean := fs.Bool("clean", false, "Run :app:clean before bundleRelease")
	skipBundle := fs.Bool("skip-bundle", false, "Skip bundleRelease and publish an existing app-release.aab")
	storePasswordAccount := fs.String("store-password-account", storePasswordKeychainAccount, "Keychain account for keystore password")
	keyPasswordAccount := fs.String("key-password-account", keyPasswordKeychainAccount, "Keychain account for key password")
	releaseNotes := fs.String("release-notes", "", "Inline release notes text to copy next to the release bundle")
	releaseNotesFile := fs.String("release-notes-file", "", "Path to a text file whose contents should be copied next to the release bundle")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	releaseNotesBody, err := resolveReleaseNotes(*releaseNotes, *releaseNotesFile)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	layout, err := resolveLayout(*projectRoot)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	metadata, err := readSigningMetadata(layout.keystoreConfig)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}
	storePassword, err := resolveSecret(*storePasswordAccount, metadata.StorePassword)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}
	keyPassword, err := resolveSecret(*keyPasswordAccount, metadata.KeyPassword)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	if !*skipBundle {
		layout, err = a.bundleRelease(*projectRoot, *clean, *storePasswordAccount, *keyPasswordAccount, releaseNotesBody)
		if err != nil {
			fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
			return 1
		}
	}

	if _, err := os.Stat(layout.bundlePath); err != nil {
		fmt.Fprintf(a.stderr, "publish failed: signed bundle not found: %s\n", layout.bundlePath)
		return 1
	}
	if err := writeReleaseNotesSidecar(a.stdout, layout.bundlePath, releaseNotesBody); err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	publisherCredentials, err := resolvePublisherCredentials(*publisherJSON)
	if err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	cmd := execCommandAndroidRelease(
		layout.gradlewPath,
		":app:publishReleaseBundle",
		"--artifact-dir", filepath.Dir(layout.bundlePath),
		"-PVLESS_TUN_ANDROID_PLAY_TRACK="+strings.TrimSpace(*track),
	)
	cmd.Dir = layout.androidDir
	cmd.Stdout = a.stdout
	cmd.Stderr = a.stderr
	cmd.Stdin = os.Stdin
	baseEnv := cmd.Env
	if len(baseEnv) == 0 {
		baseEnv = os.Environ()
	}
	cmd.Env = append(
		baseEnv,
		"ANDROID_PUBLISHER_CREDENTIALS="+publisherCredentials,
		"VLESS_TUN_ANDROID_STORE_PASSWORD="+storePassword,
		"VLESS_TUN_ANDROID_KEY_PASSWORD="+keyPassword,
	)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(a.stderr, "publish failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(a.stdout, "published %s to track %s\n", layout.bundlePath, strings.TrimSpace(*track))
	return 0
}

func (a *App) printUsage() {
	fmt.Fprintln(a.stdout, "android-release prepares and builds the Android app for Play test tracks.")
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Usage:")
	fmt.Fprintln(a.stdout, "  android-release setup")
	fmt.Fprintln(a.stdout, "  android-release generate-keystore")
	fmt.Fprintln(a.stdout, "  android-release bundle")
	fmt.Fprintln(a.stdout, "  android-release publish")
}

func resolveLayout(projectRoot string) (layout, error) {
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return layout{}, fmt.Errorf("resolve project root: %w", err)
	}
	androidDir := filepath.Join(root, "android")
	gradlewPath := filepath.Join(androidDir, "gradlew")
	if _, err := os.Stat(gradlewPath); err != nil {
		return layout{}, fmt.Errorf("android gradle wrapper not found under %s", androidDir)
	}
	return layout{
		projectRoot:       root,
		androidDir:        androidDir,
		gradlewPath:       gradlewPath,
		keystoreConfig:    filepath.Join(androidDir, "keystore.properties"),
		bundlePath:        filepath.Join(androidDir, "app", "build", "outputs", "bundle", "release", "app-release.aab"),
		nativeSymbolsPath: filepath.Join(androidDir, "app", "build", "outputs", "native-debug-symbols", "release", "native-debug-symbols.zip"),
	}, nil
}

func renderKeystoreProperties(storeFile, keyAlias string) string {
	return strings.TrimSpace(fmt.Sprintf(`
storeFile=%s
keyAlias=%s
`, storeFile, keyAlias)) + "\n"
}

func writeKeystoreProperties(path, body string, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func resolveKeytool() (string, error) {
	if javaHome := strings.TrimSpace(os.Getenv("JAVA_HOME")); javaHome != "" {
		candidate := filepath.Join(javaHome, "bin", "keytool")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	path, err := lookPathAndroidRelease("keytool")
	if err != nil {
		return "", errors.New("keytool not found; install a JDK or export JAVA_HOME")
	}
	return path, nil
}

func readSigningMetadata(path string) (signingMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return signingMetadata{}, fmt.Errorf("read %s: %w", path, err)
	}
	defer file.Close()

	var metadata signingMetadata
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "storeFile":
			metadata.StoreFile = value
		case "keyAlias":
			metadata.KeyAlias = value
		case "storePassword":
			metadata.StorePassword = value
		case "keyPassword":
			metadata.KeyPassword = value
		}
	}
	if err := scanner.Err(); err != nil {
		return signingMetadata{}, fmt.Errorf("scan %s: %w", path, err)
	}
	if metadata.StoreFile == "" {
		return signingMetadata{}, errors.New("android/keystore.properties is missing storeFile")
	}
	if metadata.KeyAlias == "" {
		return signingMetadata{}, errors.New("android/keystore.properties is missing keyAlias")
	}
	return metadata, nil
}

func resolveSecret(account, fallback string) (string, error) {
	if value := strings.TrimSpace(fallback); value != "" {
		if value == placeholderSecret {
			return "", fmt.Errorf("placeholder secret still set for %s", account)
		}
		return value, nil
	}
	value, err := keychainGetAndroidRelease(account)
	if err != nil {
		return "", fmt.Errorf("missing keychain secret %s", account)
	}
	value = strings.TrimSpace(value)
	if value == "" || value == placeholderSecret {
		return "", fmt.Errorf("placeholder secret still set for %s", account)
	}
	return value, nil
}

func (a *App) bundleRelease(projectRoot string, clean bool, storePasswordAccount, keyPasswordAccount, releaseNotes string) (layout, error) {
	layout, err := resolveLayout(projectRoot)
	if err != nil {
		return layout, err
	}

	metadata, err := readSigningMetadata(layout.keystoreConfig)
	if err != nil {
		return layout, err
	}

	storePassword, err := resolveSecret(storePasswordAccount, metadata.StorePassword)
	if err != nil {
		return layout, err
	}
	keyPassword, err := resolveSecret(keyPasswordAccount, metadata.KeyPassword)
	if err != nil {
		return layout, err
	}

	storeFilePath := metadata.StoreFile
	if !filepath.IsAbs(storeFilePath) {
		storeFilePath = filepath.Join(layout.androidDir, filepath.FromSlash(metadata.StoreFile))
	}
	if _, err := os.Stat(storeFilePath); err != nil {
		return layout, fmt.Errorf("missing keystore %s", storeFilePath)
	}

	steps := [][]string{}
	if clean {
		steps = append(steps, []string{layout.gradlewPath, ":app:clean"})
	}
	steps = append(steps, []string{layout.gradlewPath, ":app:bundleRelease"})

	for _, step := range steps {
		cmd := execCommandAndroidRelease(step[0], step[1:]...)
		cmd.Dir = layout.androidDir
		cmd.Stdout = a.stdout
		cmd.Stderr = a.stderr
		cmd.Stdin = os.Stdin
		baseEnv := cmd.Env
		if len(baseEnv) == 0 {
			baseEnv = os.Environ()
		}
		cmd.Env = append(
			baseEnv,
			"VLESS_TUN_ANDROID_STORE_PASSWORD="+storePassword,
			"VLESS_TUN_ANDROID_KEY_PASSWORD="+keyPassword,
		)
		if err := cmd.Run(); err != nil {
			return layout, err
		}
	}

	nativeSymbolsPath, fallbackUsed, err := packageNativeDebugSymbols(layout)
	if err != nil {
		return layout, err
	}
	if nativeSymbolsPath != "" {
		fmt.Fprintf(a.stdout, "native_debug_symbols: %s\n", nativeSymbolsPath)
		adjacentPath, err := copyFileAdjacentToBundle(layout.bundlePath, nativeSymbolsPath)
		if err != nil {
			return layout, err
		}
		fmt.Fprintf(a.stdout, "bundle_sidecar_native_debug_symbols: %s\n", adjacentPath)
		if fallbackUsed {
			fmt.Fprintf(
				a.stderr,
				"warning: AGP native symbol extraction output was empty; packaged fallback native libs from merged_native_libs instead\n",
			)
		}
	}
	if err := writeReleaseNotesSidecar(a.stdout, layout.bundlePath, releaseNotes); err != nil {
		return layout, err
	}

	return layout, nil
}

func copyFileAdjacentToBundle(bundlePath, sourcePath string) (string, error) {
	targetPath := filepath.Join(filepath.Dir(bundlePath), filepath.Base(sourcePath))
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", fmt.Errorf("mkdir bundle sidecar dir: %w", err)
	}
	if err := copyFile(sourcePath, targetPath); err != nil {
		return "", fmt.Errorf("copy bundle sidecar %s: %w", filepath.Base(sourcePath), err)
	}
	return targetPath, nil
}

func writeReleaseNotesSidecar(stdout io.Writer, bundlePath, releaseNotes string) error {
	releaseNotes = strings.TrimSpace(releaseNotes)
	if releaseNotes == "" {
		return nil
	}

	targetPath := filepath.Join(filepath.Dir(bundlePath), releaseNotesFilename)
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return fmt.Errorf("mkdir release notes dir: %w", err)
	}
	if err := os.WriteFile(targetPath, []byte(releaseNotes+"\n"), 0o644); err != nil {
		return fmt.Errorf("write release notes sidecar: %w", err)
	}
	fmt.Fprintf(stdout, "bundle_sidecar_release_notes: %s\n", targetPath)
	return nil
}

func resolveReleaseNotes(inline, path string) (string, error) {
	inline = strings.TrimSpace(inline)
	path = strings.TrimSpace(path)
	if inline != "" && path != "" {
		return "", errors.New("pass either --release-notes or --release-notes-file, not both")
	}
	if inline != "" {
		return inline, nil
	}
	if path == "" {
		return "", nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read release notes file %s: %w", path, err)
	}
	contents := strings.TrimSpace(string(raw))
	if contents == "" {
		return "", fmt.Errorf("release notes file %s is empty", path)
	}
	return contents, nil
}

func copyFile(sourcePath, targetPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return err
	}

	target, err := os.Create(targetPath)
	if err != nil {
		return err
	}

	_, copyErr := io.Copy(target, source)
	closeErr := target.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(targetPath, info.Mode().Perm())
}

func packageNativeDebugSymbols(layout layout) (string, bool, error) {
	candidates := []struct {
		root     string
		fallback bool
	}{
		{
			root: filepath.Join(
				layout.androidDir,
				"app",
				"build",
				"intermediates",
				"native_symbol_tables",
				"release",
				"extractReleaseNativeSymbolTables",
				"out",
				"lib",
			),
		},
		{
			root: filepath.Join(
				layout.androidDir,
				"app",
				"build",
				"intermediates",
				"native_symbol_tables",
				"release",
				"extractReleaseNativeSymbolTables",
				"out",
			),
		},
		{
			root: filepath.Join(
				layout.androidDir,
				"app",
				"build",
				"intermediates",
				"merged_native_libs",
				"release",
				"mergeReleaseNativeLibs",
				"out",
				"lib",
			),
			fallback: true,
		},
	}

	var sourceRoot string
	var fallbackUsed bool
	for _, candidate := range candidates {
		hasFiles, err := dirHasFiles(candidate.root)
		if err != nil {
			return "", false, err
		}
		if hasFiles {
			sourceRoot = candidate.root
			fallbackUsed = candidate.fallback
			break
		}
	}
	if sourceRoot == "" {
		return "", false, nil
	}

	if err := os.MkdirAll(filepath.Dir(layout.nativeSymbolsPath), 0o755); err != nil {
		return "", false, fmt.Errorf("mkdir native symbols dir: %w", err)
	}

	zipFile, err := os.Create(layout.nativeSymbolsPath)
	if err != nil {
		return "", false, fmt.Errorf("create native symbols zip: %w", err)
	}
	defer zipFile.Close()

	archive := zip.NewWriter(zipFile)
	if err := filepath.WalkDir(sourceRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		relativePath, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return fmt.Errorf("relative native symbol path: %w", err)
		}
		relativePath = filepath.ToSlash(relativePath)

		writer, err := archive.Create(relativePath)
		if err != nil {
			return fmt.Errorf("create zip entry %s: %w", relativePath, err)
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open native symbol file %s: %w", path, err)
		}
		defer file.Close()

		if _, err := io.Copy(writer, file); err != nil {
			return fmt.Errorf("copy native symbol file %s: %w", path, err)
		}
		return nil
	}); err != nil {
		archive.Close()
		return "", false, err
	}

	if err := archive.Close(); err != nil {
		return "", false, fmt.Errorf("close native symbols zip: %w", err)
	}
	if err := zipFile.Close(); err != nil {
		return "", false, fmt.Errorf("finalize native symbols zip: %w", err)
	}

	return layout.nativeSymbolsPath, fallbackUsed, nil
}

func dirHasFiles(root string) (bool, error) {
	info, err := os.Stat(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", root, err)
	}
	if !info.IsDir() {
		return true, nil
	}

	found := false
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() {
			found = true
			return io.EOF
		}
		return nil
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("scan %s: %w", root, err)
	}
	return found, nil
}

func resolvePublisherCredentials(publisherJSONPath string) (string, error) {
	if value := strings.TrimSpace(os.Getenv("ANDROID_PUBLISHER_CREDENTIALS")); value != "" {
		return value, nil
	}
	if path := strings.TrimSpace(publisherJSONPath); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read publisher json %s: %w", path, err)
		}
		if value := strings.TrimSpace(string(raw)); value != "" {
			return value, nil
		}
		return "", fmt.Errorf("publisher json %s is empty", path)
	}
	return "", errors.New("missing Google Play credentials; export ANDROID_PUBLISHER_CREDENTIALS or pass --publisher-json /path/to/service-account.json")
}
