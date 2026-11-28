package cli

import (
	"context"
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/model"
	"multi-tun/desktop/internal/vless/subscription"
)

// Tests replace these hooks before running a command; no host credential or
// terminal operation is needed to exercise the CLI.
var (
	amneziaStoreFunc                   = amnezia.DefaultKeychainStore
	amneziaStdin             io.Reader = os.Stdin
	amneziaIsTTY                       = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	amneziaReadPassword                = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
	amneziaFetchFunc                   = subscription.FetchWithOptions
	amneziaGatewayClientFunc           = amnezia.NewGatewayClient
)

func (a *App) runAuth(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "Usage: tun-wave auth <server|amnezia|migrate> [--stdin | --clipboard | --check | --delete]")
		return 2
	}
	if args[0] == "migrate" {
		return a.runAuthMigrate(args[1:])
	}
	targetServer := strings.TrimSpace(args[0])
	if strings.HasPrefix(targetServer, "-") {
		fmt.Fprintln(a.stderr, "Usage: tun-wave auth <server|amnezia|migrate> [--stdin | --clipboard | --check | --delete]")
		return 2
	}
	fs := flag.NewFlagSet("auth "+targetServer, flag.ContinueOnError)
	// flag errors can quote input (including accidental keys). Never print them.
	fs.SetOutput(io.Discard)
	stdin := fs.Bool("stdin", false, "Read key from stdin")
	clipboard := fs.Bool("clipboard", false, "Read key from clipboard")
	check := fs.Bool("check", false, "Print redacted Keychain status")
	deleteKey := fs.Bool("delete", false, "Delete the primary Keychain item")
	defaultAccount := targetServer + "/key"
	if targetServer == "amnezia" {
		defaultAccount = amnezia.DefaultKeychainAccount
	}
	service := fs.String("service", amnezia.DefaultKeychainService, "Keychain service")
	fallback := fs.String("fallback-service", amnezia.FallbackKeychainService, "Fallback service for lookup")
	account := fs.String("account", defaultAccount, "Keychain account")
	allowPlaceholder := fs.Bool("allow-placeholder", false, "Allow the scaffolding placeholder")
	warning := "Raw keys MUST NOT be passed in CLI arguments; use the interactive prompt, --stdin, or --clipboard."
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if fs.NArg() != 0 {
				fmt.Fprintln(a.stderr, warning)
				return 2
			}
			fmt.Fprintf(a.stdout, "Usage: tun-wave auth %s [--stdin | --clipboard | --check | --delete] [--service name] [--fallback-service name] [--account name] [--allow-placeholder]\n", targetServer)
			return 0
		}
		fmt.Fprintln(a.stderr, "Invalid auth flags. "+warning)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(a.stderr, warning)
		return 2
	}
	if (*stdin && *clipboard) || (*check && *deleteKey) || ((*check || *deleteKey) && (*stdin || *clipboard)) {
		fmt.Fprintln(a.stderr, "Choose one of --stdin, --clipboard, --check, or --delete.")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store := amneziaStoreFunc()
	spec := (amnezia.KeychainSpec{Service: *service, FallbackService: *fallback, Account: *account}).Normalize()
	if *check {
		status := store.CheckKey(ctx, spec)
		fmt.Fprintf(a.stdout, "state: %s\nservice: %s\naccount: %s\nused_fallback: %t\nbytes: %d\nrefusal_code: %s\n",
			status.State, status.Service, status.Account, status.UsedFallback, status.ByteLength, status.RefusalCode)
		if status.State == "present" {
			return 0
		}
		return 1
	}
	if *deleteKey {
		deleted, err := store.DeleteKey(ctx, spec.Service, spec.Account)
		if err != nil {
			fmt.Fprintf(a.stderr, "auth amnezia failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(a.stdout, "deleted: %t\nservice: %s\naccount: %s\n", deleted, spec.Service, spec.Account)
		return 0
	}
	secret, err := store.ReadSecretInput(ctx, amnezia.ReadSecretOptions{
		FromStdin: *stdin, FromClipboard: *clipboard, Stdin: amneziaStdin,
		IsTTY: amneziaIsTTY, ReadPassword: amneziaReadPassword, PromptWriter: a.stderr,
	})
	if err == nil {
		err = store.StoreKey(ctx, amnezia.StoreOptions{Service: spec.Service, Account: spec.Account, Secret: secret, AllowPlaceholder: *allowPlaceholder})
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "auth amnezia failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "stored: true\nservice: %s\naccount: %s\n", spec.Service, spec.Account)
	if decoded, err := amnezia.DecodeKey(secret); err == nil {
		fmt.Fprintf(a.stdout, "detected_format: %s\ndetected_protocol: %s\ndetected_profiles: %d\ndetected_countries: %s\n",
			decoded.Format, decoded.Protocol, len(decoded.Profiles), strings.Join(decoded.Summary.Countries, ","))
	}
	return 0
}

func amneziaKeychainSpec(cfg config.ProjectConfig) amnezia.KeychainSpec {
	spec := cfg.SourceKeychain()
	return amnezia.KeychainSpec{Service: spec.Service, FallbackService: spec.FallbackService, Account: spec.Account}
}

func resolveConfiguredSourceSecret(ctx context.Context, cfg config.ProjectConfig) (string, string, error) {
	auth := cfg.SourceAuth()
	if auth == nil {
		return "", "", errors.New("source.url or source.auth is required")
	}
	switch auth.Mode {
	case "keychain":
		spec := (amnezia.KeychainSpec{
			Service:         auth.Service,
			FallbackService: auth.FallbackService,
			Account:         auth.Record,
		}).Normalize()
		res, err := amneziaStoreFunc().LookupKey(ctx, spec)
		if err != nil {
			return "", "", err
		}
		return strings.TrimSpace(res.Secret), fmt.Sprintf("keychain://%s/%s", res.Service, res.Account), nil
	case "file":
		path := expandAuthFilePath(auth.Path)
		info, err := os.Lstat(path)
		if err != nil {
			return "", "", fmt.Errorf("read source.auth.path: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return "", "", errors.New("source.auth.path must be a regular 0600 file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read source.auth.path: %w", err)
		}
		secret := strings.TrimSpace(string(raw))
		if secret == "" {
			return "", "", errors.New("source.auth.path secret is empty")
		}
		return secret, "file://" + auth.Path, nil
	default:
		return "", "", fmt.Errorf("unsupported source.auth.mode %q", auth.Mode)
	}
}

func expandAuthFilePath(path string) string {
	path = strings.TrimSpace(path)
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home + path[1:]
		}
	}
	return path
}

func (a *App) runAuthMigrate(args []string) int {
	fs := flag.NewFlagSet("auth migrate", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	configPath := fs.String("config", "", "Path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	resolvedPath, err := config.ResolveLoadPath(*configPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "auth migrate failed: %v\n", err)
		return 1
	}
	cfg, err := config.Load(resolvedPath)
	if err != nil {
		fmt.Fprintf(a.stderr, "auth migrate failed: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store := amneziaStoreFunc()
	migrated := 0
	for name, srv := range cfg.Servers {
		record := name + "/key"
		if srv.Source.Keychain != nil && strings.TrimSpace(srv.Source.Keychain.Account) != "" {
			record = strings.TrimSpace(srv.Source.Keychain.Account)
		} else if srv.Source.Auth != nil && strings.TrimSpace(srv.Source.Auth.Record) != "" {
			record = strings.TrimSpace(srv.Source.Auth.Record)
		}
		if secret := strings.TrimSpace(srv.Source.URL); secret != "" {
			if err := store.StoreKey(ctx, amnezia.StoreOptions{
				Service: amnezia.DefaultKeychainService,
				Account: record,
				Secret:  secret,
			}); err != nil {
				fmt.Fprintf(a.stderr, "auth migrate failed for %s: %v\n", name, err)
				return 1
			}
			srv.Source.URL = ""
			srv.Source.Keychain = nil
			srv.Source.Auth = &config.SourceAuthConfig{
				Mode:   "keychain",
				Record: record,
			}
			cfg.Servers[name] = srv
			migrated++
			fmt.Fprintf(a.stdout, "migrated: %s -> keychain (%s)\n", name, record)
		} else if srv.Source.Keychain != nil {
			srv.Source.Keychain = nil
			srv.Source.Auth = &config.SourceAuthConfig{
				Mode:   "keychain",
				Record: record,
			}
			cfg.Servers[name] = srv
			migrated++
			fmt.Fprintf(a.stdout, "normalized: %s -> auth.mode=keychain (%s)\n", name, record)
		}
		if eff, _, eerr := cfg.Effective(config.SelectionOptions{Server: name, AllowMissingProfile: true}); eerr == nil && eff.CacheDir != "" {
			if snap, lerr := subscription.LoadCache(eff.CacheDir); lerr == nil {
				ref := "keychain://tun-wave/" + record
				if snap.SourceURL != ref || snap.Raw != "" {
					snap.SourceURL = ref
					snap.Raw = ""
					_ = subscription.SaveCache(eff.CacheDir, snap)
				}
			}
		}
	}
	if _, err := config.SaveConfig(resolvedPath, cfg); err != nil {
		fmt.Fprintf(a.stderr, "auth migrate save failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(a.stdout, "saved: %s (migrated=%d)\n", resolvedPath, migrated)
	return 0
}

func refreshAmneziaSource(cfg config.ProjectConfig) (subscription.CacheSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := amneziaStoreFunc().LookupKey(ctx, amneziaKeychainSpec(cfg))
	if err != nil {
		return subscription.CacheSnapshot{}, err
	}
	decoded, err := amnezia.DecodeKey(result.Secret)
	if err != nil {
		return subscription.CacheSnapshot{}, err
	}
	if err := decoded.ValidateRunnable(cfg.EngineType()); err != nil {
		return subscription.CacheSnapshot{}, err
	}
	profiles := decoded.Profiles
	switch {
	case decoded.Protocol == "amnezia-gateway" && decoded.Gateway != nil:
		installUUID, err := amnezia.LoadOrCreateInstallationUUID(cfg.CacheDir)
		if err != nil {
			return subscription.CacheSnapshot{}, err
		}
		info, err := amneziaGatewayClientFunc().FetchAccountInfo(ctx, *decoded.Gateway, installUUID)
		if err != nil {
			// Gateway refusals stay hard failures, including transport failures.
			return subscription.CacheSnapshot{}, err
		}
		profiles = info.CatalogProfiles(decoded.Gateway.ServiceProtocol)
	case decoded.Protocol == "amnezia-awg" && decoded.AWG != nil:
		c := decoded.AWG
		endpoint := net.JoinHostPort(c.EndpointHost, strconv.Itoa(c.EndpointPort))
		name := c.Name
		if name == "" {
			name = endpoint
		}
		id := sha1.Sum([]byte("amnezia-awg|" + endpoint + "|" + name))
		profiles = []model.Profile{{ID: fmt.Sprintf("%x", id)[:12], Name: name, CountryCode: c.CountryCode,
			Protocol: "amnezia-awg", Network: "udp", Host: c.EndpointHost, Port: c.EndpointPort}}
	case decoded.Format == "subscription_url":
		body, err := amneziaFetchFunc(ctx, decoded.SubscriptionURL, subscription.FetchOptions{UserAgent: cfg.SourceUserAgent(), Headers: cfg.SourceHeaders()})
		if err != nil {
			// Neither transport errors nor parser errors may quote the secret URL.
			redacted := amnezia.WrapRefusal(amnezia.CodeKeyInvalid, "Amnezia subscription fetch failed", err)
			if subscription.IsTransientFetchError(err) {
				return subscription.CacheSnapshot{}, &subscription.TransientFetchError{Err: redacted}
			}
			return subscription.CacheSnapshot{}, redacted
		}
		normalized, _, err := subscription.NormalizePayload(body)
		if err == nil {
			profiles, err = subscription.ParseProfiles(normalized)
		}
		if err != nil {
			return subscription.CacheSnapshot{}, amnezia.WrapRefusal(amnezia.CodeKeyInvalid, "Invalid Amnezia subscription payload", err)
		}
		for i := range profiles {
			profiles[i].CountryCode = subscription.ProfileCountryCode(profiles[i])
		}
	}
	if len(profiles) == 0 {
		return subscription.CacheSnapshot{}, amnezia.NewRefusal(amnezia.CodeKeyInvalid, "Amnezia key contains no runnable profiles")
	}
	snapshot := subscription.CacheSnapshot{
		SourceURL:  fmt.Sprintf("keychain://%s/%s", result.Service, result.Account),
		SourceMode: config.SourceModeAmnezia, FetchedAt: time.Now().UTC(),
		PayloadFormat: decoded.Format, Raw: "", Profiles: profiles,
	}
	if err := subscription.SaveCache(cfg.CacheDir, snapshot); err != nil {
		return subscription.CacheSnapshot{}, err
	}
	return snapshot, nil
}

// Resolve key material only at runtime; catalog snapshots never contain it.
func resolveAmneziaRuntime(ctx context.Context, cfg config.ProjectConfig, profile model.Profile) (model.Profile, *amnezia.AWGConfig, error) {
	result, err := amneziaStoreFunc().LookupKey(ctx, amneziaKeychainSpec(cfg))
	if err != nil {
		return model.Profile{}, nil, err
	}
	decoded, err := amnezia.DecodeKey(result.Secret)
	if err != nil {
		return model.Profile{}, nil, err
	}
	if err := decoded.ValidateRunnable(cfg.EngineType()); err != nil {
		return model.Profile{}, nil, err
	}
	if amnezia.IsGatewayCatalogProfile(profile) {
		if decoded.Gateway == nil {
			return model.Profile{}, nil, amnezia.NewRefusal(amnezia.CodeKeyInvalid, "gateway catalog requires gateway credentials")
		}
		installUUID, err := amnezia.LoadOrCreateInstallationUUID(cfg.CacheDir)
		if err != nil {
			return model.Profile{}, nil, err
		}
		negotiated, err := amneziaGatewayClientFunc().NegotiateConfig(ctx, *decoded.Gateway, installUUID, amnezia.GatewayServerCountryCode(profile), amnezia.GatewayServiceProtocol(profile))
		if err != nil {
			return model.Profile{}, nil, err
		}
		if negotiated.ServiceProtocol == "awg" && negotiated.AWG != nil {
			c := negotiated.AWG
			if profile.Name == "" {
				profile.Name = c.Name
			}
			profile.CountryCode, profile.Host, profile.Port = c.CountryCode, c.EndpointHost, c.EndpointPort
			profile.Protocol, profile.Network = "amnezia-awg", "udp"
			return profile, c, nil
		}
		if negotiated.ServiceProtocol == "vless" && len(negotiated.Profiles) > 0 {
			return negotiated.Profiles[0], nil, nil
		}
		return model.Profile{}, nil, amnezia.NewRefusal(amnezia.CodeKeyInvalid, "gateway returned no runnable configuration")
	}
	if decoded.Protocol == "amnezia-awg" && decoded.AWG != nil {
		return profile, decoded.AWG, nil
	}
	return profile, nil, nil
}

func amneziaShouldSkipTCPProbe(profiles []model.Profile, match *config.ProfileMatch) bool {
	if match == nil {
		return false
	}
	// Reuse the selector's filters so excluded AWG profiles do not suppress
	// probes for matching VLESS profiles. Pick=first never probes endpoints.
	matched := false
	for _, p := range profiles {
		_, err := subscription.ResolveProfileWithOptions([]model.Profile{p}, subscription.SelectOptions{
			Match: subscriptionMatch(match), Pick: "first",
		})
		if err != nil {
			continue
		}
		matched = true
		if p.Protocol != "amnezia-awg" && !amnezia.IsGatewayCatalogProfile(p) {
			return false
		}
	}
	return matched
}
