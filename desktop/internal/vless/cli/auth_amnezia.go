package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"multi-tun/desktop/internal/vless/amnezia"
	"multi-tun/desktop/internal/vless/config"
	"multi-tun/desktop/internal/vless/subscription"
)

// Tests replace these hooks before running a command; no host credential or
// terminal operation is needed to exercise the CLI.
var (
	amneziaStoreFunc              = amnezia.DefaultKeychainStore
	amneziaStdin        io.Reader = os.Stdin
	amneziaIsTTY                  = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	amneziaReadPassword           = func() ([]byte, error) { return term.ReadPassword(int(os.Stdin.Fd())) }
	amneziaFetchFunc              = subscription.FetchWithOptions
)

func (a *App) runAuth(args []string) int {
	if len(args) == 0 || args[0] != "amnezia" {
		fmt.Fprintln(a.stderr, "Usage: tun-wave auth amnezia [--stdin | --clipboard | --check | --delete]")
		return 2
	}
	fs := flag.NewFlagSet("auth amnezia", flag.ContinueOnError)
	// flag errors can quote input (including accidental keys). Never print them.
	fs.SetOutput(io.Discard)
	stdin := fs.Bool("stdin", false, "Read key from stdin")
	clipboard := fs.Bool("clipboard", false, "Read key from clipboard")
	check := fs.Bool("check", false, "Print redacted Keychain status")
	deleteKey := fs.Bool("delete", false, "Delete the primary Keychain item")
	service := fs.String("service", amnezia.DefaultKeychainService, "Keychain service")
	fallback := fs.String("fallback-service", amnezia.FallbackKeychainService, "Fallback service for lookup")
	account := fs.String("account", amnezia.DefaultKeychainAccount, "Keychain account")
	allowPlaceholder := fs.Bool("allow-placeholder", false, "Allow the scaffolding placeholder")
	warning := "Raw keys MUST NOT be passed in CLI arguments; use the interactive prompt, --stdin, or --clipboard."
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if fs.NArg() != 0 {
				fmt.Fprintln(a.stderr, warning)
				return 2
			}
			fmt.Fprintln(a.stdout, "Usage: tun-wave auth amnezia [--stdin | --clipboard | --check | --delete] [--service name] [--fallback-service name] [--account name] [--allow-placeholder]")
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
	if decoded.Format == "subscription_url" {
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
