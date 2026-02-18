package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"filippo.io/age"
	"github.com/awnumar/memguard"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/proxy"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

// mustParseIdentities opens and parses an age identity file, exiting on error.
func mustParseIdentities(path string) []age.Identity {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening identity file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	identities, err := age.ParseIdentities(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing age identities: %v\n", err)
		os.Exit(1)
	}
	return identities
}

// mustParseIdentitiesFromReader parses age identities from r, then scrambles
// the source bytes so the key material does not linger in our buffer.
func mustParseIdentitiesFromReader(r io.Reader) []age.Identity {
	data, err := io.ReadAll(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading identity from stdin: %v\n", err)
		os.Exit(1)
	}
	defer memguard.ScrambleBytes(data)
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing age identities from stdin: %v\n", err)
		os.Exit(1)
	}
	return identities
}

// unseal decrypts secrets.age and returns a validated UnsealResult.
func unseal(cfg *config.Config, identities []age.Identity, allowedHosts map[string][]string) (*secrets.UnsealResult, error) {
	secretsFile, err := os.Open(cfg.SecretsFile)
	if err != nil {
		return nil, fmt.Errorf("opening secrets file %q: %w", cfg.SecretsFile, err)
	}
	defer secretsFile.Close()

	ageReader, err := age.Decrypt(secretsFile, identities...)
	if err != nil {
		return nil, fmt.Errorf("decrypting secrets file: %w", err)
	}

	var envelope secrets.SealedEnvelope
	if err := json.NewDecoder(ageReader).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decoding sealed envelope: %w", err)
	}

	if err := envelope.Validate(allowedHosts); err != nil {
		return nil, fmt.Errorf("SECURITY VIOLATION: %w", err)
	}

	lockedSecrets := make(map[string]*memguard.Enclave, len(envelope.Secrets))
	for name, plaintext := range envelope.Secrets {
		b := []byte(plaintext)
		lockedSecrets[name] = memguard.NewEnclave(b)
		memguard.ScrambleBytes(b)
	}

	return &secrets.UnsealResult{
		Envelope:      &envelope,
		LockedSecrets: lockedSecrets,
	}, nil
}

// mustUnseal calls unseal and exits on failure (startup only).
func mustUnseal(cfg *config.Config, identities []age.Identity, allowedHosts map[string][]string) *secrets.UnsealResult {
	result, err := unseal(cfg, identities, allowedHosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	return result
}

// writePIDFile writes the current process PID to path.
func writePIDFile(path string) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}

// watchSIGHUP listens for SIGHUP signals and hot-reloads secrets via the injector.
func watchSIGHUP(injector *proxy.Injector, cfg *config.Config, identities []age.Identity, allowedHosts map[string][]string) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		fmt.Println("botlockbox: SIGHUP received, reloading secrets...")
		result, err := unseal(cfg, identities, allowedHosts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "botlockbox: reload FAILED (keeping current secrets): %v\n", err)
			continue
		}
		if err := injector.SwapSecrets(result, allowedHosts); err != nil {
			fmt.Fprintf(os.Stderr, "botlockbox: reload REJECTED (keeping current secrets): %v\n", err)
			for _, enc := range result.LockedSecrets {
				if buf, openErr := enc.Open(); openErr == nil {
					buf.Destroy()
				}
			}
			continue
		}
		fmt.Println("botlockbox: secrets reloaded successfully")
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "botlockbox.yaml", "path to botlockbox.yaml")
	identityPath := fs.String("identity", "", "path to age identity file (mutually exclusive with --identity-stdin)")
	identityStdin := fs.Bool("identity-stdin", false, "read age identity from stdin; key is never written to disk (mutually exclusive with --identity)")
	pidfilePath := fs.String("pidfile", "", "path to write PID file (optional; used with 'botlockbox reload')")
	caCertPath := fs.String("ca-cert", "", "path to write the ephemeral MITM CA public certificate PEM (optional; trust this cert in clients)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: botlockbox serve [flags]")
		fmt.Fprintln(os.Stderr, "Decrypts secrets and starts the MITM proxy.")
		fmt.Fprintln(os.Stderr, "Exactly one of --identity or --identity-stdin is required.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *identityPath != "" && *identityStdin {
		fmt.Fprintln(os.Stderr, "error: --identity and --identity-stdin are mutually exclusive")
		fs.Usage()
		os.Exit(1)
	}
	if *identityPath == "" && !*identityStdin {
		fmt.Fprintln(os.Stderr, "error: one of --identity or --identity-stdin is required")
		fs.Usage()
		os.Exit(1)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	allowedHosts, err := cfg.AllowedHostsFromRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing rules: %v\n", err)
		os.Exit(1)
	}

	var identities []age.Identity
	if *identityStdin {
		identities = mustParseIdentitiesFromReader(os.Stdin)
	} else {
		identities = mustParseIdentities(*identityPath)
	}
	result := mustUnseal(cfg, identities, allowedHosts)

	applyHardening()

	handler, injector, err := proxy.New(cfg, result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing proxy: %v\n", err)
		os.Exit(1)
	}

	if *caCertPath != "" {
		if err := os.WriteFile(*caCertPath, injector.CACertPEM, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing CA cert: %v\n", err)
			os.Exit(1)
		}
	}

	if *pidfilePath != "" {
		if err := writePIDFile(*pidfilePath); err != nil {
			fmt.Fprintf(os.Stderr, "error writing PID file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(*pidfilePath)
	}

	go watchSIGHUP(injector, cfg, identities, allowedHosts)

	fmt.Println("Host binding verified")
	fmt.Printf("botlockbox listening on %s\n", cfg.Listen)

	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}
