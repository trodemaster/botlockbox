package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"filippo.io/age"
	"github.com/awnumar/memguard"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/proxy"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "botlockbox.yaml", "path to botlockbox.yaml")
	identityPath := fs.String("identity", "", "path to age identity file (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: botlockbox serve [flags]")
		fmt.Fprintln(os.Stderr, "Decrypts secrets and starts the MITM proxy.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if *identityPath == "" {
		fmt.Fprintln(os.Stderr, "error: --identity is required")
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

	// Parse age identity.
	identityFile, err := os.Open(*identityPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening identity file: %v\n", err)
		os.Exit(1)
	}
	defer identityFile.Close()

	identities, err := age.ParseIdentities(identityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing age identities: %v\n", err)
		os.Exit(1)
	}

	// Open and decrypt secrets file.
	secretsFile, err := os.Open(cfg.SecretsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening secrets file %q: %v\n", cfg.SecretsFile, err)
		os.Exit(1)
	}
	defer secretsFile.Close()

	ageReader, err := age.Decrypt(secretsFile, identities...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error decrypting secrets file: %v\n", err)
		os.Exit(1)
	}

	var envelope secrets.SealedEnvelope
	if err := json.NewDecoder(ageReader).Decode(&envelope); err != nil {
		fmt.Fprintf(os.Stderr, "error decoding sealed envelope: %v\n", err)
		os.Exit(1)
	}

	// Validate envelope against live config — hard exit on mismatch.
	if err := envelope.Validate(allowedHosts); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY VIOLATION: %v\n", err)
		os.Exit(1)
	}

	// Lock each secret into guarded memory.
	lockedSecrets := make(map[string]*memguard.Enclave, len(envelope.Secrets))
	for name, plaintext := range envelope.Secrets {
		b := []byte(plaintext)
		lockedSecrets[name] = memguard.NewEnclave(b)
		memguard.ScrambleBytes(b)
	}

	applyHardening()

	handler, err := proxy.New(cfg, &secrets.UnsealResult{
		Envelope:      &envelope,
		LockedSecrets: lockedSecrets,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing proxy: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Host binding verified")
	fmt.Printf("botlockbox listening on %s\n", cfg.Listen)

	if err := http.ListenAndServe(cfg.Listen, handler); err != nil {
		fmt.Fprintf(os.Stderr, "proxy error: %v\n", err)
		os.Exit(1)
	}
}
