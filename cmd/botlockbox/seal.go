package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/secrets"
	"gopkg.in/yaml.v3"
)

func runSeal(args []string) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	configPath := fs.String("config", "botlockbox.yaml", "path to botlockbox.yaml")
	identityPath := fs.String("identity", "", "path to age identity file (required)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: botlockbox seal [flags]")
		fmt.Fprintln(os.Stderr, "Reads secrets from stdin as YAML (key: value pairs) and seals them.")
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

	// Read secrets from stdin as YAML.
	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		os.Exit(1)
	}
	var inputSecrets map[string]string
	if err := yaml.Unmarshal(stdinData, &inputSecrets); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing secrets from stdin: %v\n", err)
		os.Exit(1)
	}

	// Verify every secret referenced in rules is present in stdin input.
	for secretName := range allowedHosts {
		if _, ok := inputSecrets[secretName]; !ok {
			fmt.Fprintf(os.Stderr, "error: secret %q is referenced in config rules but was not provided on stdin\n", secretName)
			os.Exit(1)
		}
	}

	envelope := secrets.SealedEnvelope{
		Version:      1,
		SealedAt:     time.Now().UTC(),
		AllowedHosts: allowedHosts,
		Secrets:      inputSecrets,
	}

	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling envelope: %v\n", err)
		os.Exit(1)
	}

	// Parse age identity to get the recipient.
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
	if len(identities) == 0 {
		fmt.Fprintln(os.Stderr, "error: no identities found in identity file")
		os.Exit(1)
	}

	xi, ok := identities[0].(*age.X25519Identity)
	if !ok {
		fmt.Fprintln(os.Stderr, "error: identity is not an X25519 key")
		os.Exit(1)
	}
	recipient := xi.Recipient()

	// Ensure parent directory exists.
	if err := os.MkdirAll(filepath.Dir(cfg.SecretsFile), 0700); err != nil {
		fmt.Fprintf(os.Stderr, "error creating secrets directory: %v\n", err)
		os.Exit(1)
	}

	// Write age-encrypted JSON to secrets file.
	outFile, err := os.OpenFile(cfg.SecretsFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating secrets file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	ageWriter, err := age.Encrypt(outFile, recipient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing age encryption: %v\n", err)
		os.Exit(1)
	}
	if _, err := ageWriter.Write(envelopeJSON); err != nil {
		fmt.Fprintf(os.Stderr, "error writing encrypted envelope: %v\n", err)
		os.Exit(1)
	}
	if err := ageWriter.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "error finalizing age encryption: %v\n", err)
		os.Exit(1)
	}

	// Make config read-only.
	if err := os.Chmod(*configPath, 0444); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not set config read-only: %v\n", err)
	}

	fmt.Printf("Secrets sealed to %s\n", cfg.SecretsFile)
	fmt.Printf("Config set to read-only (0444): %s\n", *configPath)
}
