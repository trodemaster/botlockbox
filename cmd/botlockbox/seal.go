package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/secrets"
	"gopkg.in/yaml.v3"
)

func runSeal(args []string) {
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	configPath := fs.String("config", "botlockbox.yaml", "path to botlockbox.yaml")
	identityPath := fs.String("identity", "", "path to age X25519 identity file (derives recipient from key)")
	recipientStr := fs.String("recipient", "", "age recipient public key string (use for plugin keys such as age-plugin-se, e.g. age1se1q...)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: botlockbox seal [flags]")
		fmt.Fprintln(os.Stderr, "Reads secrets from stdin as YAML (key: value pairs) and seals them.")
		fmt.Fprintln(os.Stderr, "Exactly one of --identity or --recipient is required.")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if (*identityPath == "") == (*recipientStr == "") {
		fmt.Fprintln(os.Stderr, "error: exactly one of --identity or --recipient is required")
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

	recipient, err := resolveRecipient(*identityPath, *recipientStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error resolving recipient: %v\n", err)
		os.Exit(1)
	}

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

// resolveRecipient returns an age.Recipient from either a public key string
// (for plugin keys such as age-plugin-se) or an X25519 identity file.
func resolveRecipient(identityPath, recipientStr string) (age.Recipient, error) {
	if recipientStr != "" {
		recipients, err := age.ParseRecipients(strings.NewReader(recipientStr))
		if err != nil {
			return nil, fmt.Errorf("parsing recipient %q: %w", recipientStr, err)
		}
		if len(recipients) == 0 {
			return nil, fmt.Errorf("no recipient found in %q", recipientStr)
		}
		return recipients[0], nil
	}

	// X25519 identity path: open the file and derive the recipient.
	f, err := os.Open(identityPath)
	if err != nil {
		return nil, fmt.Errorf("opening identity file: %w", err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parsing identity file: %w", err)
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no identities found in %q", identityPath)
	}
	xi, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("identity in %q is not an X25519 key; use --recipient with the public key string instead", identityPath)
	}
	return xi.Recipient(), nil
}
