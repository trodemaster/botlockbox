# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

The README documents these make targets (note: `Makefile` and `go.mod` do not yet exist in the repo and will need to be created):

```bash
make build    # compile to bin/botlockbox
make install  # go install
make test     # go test ./...
make lint     # go vet ./...
make tidy     # go mod tidy
```

The Go module path is `github.com/trodemaster/botlockbox`.

## Architecture

`botlockbox` is a credential-injecting HTTPS/HTTP MITM proxy. It sits between AI agents/tools and external APIs, decrypting `age`-encrypted secrets into memory and injecting them into outbound requests. Callers never see the credentials.

### Package layout

```
internal/config/    -- Config struct, YAML loading, AllowedHostsFromRules()
internal/secrets/   -- SealedEnvelope type and Validate()
internal/matcher/   -- Matches() and HostMatches() for host glob + path prefix checks
internal/proxy/     -- goproxy HTTP handler, MITM CA, injector, response scrubber, audit log
```

This is a **library** — there is no `main.go` or `cmd/` directory. A separate CLI (with `seal` and `serve` subcommands) consumes these packages.

### Data flow

1. At **seal time**: `config.AllowedHostsFromRules()` extracts `map[secretName][]hostGlob` from the YAML rules. This map, plus the encrypted secrets, are written into a `SealedEnvelope` and age-encrypted to disk (`secrets.age`).
2. At **serve time**: the CLI decrypts `secrets.age`, calls `SealedEnvelope.Validate()` against the live config, and passes `secrets.UnsealResult` (containing `memguard.Enclave` per secret) to `proxy.New()`.
3. **Per request**: `Injector.Handle()` iterates rules, calls `matcher.Matches()`, then `assertHostAllowed()` (re-checks against the sealed envelope at runtime), retrieves the secret from the `memguard.Enclave`, renders the `{{secrets.NAME}}` template, and injects the result as a header or query param. The plaintext secret is scrambled with `memguard.ScrambleBytes()` immediately after use.
4. **Response scrubbing**: `InstallResponseScrubber()` regex-redacts known credential patterns (GitHub tokens, OpenAI keys, AWS keys, JSON token fields) from all responses.

### Security invariants

- The sealed envelope is the **source of truth** for which hosts each secret may reach. Both `Validate()` (startup) and `assertHostAllowed()` (per-injection) enforce this. Any mismatch is a hard `os.Exit(1)` / 503.
- The ephemeral MITM CA is ECDSA P-256, generated in memory, never written to disk (24h lifetime).
- Secrets live only in `memguard.Enclave` (encrypted memory); they are opened briefly per injection and immediately scrambled.
- The config file (`botlockbox.yaml`) contains **no secrets** — only routing rules and file paths. Secrets are exclusively in the age-encrypted blob.
- Upstream TLS is always verified (TLS 1.2+); `InsecureSkipVerify` is never set.
- Audit log emits structured JSON (`AUDIT {...}`) with secret **names** only, never values.
