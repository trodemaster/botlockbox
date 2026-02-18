# botlockbox

`botlockbox` is a credential-injecting HTTPS/HTTP MITM proxy for AI agents, MCP servers, and CLI tools. It sits between your agents and external APIs, decrypting `age`-encrypted secrets in memory and injecting them transparently into outbound requests. Callers -- including agents with root shell access -- **never see the credentials**.

## Architecture

```
+-----------------------------------------------------+
|  AI Agent / MCP Server / CLI Tool                   |
|  (zero credentials, uses http_proxy=localhost:8080) |
+----------------------+------------------------------+
                       |
                       | plain request (no creds)
                       v
+-----------------------------------------------------+
|  botlockbox proxy (localhost:8080)                  |
|  - decrypts secrets in memory (age + memguard)      |
|  - validates sealed host allowlist                  |
|  - injects Authorization / API headers              |
|  - verifies upstream TLS (anti-DNS-rebinding)       |
|  - scrubs credentials from responses                |
|  - writes structured audit log (JSONL)              |
+----------------------+------------------------------+
                       |
                       | request + injected credentials
                       v
             External API (GitHub, OpenAI, AWS...)
```

## Security model

| # | Attack vector | Mitigation | Layer |
|---|--------------|-----------|-------|
| 1 | Read `/proc/<pid>/mem` | `PR_SET_DUMPABLE=0` | OS |
| 2 | `ptrace` attach | `PR_SET_DUMPABLE=0` + separate UID | OS |
| 3 | Secrets swapped to disk | `mlockall` + `MADV_DONTDUMP` | OS |
| 4 | Core dump contains secrets | `setrlimit(RLIMIT_CORE,0)` + `MADV_DONTDUMP` | OS |
| 5 | GC copies secrets in heap | `memguard` encrypted enclave | App |
| 6 | MITM CA key readable on disk | Ephemeral in-memory ECDSA CA, never written to disk | App |
| 7 | Config tampered to add a new host | Sealed envelope validation at startup -- hard `os.Exit(1)` | App |
| 8 | Config tampered to bypass at runtime | Per-injection sealed allowlist check in injector | App |
| 9 | DNS rebinding past host check | Upstream TLS certificate verification | App |
| 10 | Response body leaks tokens | Response scrubber redacts known credential patterns | App |
| 11 | Prompt injection edits config + restart | Config set `0444` post-seal + envelope validation on next start | App+OS |
| 12 | Silent credential exfiltration | Structured JSONL audit log (secret names only, never values) | App |
| 13 | Swap / hibernate writes memory to disk | `mlockall` | OS |
| 14 | Brute-force the encrypted blob | `age` X25519 / scrypt -- computationally infeasible | Crypto |
| 15 | Binary replacement (swap botlockbox) | OS file integrity monitoring (separate ops concern) | Ops |

## Installation

```bash
go install github.com/trodemaster/botlockbox@latest
```

Or build from source:

```bash
git clone https://github.com/trodemaster/botlockbox
cd botlockbox
make build
# binary at bin/botlockbox
```

## Quick start

### 1. Generate an age key pair (one time)

```bash
age-keygen -o ~/.age/identity.txt
# Public key printed to stdout: age1xxxxxxxxxx
```

### 2. Write your config (no secrets here)

```bash
cp botlockbox.yaml ~/.config/botlockbox.yaml
# edit rules as needed
```

### 3. Seal your secrets

```bash
cat <<EOF | botlockbox seal \
  --config ~/.config/botlockbox.yaml \
  --identity ~/.age/identity.txt
github_token: "ghp_xxxxxxxxxxxxxxxxxxxx"
openai_key: "sk-xxxxxxxxxxxxxxxxxxxx"
EOF
# Secrets sealed to ~/.botlockbox/secrets.age
# Config set to read-only (0444)
```

### 4. Start the proxy

```bash
botlockbox serve \
  --config ~/.config/botlockbox.yaml \
  --identity ~/.age/identity.txt
# Host binding verified
# botlockbox listening on 127.0.0.1:8080
```

### 5. Use it -- callers need zero credentials

```bash
http_proxy=http://127.0.0.1:8080 \
https_proxy=http://127.0.0.1:8080 \
  curl https://api.github.com/user
# Authorization: Bearer ghp_xxx injected transparently
```

## Config reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `listen` | string | `127.0.0.1:8080` | Proxy listen address |
| `secrets_file` | string | `~/.botlockbox/secrets.age` | Path to age-encrypted secrets |
| `verbose` | bool | `false` | Log every proxied request |
| `identity_file` | string | -- | Default age identity file path |
| `rules` | list | -- | Credential injection rules |
| `rules[].name` | string | -- | Human-readable rule name (appears in audit log) |
| `rules[].match.hosts` | list | -- | Host glob patterns (`*.example.com` supported) |
| `rules[].match.path_prefixes` | list | -- | Optional URL path prefix filters |
| `rules[].inject.headers` | map | -- | Request headers to inject; supports `{{secrets.NAME}}` |
| `rules[].inject.query_params` | map | -- | Query parameters to inject; supports `{{secrets.NAME}}` |

## Secrets file format

Provided via stdin to `botlockbox seal` only -- **never written to disk in plaintext**:

```yaml
github_token: "ghp_xxxxxxxxxxxxxxxxxxxx"
openai_key: "sk-xxxxxxxxxxxxxxxxxxxx"
aws_session_token: "IQoJb3..."
```

The only artifact written to disk is `~/.botlockbox/secrets.age` -- an opaque `age`-encrypted blob.

## Deployment posture

```
+---------------------------------------------+
|  Container / VM                             |
|                                             |
|  uid 1001: botlockbox serve                 |
|    - secrets.age   (0600, owned by 1001)    |
|    - identity.txt  (0600, owned by 1001)    |
|    - botlockbox.yaml (0444, read-only)      |
|    - PR_SET_DUMPABLE=0                      |
|    - mlockall                               |
|    - RLIMIT_CORE=0                          |
|                                             |
|  uid 1002: AI agent / MCP server            |
|    - http_proxy=http://127.0.0.1:8080       |
|    - NO access to uid 1001 files            |
|    - NO ptrace capability on uid 1001       |
|                                             |
|  Egress firewall: only allowlisted hosts    |
+---------------------------------------------+
```

## Building

```bash
make build    # compile to bin/botlockbox
make install  # go install
make test     # go test ./...
make lint     # go vet ./...
make tidy     # go mod tidy
```

## License

MIT
