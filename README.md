# Privacy Filter (Go)

**English** | [简体中文](README.zh-CN.md)

Strip sensitive user data (PII / secrets) from text before it reaches an LLM.
Pure Go, no model, no GPU, no CGO — a single static binary, millisecond latency on text of any length.

🌐 Running in production at [PackyCode](https://www.packyapi.com) — the privacy-compliance component of an API relay service.

---

## Three ways to use it

1. **Core package**: `import "privacyfilter/filter"` straight into your gateway — redaction is one function call, no HTTP hop.
2. **HTTP service**: `cmd/http`, REST API.
3. **gRPC service**: `cmd/grpc`, interface in `proto/filter.proto`.

The latter two are thin wrappers around the `filter` core package.

---

## Two detection layers

| Layer | Covers | Technique |
|---|---|---|
| Structured PII | Email, phone, national ID, bank card (Luhn-checked), IP | Regex |
| Secrets / credentials | API keys, tokens, private keys, passwords written in prose, unknown high-entropy strings | gitleaks ruleset (keyword pre-filter) + contextual regex + Shannon-entropy fallback |

Each layer emits `(start, end, placeholder)` spans → spans are merged and de-overlapped → the text is rebuilt in a single pass.
Placeholders are typed and carry the entity kind — `[邮箱]` (email), `[电话]` (phone), `[身份证]` (national ID), `[银行卡]` (bank card), `[IP]`, `[密钥]` (secret) — and are irreversible (no un-redaction).

> No person / place / organization name recognition — that needs an NER model, which costs seconds of CPU time on long text and was removed per requirements.
> High-risk identity data (national ID, bank card, secrets, etc.) is fully covered by regex.

---

## Layout

```
privacy-filter/
├── go.mod / go.sum
├── filter/                  core package (import directly from a gateway)
│   ├── filter.go            Filter / New / Redact
│   ├── pii.go               structured PII
│   ├── secrets.go           gitleaks + context + entropy
│   └── filter_test.go
├── cmd/
│   ├── http/main.go         HTTP service
│   └── grpc/main.go         gRPC service
├── proto/filter.proto       gRPC interface definition
├── gen/filterpb/            protoc-generated code
├── rules/gitleaks.toml      gitleaks ruleset
├── scripts/fetch_rules.sh   ruleset update script
└── Dockerfile
```

---

## Build

```bash
go build -o bin/server-http ./cmd/http
go build -o bin/server-grpc ./cmd/grpc
go test ./...                          # run all tests
```

---

## Usage

### 1. Core package (recommended for gateways)

```go
import "privacyfilter/filter"

// Create once at startup; concurrency-safe, reuse globally.
f, err := filter.New("rules/gitleaks.toml")   // pass "" to use the built-in fallback rules

// Per request
res := f.Redact(userPrompt)
forwardToLLM(res.Redacted)                    // forward the redacted text to the LLM
```

`filter.Result`: `Redacted` (redacted text), `Hit`, `Count`, `Entities` (hit details,
including type and byte offsets).

> To consume this package from your own gateway module: put it in the same monorepo, or add
> `replace privacyfilter => ../privacy-filter` to the gateway's go.mod. The `filter` package
> depends only on `BurntSushi/toml`.

### 2. HTTP service

```bash
./bin/server-http                    # default :8088
```

```bash
curl http://127.0.0.1:8088/health
curl -X POST http://127.0.0.1:8088/redact -H 'Content-Type: application/json' \
  -d '{"text":"我的邮箱是 a@b.com，密码是 Hunter2xy"}'
# {"redacted":"我的邮箱是 [邮箱]，密码是 [密钥]","hit":true,"count":2,"entities":[...],"elapsed_ms":0.08}
```

Endpoints: `GET /health`, `POST /redact`, `POST /redact/batch` (`{"texts":[...]}`).

### 3. gRPC service

```bash
./bin/server-grpc                    # default :8089
```

Service `filter.v1.PrivacyFilter`, methods `Redact` / `RedactBatch`, defined in `proto/filter.proto`.
Generate a client from that proto on the gateway side. To regenerate the code in this repo:

```bash
protoc -I. --go_out=. --go_opt=module=privacyfilter \
       --go-grpc_out=. --go-grpc_opt=module=privacyfilter proto/filter.proto
```

---

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `PF_PORT` | `8088` | HTTP listen port |
| `PF_GRPC_PORT` | `8089` | gRPC listen port |
| `PF_GITLEAKS_TOML` | `rules/gitleaks.toml` | path to the gitleaks rules file |

---

## Performance (local benchmark, synthetic high-density PII text — worst case)

| Text length | Latency |
|---|---|
| ~50 B | ~0.01ms |
| ~2 KB | ~0.46ms |
| ~32 KB | ~9ms |

Both layers are O(n). Real prompts (PII is never this dense) are faster.

---

## Integration notes (gateway side)

- With the core-package import there is no HTTP/gRPC hop, hence no timeout and no fail-open/closed concerns.
- If you use the HTTP/gRPC service: set a 150–300ms timeout; on failure, prefer fail-closed (reject the request rather than forwarding the raw text).

---

## Notes

- All **222 gitleaks rules compile natively** in Go (Go's `regexp` is RE2, the same engine gitleaks uses;
  an earlier Python port lost 26 rules to RE2-incompatible syntax).
- Go `regexp` runs in linear time — no catastrophic backtracking (ReDoS) risk.
- gitleaks does not support look-around assertions, so digit boundaries for phone / national ID etc. are
  enforced by manual post-match validation.
- No person / place / organization recognition. If added later, prefer rules (a Chinese-address regex is
  feasible; names are better anchored by context).
- The entropy fallback can mis-flag git SHAs, long base64 strings, etc. — tune the threshold or add an allowlist.
```
