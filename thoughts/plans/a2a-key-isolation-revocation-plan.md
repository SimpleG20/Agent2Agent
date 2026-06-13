# A2A Security: Key Isolation + Real-time Credential Revocation

> Implementation plan for Agent2Agent project
> **Estimated: ~25h** | **5 phases** | **Go + Redis + TypeScript SDK**

## Architecture Overview

```
┌──────────────────────┐      POST /v1/sign       ┌─────────────────────────┐
│   LLM Agent          │ ──────────────────────►   │   Key Guard (Go)        │
│   (Node/Python/Go)   │                          │   - Valida Schema       │
│   SEM chaves crypto  │ ◄──────────────────────  │   - Aplica Políticas    │
│                      │    Signed DIDComm Msg     │   - Verifica Revogação  │
└──────────────────────┘                           │   - Assina Ed25519      │
                                                   └──────────┬──────────────┘
                                                              │
                                                    ┌─────────▼──────────────┐
                                                    │   Redis (Revogação)    │
                                                    │   TTL: 300s           │
                                                    └────────────────────────┘
                                                              ▲
                                                    ┌─────────┴──────────────┐
                                                    │   Sanity Monitor (Go)  │
                                                    │   - Detecta anomalias  │
                                                    │   - Publica revogação  │
                                                    └────────────────────────┘
```

**Princípio Fundamental:** Separação estrita entre **camada cognitiva** (LLM, vulnerável a injeção) e **camada criptográfica** (determinística, validada). O agente NUNCA detém chaves privadas na memória.

---

## Scope Boundaries

| Item | Decision | Rationale |
|------|----------|-----------|
| Actual TEE (Nitro/Confidential VM) | Phase 2 | Requires AWS/GCP. Phase 1 uses Docker as isolation boundary |
| Full DIDComm v2 spec | Not implemented | We do JWS + did:peer:2. No routing, no DID doc lookup, no did:key |
| Python LLM agent | Not built | We provide TypeScript SDK + sample. LLM integration is consumer's job |
| Production Redis cluster | Phase 2 | Single Redis container sufficient for dev/validation |
| ML-based anomaly detection | Phase 2 | Phase 1 uses deterministic regex rules |
| gRPC | Not used | REST/JSON — simpler for heterogeneous agents (Python, Node, Go) |
| mTLS between services | Phase 2 | Trusted Docker network for Phase 1 |

---

## Project Structure

```
Agent2Agent/
├── .gitignore
├── docker-compose.yml
├── key-guard/                          # Go module: the key service
│   ├── cmd/key-guard/main.go
│   ├── internal/
│   │   ├── crypto/
│   │   │   ├── ed25519.go             # Key generation, signing, verification
│   │   │   └── did.go                 # did:peer + DIDComm JWS envelope
│   │   ├── validation/
│   │   │   ├── schema.go              # JSON Schema validation for intents
│   │   │   ├── budget.go              # Rate limit / budget enforcement
│   │   │   └── policies.go            # Deterministic policy engine
│   │   ├── storage/
│   │   │   ├── redis.go               # Redis client wrapper
│   │   │   └── revocation.go          # Cache + revocation check
│   │   └── server/
│   │       ├── routes.go              # HTTP handlers
│   │       ├── middleware.go          # Request ID, logging, recovery, metrics
│   │       └── types.go               # Request/response DTOs
│   ├── Dockerfile                     # Multi-stage: golang:alpine → distroless
│   └── tests/
│       ├── crypto_test.go
│       ├── validation_test.go
│       └── integration_test.go
│
├── agent-sdk/                         # TypeScript client library for agents
│   ├── src/
│   │   ├── index.ts
│   │   ├── key-guard-client.ts        # HTTP client with retry + backoff
│   │   ├── intent.ts                  # IntentBuilder
│   │   └── revocation.ts             # Revocation checker (Redis)
│   └── tests/
│
├── tools/
│   ├── keygen/                        # DID key generation CLI (Go)
│   └── sanity-monitor/                # Deterministic log watcher (Go)
│       └── rules/
│           ├── hallucination.go
│           ├── injection.go
│           └── revocation.go
│
├── tests/
│   ├── e2e/
│   │   ├── docker-compose.e2e.yml
│   │   ├── happy-path.test.ts
│   │   └── revocation-flow.test.ts
│   └── load/sign-benchmark.go
│
├── docs/
│   ├── architecture.md
│   ├── api-contracts.md
│   └── threat-model.md
│
└── scripts/
    ├── setup.sh
    └── dev.sh
```

---

## Phases

### Phase 0 — Project Scaffolding (2h)

**Deliverables:**
- `.gitignore` (ignores `node_modules/`, `*.key`, `*.pem`, `dist/`, `.env`)
- `docker-compose.yml` defining `key-guard`, `redis`, `sanity-monitor` services on shared `a2a-net` network
- `key-guard/go.mod` + `tools/keygen/go.mod` + `tools/sanity-monitor/go.mod`
- `key-guard/Dockerfile` multi-stage: `golang:1.25-alpine` build → `distroless/static` runtime
- `agent-sdk/package.json` + `tsconfig.json`
- `scripts/setup.sh` and `scripts/dev.sh`

**Go dependencies:**
| Package | Purpose |
|---------|---------|
| `go-chi/chi/v5` | Lightweight HTTP router (stdlib-compatible) |
| `redis/go-redis/v9` | Official Redis client |
| `xeipuuv/gojsonschema` | JSON Schema validation |
| `prometheus/client_golang` | Metrics (`/metrics` endpoint) |
| `google/uuid` | Request ID generation |

**Node dependencies:**
| Package | Purpose |
|---------|---------|
| `typescript`, `tsx` | Dev/run |
| `vitest` | Testing |
| `ioredis` | Redis client |

**Docker Compose skeleton:**
```yaml
services:
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck: { test: ["CMD", "redis-cli", "ping"] }

  key-guard:
    build: ./key-guard
    ports: ["3000:3000"]
    environment:
      - REDIS_URL=redis://redis:6379
      - KEY_GUARD_PORT=3000
    depends_on: [redis]

  sanity-monitor:
    build: ./tools/sanity-monitor
    environment:
      - REDIS_URL=redis://redis:6379
      - AGENT_LOG_PATH=/var/log/agent
    volumes: [./logs:/var/log/agent]
    depends_on: [redis]

networks:
  a2a-net:
    driver: bridge
```

---

### Phase 1 — Key Guard Core (8h)

#### 1A — Crypto Layer (2h)

**`internal/crypto/ed25519.go`:**
```go
func GenerateKey() (seed []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey, err error)
func Sign(priv ed25519.PrivateKey, payload []byte) []byte
func Verify(pub ed25519.PublicKey, payload []byte, sig []byte) bool
```
- Uses Go stdlib `crypto/ed25519` — zero CGO, no external deps
- Seed loaded from `KEY_GUARD_SEED` env var (Docker secrets in prod)
- No key material written to disk by the service

**`internal/crypto/did.go`:**
```go
func DIDFromPublicKey(pub []byte) string                // did:peer:2 encoding
func PublicKeyFromDID(did string) ([]byte, error)       // decode
func BuildEnvelope(payload []byte, priv ed25519.PrivateKey, fromDID, toDID string) (*Envelope, error)
```
- `did:peer:2` format (short-form, self-contained key material)
- Envelope = JWS Compact Serialization (RFC 7515): `base64url(protected).base64url(payload).base64url(signature)`
- No blockchain or registry needed — key is in the DID string

#### 1B — Validation Layer (2h)

**`internal/validation/schema.go`:**
- JSON Schema with `action` enum-restricted: `["a2a.message.sign", "a2a.credential.issue", "did.update"]`
- `nonce`: min 16 chars (prevents replay)
- `timestamp`: must be within `MAX_TIMESTAMP_SKEW` (default 60s) of server clock

**Request schema:**
```json
{
  "action": "a2a.message.sign",
  "payload": {
    "content": "Hello, Agent Beta!",
    "content_type": "text/plain",
    "recipient_did": "did:peer:2.Ez6LSbys..."
  },
  "agent_id": "agent-alpha",
  "timestamp": 1749760000,
  "nonce": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**`internal/validation/budget.go`:**
- Sliding window rate limit: 100 signatures/minute per `agent_id`
- Budget: 1000 signatures/hour
- Uses Redis for cross-instance counting (Phase 1 single-instance: in-memory)

**`internal/validation/policies.go`:**
```go
type PolicyFunc func(*SigningIntent) *PolicyResult

var DefaultPolicies = []PolicyFunc{
    MaxMessageSize(10 * 1024),        // max 10KB payload
    NoSystemPromptOverride(),         // blocks "ignore previous instructions"
    AllowedRecipientDIDs(nil),        // allow all (whitelist later)
    ValidActionForRole(),             // action allowed for agent's role
}
```

**Success Response (200):**
```json
{
  "status": "signed",
  "request_id": "req-abc123",
  "did": "did:peer:2.Ez6L...",
  "envelope": {
    "protected": "base64url(...)",
    "payload": "base64url(content)",
    "signature": "base64url(ed25519 sig)"
  }
}
```

**Error Responses:**

| Status | `status` field | Trigger |
|--------|---------------|---------|
| 400 | `invalid_schema` | JSON Schema failure |
| 400 | `expired_timestamp` | timestamp > 60s from server |
| 400 | `reused_nonce` | nonce already seen in TTL window |
| 403 | `recipient_revoked` | Redis shows revoked recipient DID |
| 429 | `rate_limit_exceeded` | Budget exceeded |
| 503 | `service_unavailable` | Redis down (fail-closed) |

#### 1C — Storage Layer (1h)

**`internal/storage/redis.go`:**
- Redis client connection with 100ms timeout
- Health check: `PING`

**`internal/storage/revocation.go`:**
- 10s in-memory cache (avoids Redis hot-path on every sign)
- `CheckRevoked(did string) (bool, error)`
- Cache hit (revoked) → return immediately
- Cache miss → query Redis → populate cache
- Redis timeout → fail-closed (returns error → 503)

**`internal/storage/nonce.go`:**
- In-memory `sync.Map` with TTL (5 min)
- Atomic check-and-set to prevent race conditions
- Phase 2: move to Redis for multi-instance support

#### 1D — HTTP Server (3h)

**Routes:**

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| POST | `/v1/sign` | `handleSign` | Sign an intent (full validation pipeline) |
| GET | `/v1/health` | `handleHealth` | Health check (Redis, key loaded) |
| GET | `/v1/did` | `handleGetDID` | Return service's public DID |
| GET | `/metrics` | (Prometheus) | Metrics endpoint |

**Signing flow:**
```
1. Parse body → SigningIntent
2. Validate JSON Schema
3. Check nonce not reused (sync.Map with TTL)
4. Check timestamp within MAX_TIMESTAMP_SKEW
5. Run policy engine (all policies must pass)
6. Check recipient DID revocation (Redis + cache)
7. Check budget/rate limits
8. Sign payload with Ed25519
9. Build JWS DIDComm envelope
10. Return signed message
```

**Middleware:**
- Request ID injection (`X-Request-ID`)
- Structured JSON logging (request_id, agent_id, action, outcome, duration)
- Panic recovery (never crash)
- Rate limit pre-check (quick reject before validation)
- Prometheus HTTP metrics (request count, duration, status codes)

---

### Phase 2 — Redis Revocation + Sanity Monitor (5h)

#### 2A — Revocation Circuit Breaker (1h)

**Redis data model:**
```
Key:   revocation:{did:peer:xxxx}
Value: "revoked" | "suspended"
TTL:   300 seconds (configurable via REVOCATION_TTL env var)
```

**Operations:**

| Action | Redis Command | Who |
|--------|---------------|-----|
| Revoke | `SET revocation:{did} "revoked" EX 300` | Sanity Monitor |
| Check | `GET revocation:{did}` | Key Guard (+cache) |
| Suspend | `SET revocation:{did} "suspended" EX 60` | Sanity Monitor |
| Clear | `DEL revocation:{did}` | Admin (or auto-expire) |

**Key Guard integration:**
- On every `/v1/sign`, check `recipient_did` via `RevocationStore`
- 10s in-memory cache with background refresh
- If Redis is unreachable: **fail-closed** (return 503)

#### 2B — Sanity Monitor (4h)

**`tools/sanity-monitor/main.go`:**
- File watcher (tail `AGENT_LOG_PATH`) via polling every 500ms
- Reads structured JSON logs
- On each new log line, runs all rule engines

**Rules:**

**`rules/hallucination.go`:**
```go
var hallucinationPatterns = []string{
    `(?i)i(\s+am\s+)?(not\s+)?(sure|certain|confident)`,
    `(?i)i(\s+dont\s+|don't\s+)?know`,
    `(?i)that(\s+is\s+)?(incorrect|wrong|false)`,
    `(?i)cannot\s+(answer|respond|process)`,
}
```

**`rules/injection.go`:**
```go
var injectionPatterns = []string{
    `(?i)ignore\s+(all\s+)?(previous|the\s+above|your)\s+(instructions|prompts)`,
    `(?i)system\s+prompt`,
    `(?i)you\s+are\s+now\s+`,
    `(?i)do\s+not\s+follow`,
    `(?i)dan\s+mode`,
    `(?i)[A-Za-z0-9+/]{40,}={0,2}`,       // suspicious base64
}
```

**Score-based alerting:**
- Hallucination: 2 points per match, threshold 5
- Injection: 10 points per match, threshold 5
- Matches decay over a 60s rolling window
- Only scores >= threshold trigger revocation
- Prevents single false positive from causing damage

**Revocation publishing (`rules/revocation.go`):**
```go
// On threshold reached:
// 1. Determine agent DID from log source
// 2. SET revocation:{did} "revoked" EX {TTL}
// 3. Log structured event for audit trail
```

---

### Phase 3 — Agent SDK (4h)

**Public API (`agent-sdk/src/index.ts`):**
```typescript
export { KeyGuardClient } from './key-guard-client'
export { createIntent, IntentBuilder } from './intent'
export { RevocationChecker } from './revocation'
export type { SigningIntent, SignResult, SignedMessage }
```

**`key-guard-client.ts`:**
- HTTP client to Key Guard (`POST /v1/sign`)
- **Retry with exponential backoff** (3 attempts: 100ms, 300ms, 900ms)
- Only retries on 503 (Redis down) — not on 400/403/429
- Timeout: 5s per request

**`intent.ts`:**
```typescript
class IntentBuilder {
  constructor(agentId: string)
  setAction(action: 'a2a.message.sign' | 'a2a.credential.issue' | 'did.update'): this
  setPayload(content: string, contentType?: string, recipientDID?: string): this
  setNonce(nonce: string): this
  build(): SigningIntent   // auto-sets timestamp + random nonce
}
```

**`revocation.ts`:**
```typescript
class RevocationChecker {
  constructor(redisURL: string)
  // Check before processing incoming A2A message
  async isRevoked(did: string): Promise<boolean>
  // 10s in-memory cache to avoid Redis on every message
}
```

**Usage example:**
```typescript
import { KeyGuardClient, IntentBuilder, RevocationChecker } from '@stumgart/a2a-agent-sdk'

const guard = new KeyGuardClient('http://key-guard:3000')
const revoker = new RevocationChecker('redis://redis:6379')

// Before processing incoming message:
if (await revoker.isRevoked(msg.fromDID)) {
  throw new Error('Message from revoked agent')
}

// Sign outgoing message:
const intent = new IntentBuilder('agent-alpha')
  .setAction('a2a.message.sign')
  .setPayload('Hello from Agent Alpha', 'text/plain', 'did:peer:xyz')
  .build()

const result = await guard.sign(intent)
// result.did, result.envelope.signature
```

---

### Phase 4 — Integration & Testing (3h)

**E2E Tests (`tests/e2e/`):**

| Test | Scenario | Expected |
|------|----------|----------|
| Happy path | Valid intent → sign | Status "signed", valid Ed25519 signature |
| Revocation | Revoke DID → attempt sign | 403 "recipient_revoked" |
| Invalid schema | 10 malformed intents | 10x 400 |
| Rate limit | 110 req in 1 min | Last 10 = 429 |
| Nonce replay | Same nonce twice | Second = 400 |
| Clock skew | timestamp >60s old | 400 |
| Redis down | Stop Redis → try sign | 503 (fail-closed) |
| Sanity Monitor | Injection pattern in log | Revocation key appears in Redis |

**Load Test (`tests/load/sign-benchmark.go`):**
- Target: >1000 signatures/second on local Docker
- Measure: throughput, latency p50/p99

---

## Refined Technical Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Key Guard language | Go | Native concurrency, single binary, stdlib `crypto/ed25519` = zero CGO |
| HTTP router | `chi/v5` | Lightweight, stdlib-compatible, no reflection-heavy init |
| JSON Schema validation | `gojsonschema` | Deterministic, well-specified, agent cannot bypass |
| Envelope format | JWS Compact (RFC 7515) | Standard, minimal, sufficient for A2A message signing |
| DID method | `did:peer:2` | Self-contained key, no blockchain, perfect for A2A |
| Nonce storage (Phase 1) | In-memory `sync.Map` + TTL | Simpler than Redis for single instance |
| Nonce storage (Phase 2+) | Redis hash + TTL | Required for multi-instance Key Guard |
| Revocation cache | 10s in-memory TTL | Prevents Redis hot-path. 10s staleness acceptable |
| SDK retry | Exponential backoff (3 attempts) | Resilient to transient Key Guard unavailability |
| Fail-closed | Redis error → 503 | Security > availability for crypto ops |
| Configuration | Environment variables | 12-factor app. Docker secrets in production. |

---

## Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Key extraction via debug symbols | Low | Critical | Distroless Docker, `CGO_ENABLED=0`, binary strip |
| Sanity Monitor false positives | High | Low-Med | Score-based, 5min auto-expiry, admin override CLI |
| Redis SPOF (dev) | Medium | High | Dev: acceptable. Prod: Redis Sentinel. Fail-closed on down |
| Race condition in nonce store | Low | Medium | `sync.Map` + atomic CAS. Phase 2: Redis-backed |
| Clock skew >60s | Medium | Low-Med | Configurable `MAX_TIMESTAMP_SKEW` env var |
| Key Guard crash mid-sign | Low | High | Nonce already consumed (no duplicate). Client retries |
| Key rotation | Medium | High | Seed via env var only. Rotate = new container. Old DID revoked in Redis |
| Multi-instance Key Guard | Low (Phase 1) | Medium | Nonce moves to Redis. Policies are stateless (no issue) |
| DID doesn't exist | Low | Low | Key Guard validates format only. Resolution is agent's job |

---

## Success Criteria

### Automated (CI-gate):
- [ ] `crypto/ed25519` sign + verify cycle passes 100% of generated keys
- [ ] 10 invalid intents → 10x 400 responses
- [ ] Rate limit: 110 requests in 1 min → last 10 get 429
- [ ] Revoke a DID → sign to that DID → 403 rejection
- [ ] Sanity Monitor detects known injection pattern → revocation key in Redis
- [ ] Nonce replay → second use returns 400
- [ ] Clock drift → intent with timestamp >60s returns 400
- [ ] `docker compose build` succeeds for all services
- [ ] POST `/v1/sign` with valid intent → returns `status: "signed"` + valid Ed25519 signature
- [ ] Redis stopped → Key Guard returns 503 (fail-closed)
- [ ] Load test: >1000 signatures/second

### Manual Verification:
- [ ] Key isolation: agent container cannot access `KEY_GUARD_SEED` env var
- [ ] Network isolation: agent cannot reach Redis directly (only via Key Guard)
- [ ] All signing requests logged with request_id, agent_id, action, outcome
- [ ] Revocation takes effect within <1s of Sanity Monitor detection

---

## Effort Summary

| Phase | Tasks | Time | Depends On |
|-------|-------|------|------------|
| **Phase 0** | Scaffolding, Docker, Go mods | 2h | — |
| **Phase 1A** | Crypto (ed25519, DID) | 2h | Phase 0 |
| **Phase 1B** | Validation (schema, budget, policies) | 2h | Phase 0 |
| **Phase 1C** | Storage (Redis, revocation) | 1h | Phase 0 |
| **Phase 1D** | HTTP Server (routes, middleware) | 3h | 1A + 1B + 1C |
| **Phase 2A** | Redis revocation circuit breaker | 1h | Phase 1C |
| **Phase 2B** | Sanity Monitor | 4h | Phase 2A |
| **Phase 3** | Agent SDK (TypeScript) | 4h | Phase 1D |
| **Phase 4** | E2E tests, load tests, docs | 3h | Phases 1-3 |
| **Buffer** | Integration bugs, tuning | 3h | — |
| **Total** | | **~25h** | |

**Recommended sequencing:** Phase 0 → (1A + 1B + 1C in parallel) → 1D → 2A → 2B → 3 → 4

**First actionable step:** Create `.gitignore`, `docker-compose.yml`, and `key-guard/go.mod`. Then implement `internal/crypto/ed25519.go` with `GenerateKey()`, `Sign()`, `Verify()` + unit tests. This gives a tangible deliverable (working crypto + bootable service) within ~3h.
