# A2A Security — Threat Model (STRIDE)

> **Scope:** A2A Key Guard, Agent SDK, Sanity Monitor, Redis revocation
> **Version:** 0.1.0 | **Date:** 2026-06-12

---

## 1. Data Flow Diagram (Simplified)

```
┌──────────┐   POST /v1/sign    ┌────────────┐   GET revocation:{did}   ┌───────┐
│  Agent    │ ─────────────────► │ Key Guard  │ ◄──────────────────────── │ Redis │
│  (Client) │                   │ (Go HTTP)  │ ────────────────────────► │       │
│           │ ◄──────────────── │            │   SET revocation:{did}   └───────┘
└──────────┘   Signed Msg/JWS   └────────────┘         ▲
                               Internal:                │
                               Sanity Monitor ──────────┘
                               (watches agent logs)
```

### Trust Boundaries

| Boundary | From | To | Model |
|----------|------|----|-------|
| T1 | Agent Network | Key Guard Process | Network boundary (Docker network) |
| T2 | Key Guard Process | Redis Process | Network boundary (internal Docker) |
| T3 | Sanity Monitor | Redis Process | Network boundary (internal Docker) |
| T4 | Host Filesystem | Sanity Monitor | File read boundary (agent logs) |
| T5 | Environment | Key Guard Process | Secret injection (KEY_GUARD_SEED) |

---

## 2. STRIDE Analysis per Component

### 2.1 Key Guard (Go Service)

| Threat | Type | Description | Impact | Mitigation |
|--------|------|-------------|--------|------------|
| KG-01 | **S**poofing | Attacker impersonates a valid agent and submits signing intents | Attacker could sign arbitrary messages | No auth in Phase 1 (trusted network). Future: agent authentication via DID auth + challenge-response |
| KG-02 | **T**ampering | Attacker modifies signing intent in transit | Invalid message gets signed | TLS/mTLS in Phase 2. Network isolation (Docker internal network) prevents injection within the same host |
| KG-03 | **R**epudiation | Agent denies submitting a signing intent | No audit trail | All requests logged with request_id, agent_id, action, outcome, timestamp. Prometheus metrics for sign count |
| KG-04 | **I**nformation Disclosure | Private key extracted from memory/debug symbols | Complete loss of trust | Distroless Docker image, `CGO_ENABLED=0`, binary strip, no debug symbols in production |
| KG-05 | **D**enial of Service | Flood POST /v1/sign with invalid requests | Resource exhaustion | Rate limiting (100/min per agent_id). HTTP timeout (30s). JSON body size limit |
| KG-06 | **E**levation of Privilege | Attacker bypasses validation pipeline | Sign arbitrary payloads | Pipeline is sequential with short-circuit on first failure. JSON Schema validation runs first |

### 2.2 Redis Revocation Store

| Threat | Type | Description | Impact | Mitigation |
|--------|------|-------------|--------|------------|
| RD-01 | **S**poofing | Attacker writes false revocation entries | Legitimate agents denied service | Redis is internal-only (no exposed ports). Sanity Monitor is only authorized writer |
| RD-02 | **T**ampering | Attacker modifies revocation TTL | Revocation expires too early/never | Redis is internal-only. Values expire automatically via EX |
| RD-03 | **R**epudiation | Sanity Monitor falsely revokes a DID | Agent incorrectly blocked | Score-based alerting prevents single false positive. 5-min auto-expiry. Audit log |
| RD-04 | **I**nformation Disclosure | Revocation status leaks agent identity | Attacker learns which agents are blocked | Revocation keys contain DIDs which are public by design |
| RD-05 | **D**enial of Service | Redis memory exhaustion from too many revocation keys | Service degradation | TTL ensures keys auto-expire. Max ~1000 concurrent revoked DIDs |
| RD-06 | **E**levation of Privilege | Redis compromise leads to key guard compromise | Attacker controls signing decisions | Key Guard fails closed (503) if Redis is down. No Redis → no sign |

### 2.3 Sanity Monitor

| Threat | Type | Description | Impact | Mitigation |
|--------|------|-------------|--------|------------|
| SM-01 | **S**poofing | Attacker writes fake agent log entries | False revocation or missed detection | File system access required. Attacker must have write access to agent logs |
| SM-02 | **T**ampering | Attacker modifies Sanity Monitor config | Disable or change detection rules | Config via env vars only (read-only at runtime). No file-based config |
| SM-03 | **R**epudiation | Sanity Monitor triggers false revocation without trace | No accountability | All revocations logged with structured JSON (agent DID, rule matched, score, timestamp) |
| SM-04 | **I**nformation Disclosure | Agent log contents exposed via Sanity Monitor | Agent conversation privacy | Sanity Monitor only reads log files it has access to. Runs inside Docker network |
| SM-05 | **D**enial of Service | Sanity Monitor floods Redis with revocation entries | Redis resource exhaustion | Score-based threshold prevents single-match revocations. Configurable cooldown |
| SM-06 | **E**levation of Privilege | Regex injection via crafted log entries | Bypass detection | Patterns are compiled regex, safe from injection. Score matching is exact |

### 2.4 Agent SDK (TypeScript)

| Threat | Type | Description | Impact | Mitigation |
|--------|------|-------------|--------|------------|
| SDK-01 | **S**poofing | Attacker uses another agent's ID | Sign as another agent | No auth in Phase 1. Key Guard rate-limits by agent_id. Future: per-agent API keys |
| SDK-02 | **T**ampering | Attacker modifies SDK in transit | Compromise all agents | SDK distributed via npm with integrity hashes. Package-lock.json committed |
| SDK-03 | **R**epudiation | Agent fails to check revocation before processing | Process message from revoked agent | RevocationChecker is optional. Agent must call isRevoked() explicitly |
| SDK-04 | **I**nformation Disclosure | SDK leaks Key Guard URL in error messages | Attacker learns internal service topology | Error messages are generic. No stack traces exposed |
| SDK-05 | **D**enial of Service | SDK retries forever on unreachable Key Guard | Resource exhaustion | Max 3 retries with exponential backoff (100ms, 300ms, 900ms). 5s timeout per request |
| SDK-06 | **E**levation of Privilege | SDK bypasses IntentBuilder validation | Send malformed intents | IntentBuilder enforces nonce length (>=16) and agentId presence. But SDK is client-side — Key Guard validates independently |

---

## 3. Risk Matrix

| ID | Threat | Likelihood | Impact | Risk Score | Priority |
|----|--------|-----------|--------|------------|----------|
| KG-04 | Key extraction from memory | Low | Critical | **High** | P0 |
| RD-05 | Redis DoS (memory) | Low | Medium | Medium | P2 |
| KG-05 | Sign endpoint DoS | Medium | Medium | **High** | P1 |
| KG-03 | Repudiation (no audit) | Low | Medium | Medium | P2 |
| SM-05 | Sanity Monitor flood | Low | Low | Low | P3 |
| SDK-02 | SDK tampering | Low | High | Medium | P1 |
| KG-01 | Agent spoofing | Medium | High | **High** | P0 (Phase 2) |
| RD-01 | False revocation | Medium | Medium | Medium | P1 |
| SM-03 | False positive without trace | Medium | Low | Medium | P2 |

### Risk Ratings

| Likelihood | Impact | Rating |
|------------|--------|--------|
| Low | Critical | High |
| Medium | High | High |
| Medium | Medium | Medium |
| Low | High | Medium |
| Low | Medium | Medium |
| Medium | Low | Medium |
| Low | Low | Low |

---

## 4. Security Controls Verification

### Implemented (Phase 1)

| Control | Location | Verification |
|---------|----------|-------------|
| JSON Schema validation | `validation/schema.go` | Unit tests + E2E |
| Timestamp skew check | `validation/schema.go` | Unit tests + E2E |
| Nonce replay protection | `storage/nonce.go` | Unit tests + E2E |
| Policy engine | `validation/policies.go` | Unit tests + E2E |
| Rate limiting (100/min) | `validation/budget.go` | Unit tests + E2E |
| Recipient revocation check | `storage/revocation.go` | Unit tests + E2E |
| Ed25519 signing | `crypto/ed25519.go` | Unit tests |
| DIDComm JWS envelope | `crypto/did.go` | Unit tests |
| Fail-closed on Redis down | `server/routes.go` | Unit tests |
| Secure Docker build | `Dockerfile` | Manual verify |
| Prometheus metrics | `server/middleware.go` | Unit tests |
| Request ID tracing | `server/middleware.go` | Log audit |
| Panic recovery | `server/middleware.go` | Unit tests |
| Score-based anomaly detection | `rules/*.go` | Unit tests |
| Auto-expiring revocation | Redis TTL | E2E tests |
| SDK retry with backoff | `key-guard-client.ts` | Unit tests |
| Nonce min length (16) | `intent.ts` | Unit tests |

### Planned (Phase 2+)

| Control | Priority | Rationale |
|---------|----------|-----------|
| mTLS between services | P1 | Defense in depth for network isolation |
| Agent authentication (DID auth) | P0 | Prevents agent spoofing |
| API key per agent | P0 | Rate limiting by authenticated identity |
| Audit log persistence (file/DB) | P2 | Long-term repudiation protection |
| Redis Sentinel/Cluster | P1 | HA for revocation store |
| Key rotation API | P1 | Rotate without downtime |
| Admin revocation CLI | P2 | Manual override for false positives |
| Alerting on anomaly detection | P1 | Notify operators of potential attacks |
| ML-based anomaly detection | P2 | Replace deterministic regex |

---

## 5. Incident Response Plan

### Scenario: False Positive Revocation

1. **Detection:** Agent reports being unable to send messages
2. **Verification:** Check Redis `GET revocation:{did}` — inspect TTL
3. **Resolution:** `DEL revocation:{did}` via admin CLI (Phase 2)
4. **Root Cause:** Sanity Monitor pattern matched benign text
5. **Prevention:** Adjust threshold or add pattern to whitelist

### Scenario: Key Guard Unavailable

1. **Detection:** Agents receive 503 from POST /v1/sign
2. **Verification:** Check `GET /v1/health` — is Redis connected? Key loaded?
3. **Resolution:** Check Docker logs, restart container
4. **Root Cause:** Redis down, pod restart, config change
5. **Prevention:** Health check monitoring, Redis HA

### Scenario: Key Compromise

1. **Detection:** Unauthorized signed messages detected
2. **Containment:** Stop Key Guard container
3. **Revocation:** Generate new key, start new container with new seed
4. **Recovery:** Old DID added to revocation list, agents update trusted DIDs
5. **Post-mortem:** Audit how key was extracted, harden accordingly

---

## 6. Assumptions & Dependencies

| # | Assumption | Risk if False |
|---|-----------|---------------|
| 1 | Docker network is trusted (no lateral movement) | Attacker can send requests directly to Key Guard |
| 2 | `KEY_GUARD_SEED` is securely injected (Docker secrets/KMS) | Seed leaks via env dump |
| 3 | Node.js runtime is trusted for SDK | Malicious SDK could leak keys (but keys are server-side) |
| 4 | Agent log files are append-only (not modifiable by attacker) | Sanity Monitor can be poisoned |
| 5 | Clock skew between agent and Key Guard < 60s | Legitimate requests rejected as expired |
| 6 | Redis is single-instance (no cluster in Phase 1) | SPOF for revocation checks |

---

## 7. Review Cadence

| Review Type | Frequency | Owner |
|-------------|-----------|-------|
| Threat model update | Per significant feature change | Security team |
| Dependency scan (SCA) | Weekly | CI pipeline |
| SAST scan (go vet, staticcheck) | Per commit | CI pipeline |
| Secret scan (trufflehog) | Per commit | CI pipeline |
| Penetration test | Quarterly | External team |

---

*End of threat model*
