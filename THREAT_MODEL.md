# Threat Model: agent-cred-broker

## What this system is

A short-lived credential vending service for AI agents. Agents present a request (principal, agent ID, action, resource, purpose, TTL); the broker evaluates a policy, mints an Ed25519-signed JWT scoped to the approved action, and appends a hash-chained audit record. All issuances and denials are logged with tamper-evident chaining.

---

## Assets

| Asset | Sensitivity | Notes |
|---|---|---|
| `keys/signing.pem` (Ed25519 private key) | Critical | Compromise allows forging arbitrary tokens |
| Issued JWTs | High | Valid tokens grant access to downstream resources |
| Audit log | High | Tamper-evident; integrity violation indicates an attack |
| `ANTHROPIC_API_KEY` (if used) | High | Billed API access |
| Downstream resources (databases, APIs) | Varies | The broker protects access to these |

---

## Threat actors

| Actor | Goal | Entry point |
|---|---|---|
| Compromised agent | Obtain credentials for actions beyond its scope | POST /credentials with inflated scope or TTL |
| External attacker | Forge tokens or replay captured tokens | Network interception, stolen private key |
| Malicious insider | Alter audit log to conceal credential abuse | Direct database access |
| Prompt-injected agent | Cause agent to request credentials for attacker's purpose | Injected payload in agent's input |

---

## Security controls

### 1. Ed25519 JWT signing

Tokens are signed with an Ed25519 private key stored at `keys/signing.pem` (600 permissions, gitignored). Verifiers use the public key served at `/.well-known/jwks.json`.

**Assumption:** the private key file is accessible only to the broker process. If the host is compromised, all issued tokens must be considered forged.

**Short TTL:** maximum 3600 seconds (1 hour); minimum 30 seconds. Short-lived tokens limit the blast radius of token leakage — a stolen token expires quickly.

### 2. Scope-limited policy

Each registered agent (`AGENT_REGISTRY`) has:
- An explicit owner principal
- An allowlist of `allowed_scopes` (fnmatch glob patterns)
- A `max_ttl_seconds` cap

A request is denied if:
- The requesting principal is not the registered owner of the agent
- The requested action does not match any allowed scope
- The requested TTL exceeds the agent's cap

**Limit:** the registry is static and compiled into `src/core/policy.py`. Dynamic agent registration is not supported — new agents require a code change and redeploy.

### 3. Hash-chained audit log

Every issuance and denial is recorded with:
- `prev_hash`: SHA-256 of the previous record's canonical representation
- `record_hash`: SHA-256 of this record concatenated with `prev_hash`

`GET /audit/verify` recomputes the entire chain and returns `{"valid": true/false}`.

**What this detects:** deletion or modification of any record, or insertion of a record out of order.

**What this does not detect:** an attacker with database write access who also recomputes and rewrites all hashes from the tampered record forward. Mitigation for this requires an external append-only log (e.g. a transparency log) — not implemented.

### 4. `user_token` field

Included in `CredentialRequest` but **not verified** in this implementation (marked `TODO(production)`). In production this must be validated against a real IdP (OAuth introspection, JWKS verify) before issuance.

---

## Trust boundary diagram

```
AI Agent
    │  POST /credentials {principal, agent_id, action, resource, ttl, user_token}
    ▼
PolicyEngine
    ├── principal == registered owner?         deny if no
    ├── action matches allowed_scopes?          deny if no
    └── ttl <= max_ttl_seconds?                 deny if no
         │ allow
         ▼
    JWT mint (Ed25519, short-lived, scoped JTI)
         │
         ▼
    Audit append (hash-chained)
         │
         ▼
    CredentialResponse {token, expires_at, scope}
         │
    ▼
Downstream Resource
    validates JWT via /.well-known/jwks.json
```

**The trust boundary is at the policy evaluation step.** The broker trusts that `principal` and `agent_id` are honest self-reports — in production, both must be verified via the `user_token`.

---

## What the broker does NOT protect against

1. **Private key compromise.** Anyone with `keys/signing.pem` can mint arbitrary tokens. The key must be in a secrets manager (Vault, AWS Secrets Manager) in production, not a file.
2. **Unverified user_token.** The current implementation does not validate the bearer's identity. A rogue caller can claim any principal name.
3. **Token leakage after issuance.** Once issued, a token is valid until expiry. The broker has no revocation mechanism (no token blocklist). Mitigation: very short TTLs.
4. **Database integrity with write access.** An attacker with Postgres write access can recompute the hash chain after modification. An external transparency log would close this gap.
5. **Replay attacks.** JTI (JWT ID) is unique per token but the broker does not maintain a JTI blocklist to reject replayed tokens. Downstream resources must check JTI uniqueness.
6. **Denial of service.** No rate limiting on POST /credentials. A compromised agent could flood the broker and exhaust the database connection pool.

---

## Deployment security checklist

- [ ] `keys/signing.pem` stored in a secrets manager, not on disk
- [ ] `user_token` validation wired to a real IdP
- [ ] Postgres connection uses TLS (`sslmode=require`)
- [ ] Redis connection uses TLS and AUTH
- [ ] Rate limiting on POST /credentials (per agent_id)
- [ ] JTI blocklist for token revocation
- [ ] Audit log replicated to an external append-only store
- [ ] `ANTHROPIC_API_KEY` (if used) rotated regularly and never logged
