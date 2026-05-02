# agent-cred-broker

A short-lived credential vending service for AI agents. Agents request scoped, time-limited JWT tokens; the broker evaluates a policy, mints an Ed25519-signed token, and appends a tamper-evident hash-chained audit record. No agent gets more access than its policy allows.

## How it works

```
Agent → POST /credentials {principal, agent_id, action, resource, ttl_seconds, purpose}
              │
              ▼
        PolicyEngine
          ├── principal == registered owner?
          ├── action matches allowed_scopes? (fnmatch glob)
          └── ttl <= max_ttl_seconds?
              │  deny → 403 + audit record
              │  allow
              ▼
        JWT mint (Ed25519, scoped JTI, short TTL)
              │
              ▼
        Audit append (SHA-256 hash chain)
              │
              ▼
        ← {token, scope, expires_at}
```

## Quickstart

```bash
git clone <repo>
cd agent-cred-broker
uv sync

# Generate signing keypair (first-time setup)
openssl genpkey -algorithm Ed25519 -out keys/signing.pem
openssl pkey -in keys/signing.pem -pubout -out keys/signing.pub
chmod 600 keys/signing.pem

# Run 5 demo scenarios (no database required)
uv run broker-cli demo

# Verify audit chain integrity
uv run broker-cli verify-chain

# Decode a token
uv run broker-cli decode-token <jwt>
```

## API

```bash
# Start the server (requires Postgres + Redis)
docker compose up -d
broker-server

# Issue a credential
curl -s -X POST http://localhost:8000/credentials \
  -H 'Content-Type: application/json' \
  -d '{"principal":"alice","agent_id":"data-pipeline","action":"s3:GetObject","resource":"s3://my-bucket/*","ttl_seconds":300,"purpose":"nightly ETL"}'

# Verify audit chain
curl -s http://localhost:8000/audit/verify

# Get JWKS (for downstream JWT validation)
curl -s http://localhost:8000/.well-known/jwks.json

# Health check
curl -s http://localhost:8000/health
```

## Development

```bash
# Demo — no database needed
uv run broker-cli demo

# Start backing services
docker compose up -d

# Start API server
uv run uvicorn src.api.server:app --port 8000 --reload

# Run tests
uv run pytest tests/ -v
```

## Policy configuration

Agents are registered in `src/core/policy.py`:

```python
AGENT_REGISTRY: dict[str, dict] = {
    "data-pipeline": {
        "owners": {"alice@example.com"},
        "allowed_scopes": [
            ("s3:GetObject", "arn:aws:s3:::my-bucket/*"),
            ("s3:PutObject", "arn:aws:s3:::my-bucket/output/*"),
        ],
        "max_ttl_seconds": 1800,
    },
}
```

`owners` is a set of principals allowed to request credentials for this agent. `allowed_scopes` is a list of `(action, resource)` pairs where the resource supports `fnmatch` glob patterns — `arn:aws:s3:::my-bucket/*` matches any object in the bucket.

## Threat model

See [THREAT_MODEL.md](THREAT_MODEL.md) for a full breakdown of controls, gaps, and the production deployment checklist.

Key points:
- `keys/signing.pem` must be in a secrets manager in production — not a file on disk.
- The `user_token` field is accepted but **not verified** in this implementation. Wire it to a real IdP before production use.
- There is no token revocation mechanism. Keep TTLs short.
- The hash chain detects record modification but not an attacker who rewrites the chain after tampering.
