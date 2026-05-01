import fnmatch
from src.core.models import CredentialRequest, PolicyDecision

# In production: load from a database or config service with Git-PR-based change control.
AGENT_REGISTRY: dict[str, dict] = {
    "research-agent-v2": {
        "owners": {"alice@example.com", "bob@example.com"},
        "allowed_scopes": [
            ("s3:GetObject", "arn:aws:s3:::q3-reports/*"),
            ("snowflake:Select", "warehouse:research/db:public/*"),
        ],
        "max_ttl_seconds": 1800,
    },
    "trading-agent-v1": {
        "owners": {"bob@example.com"},
        "allowed_scopes": [
            ("trading:GetPosition", "account:trading/portfolio:main"),
        ],
        "max_ttl_seconds": 600,  # read-only by design — no execute scopes
    },
}


def _scope_matches(requested_action: str, requested_resource: str, allowed_scopes: list) -> bool:
    for allowed_action, allowed_resource in allowed_scopes:
        action_ok = requested_action == allowed_action
        resource_ok = fnmatch.fnmatch(requested_resource, allowed_resource)
        if action_ok and resource_ok:
            return True
    return False


def evaluate(req: CredentialRequest) -> PolicyDecision:
    agent = AGENT_REGISTRY.get(req.agent_id)
    if not agent:
        return PolicyDecision(allowed=False, reason=f"unknown agent '{req.agent_id}'")

    if req.principal not in agent["owners"]:
        return PolicyDecision(
            allowed=False,
            reason=f"'{req.principal}' is not an authorized owner of agent '{req.agent_id}'",
        )

    if req.ttl_seconds > agent["max_ttl_seconds"]:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"requested TTL {req.ttl_seconds}s exceeds max "
                f"{agent['max_ttl_seconds']}s for agent '{req.agent_id}'"
            ),
        )

    if not _scope_matches(req.action, req.resource, agent["allowed_scopes"]):
        return PolicyDecision(
            allowed=False,
            reason=f"scope '{req.action}' on '{req.resource}' not in allowed scopes for '{req.agent_id}'",
        )

    return PolicyDecision(allowed=True, reason="all checks passed")
