import json
import typer
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

app = typer.Typer(help="Agent Credential Broker — demo and admin CLI.")
console = Console()

_DEMO_SCENARIOS = [
    {
        "label": "Valid grant (research agent, S3 read)",
        "req": {
            "principal": "alice@example.com",
            "agent_id": "research-agent-v2",
            "action": "s3:GetObject",
            "resource": "arn:aws:s3:::q3-reports/report.csv",
            "ttl_seconds": 300,
            "purpose": "Q3 earnings review",
            "user_token": "stub-token",
        },
        "expect": "issued",
    },
    {
        "label": "Wrong owner (Alice → trading agent)",
        "req": {
            "principal": "alice@example.com",
            "agent_id": "trading-agent-v1",
            "action": "trading:GetPosition",
            "resource": "account:trading/portfolio:main",
            "ttl_seconds": 60,
            "purpose": "portfolio check",
            "user_token": "stub-token",
        },
        "expect": "denied",
    },
    {
        "label": "Excessive TTL (trading agent, 1h requested)",
        "req": {
            "principal": "bob@example.com",
            "agent_id": "trading-agent-v1",
            "action": "trading:GetPosition",
            "resource": "account:trading/portfolio:main",
            "ttl_seconds": 3600,
            "purpose": "long-running task",
            "user_token": "stub-token",
        },
        "expect": "denied",
    },
    {
        "label": "Out-of-scope action (research agent → trading)",
        "req": {
            "principal": "alice@example.com",
            "agent_id": "research-agent-v2",
            "action": "trading:ExecuteOrder",
            "resource": "account:trading/portfolio:main",
            "ttl_seconds": 60,
            "purpose": "unauthorized trade",
            "user_token": "stub-token",
        },
        "expect": "denied",
    },
    {
        "label": "Valid grant (trading agent, position read)",
        "req": {
            "principal": "bob@example.com",
            "agent_id": "trading-agent-v1",
            "action": "trading:GetPosition",
            "resource": "account:trading/portfolio:main",
            "ttl_seconds": 300,
            "purpose": "risk check",
            "user_token": "stub-token",
        },
        "expect": "issued",
    },
]


@app.command("demo")
def demo():
    """Walk through five credential scenarios (no DB required)."""
    from src.core.policy import evaluate
    from src.core.jwt_signer import mint
    from src.core.models import CredentialRequest

    console.print(Panel(
        "[bold]Agent Credential Broker Demo[/bold]\n"
        "Simulates issuance and denial scenarios against the policy engine.",
        border_style="blue",
    ))
    console.print()

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Scenario")
    table.add_column("Expected")
    table.add_column("Outcome", justify="center")
    table.add_column("Detail")

    for scenario in _DEMO_SCENARIOS:
        req = CredentialRequest(**scenario["req"])
        decision = evaluate(req)

        if decision.allowed:
            token, jti, expires = mint(
                req.principal, req.agent_id, req.action,
                req.resource, req.ttl_seconds, req.purpose,
            )
            outcome = "[green]ISSUED[/green]"
            detail = f"expires {expires.strftime('%H:%M:%S UTC')} · jti:{jti[:8]}…"
        else:
            outcome = "[red]DENIED[/red]"
            detail = decision.reason

        table.add_row(scenario["label"], scenario["expect"], outcome, detail)

    console.print(table)


@app.command("verify-chain")
def verify_chain():
    """Check audit log chain integrity (requires DB)."""
    from src.core.audit import verify_chain as _verify
    ok, message = _verify()
    if ok:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")
        raise typer.Exit(1)


@app.command("decode-token")
def decode_token(token: str):
    """Decode and display a JWT issued by this broker."""
    from src.core.jwt_signer import verify
    try:
        payload = verify(token)
        console.print_json(json.dumps(payload, indent=2))
    except Exception as e:
        console.print(f"[red]Invalid token:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
