import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_KEY_DIR = Path(__file__).parent.parent.parent / "keys"
_PRIVATE_KEY_PATH = _KEY_DIR / "signing.pem"
_PUBLIC_KEY_PATH = _KEY_DIR / "signing.pub"
ISSUER = "agent-cred-broker"
KEY_ID = "ed25519-v1"


def _load_private_key():
    return serialization.load_pem_private_key(
        _PRIVATE_KEY_PATH.read_bytes(), password=None
    )


def _load_public_key():
    return serialization.load_pem_public_key(_PUBLIC_KEY_PATH.read_bytes())


def mint(
    principal: str,
    agent_id: str,
    action: str,
    resource: str,
    ttl_seconds: int,
    purpose: str,
) -> tuple[str, str, datetime]:
    """Mint an Ed25519-signed JWT. Returns (token, jti, expires_at)."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)
    jti = str(uuid.uuid4())

    payload = {
        "iss": ISSUER,
        "sub": principal,
        "azp": agent_id,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": jti,
        "scope": {"action": action, "resource": resource},
        "purpose": purpose,
    }
    private_key = _load_private_key()
    token = jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": KEY_ID})
    return token, jti, expires


def verify(token: str) -> dict:
    """Verify and decode a token. Raises jwt.InvalidTokenError on failure."""
    public_key = _load_public_key()
    return jwt.decode(token, public_key, algorithms=["EdDSA"], issuer=ISSUER)


def jwks() -> dict:
    """Return the JWKS (JSON Web Key Set) for the public key."""
    pub = _load_public_key()
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    import base64
    x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": KEY_ID,
                "use": "sig",
                "x": x,
            }
        ]
    }
