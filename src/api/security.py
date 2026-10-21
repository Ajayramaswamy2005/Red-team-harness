"""
API authentication and request hardening.

Auth model: bearer API keys. The server stores only SHA-256 *hashes* of the
accepted keys (SETTINGS.api_key_hashes) — the raw keys never live on disk or in
env. Clients present the raw key as either:

    Authorization: Bearer <key>
    X-API-Key: <key>

Verification hashes the presented key and compares it against the allowed
hashes in constant time (hmac.compare_digest), so a wrong key can't be
recovered by timing the response.

Generate a key hash for deployment:

    python -m src.api.security <your-secret-key>
    # or let it mint a strong key for you:
    python -m src.api.security --generate
"""

import hashlib
import hmac
import logging

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from src.config import settings

logger = logging.getLogger(__name__)

# auto_error=False so a missing credential falls through to our own 401 with a
# consistent body, and so the two schemes don't fight each other.
_bearer_scheme = HTTPBearer(auto_error=False, description="API key as a bearer token")
_api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_key(raw_key: str) -> str:
    """Return the lowercase hex SHA-256 of an API key (what the server stores)."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def _match(presented_hash: str, allowed: set[str]) -> bool:
    """Constant-time membership test of a hash against the allowed set."""
    matched = False
    for candidate in allowed:
        # compare_digest over every candidate so timing doesn't leak which
        # (or whether an early) entry matched.
        if hmac.compare_digest(presented_hash, candidate):
            matched = True
    return matched


async def require_api_key(
    bearer: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    x_api_key: str | None = Depends(_api_key_scheme),
) -> str:
    """
    FastAPI dependency enforcing API-key auth.

    Returns a short, non-sensitive principal id (the key hash prefix) on success.
    Raises 401 on a missing/invalid key, 503 if auth is enabled but misconfigured.
    """
    if not settings.auth_enabled:
        return "auth-disabled"

    allowed = settings.api_key_hash_set
    if not allowed:
        # Fail closed: auth is on but no keys are configured. Never fall open.
        logger.error("AUTH_ENABLED is true but API_KEY_HASHES is empty — refusing all requests.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server authentication is misconfigured (no API keys set).",
        )

    presented = (bearer.credentials if bearer else None) or x_api_key
    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Send 'Authorization: Bearer <key>' or 'X-API-Key: <key>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not _match(hash_key(presented), allowed):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return hash_key(presented)[:8]


if __name__ == "__main__":
    import secrets
    import sys

    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if args[0] in ("-g", "--generate"):
        key = secrets.token_urlsafe(32)
        print("Generated API key (give this to clients, store it nowhere on the server):")
        print(f"  {key}")
        print("\nAdd this hash to the server's API_KEY_HASHES:")
        print(f"  {hash_key(key)}")
    else:
        raw = args[0]
        print("API_KEY_HASHES entry for this key:")
        print(f"  {hash_key(raw)}")
