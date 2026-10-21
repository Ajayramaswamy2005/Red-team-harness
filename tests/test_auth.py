"""
Tests for API-key authentication and the key-hashing helper.
"""


import httpx
import pytest
from httpx import ASGITransport

from src.api.security import hash_key, require_api_key
from src.api.server import app
from src.config import settings


def test_hash_key_is_stable_and_sha256():
    h = hash_key("my-secret")
    assert h == hash_key(" my-secret ")  # trimmed
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h)


@pytest.mark.asyncio
async def test_require_api_key_disabled_allows_anonymous(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", False)
    principal = await require_api_key(bearer=None, x_api_key=None)
    assert principal == "auth-disabled"


async def _client():
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_health_is_public(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_key_hashes", hash_key("secret-key"))
    async with await _client() as c:
        res = await c.get("/api/health")
        assert res.status_code == 200
        assert res.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_missing_and_bad_keys(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_key_hashes", hash_key("secret-key"))
    async with await _client() as c:
        assert (await c.get("/api/attacks")).status_code == 401
        assert (
            await c.get("/api/attacks", headers={"Authorization": "Bearer wrong-key"})
        ).status_code == 401
        assert (
            await c.get("/api/attacks", headers={"X-API-Key": "wrong-key"})
        ).status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_accepts_valid_key_both_schemes(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_key_hashes", hash_key("secret-key"))
    async with await _client() as c:
        r_bearer = await c.get("/api/attacks", headers={"Authorization": "Bearer secret-key"})
        r_header = await c.get("/api/attacks", headers={"X-API-Key": "secret-key"})
        # A valid key must get past auth (not 401); the route itself returns 200.
        assert r_bearer.status_code != 401
        assert r_header.status_code != 401


@pytest.mark.asyncio
async def test_auth_fails_closed_when_no_keys_configured(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_key_hashes", "")
    async with await _client() as c:
        res = await c.get("/api/attacks", headers={"Authorization": "Bearer anything"})
        assert res.status_code == 503  # misconfigured, never falls open


@pytest.mark.asyncio
async def test_security_headers_present(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_key_hashes", hash_key("secret-key"))
    async with await _client() as c:
        res = await c.get("/api/health")
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert "default-src" in res.headers.get("Content-Security-Policy", "")
