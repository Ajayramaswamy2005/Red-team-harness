"""
FastAPI Server — main entrypoint for the Automated Red-Team Harness.
Exposes REST APIs, CI/CD webhook, interactive dashboard, and mock testing endpoint.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, func

from src.config import settings
from src.database import init_db, close_db, async_session_factory
from src.models.attack import Attack
from src.attacks.loader import load_yaml_seeds
from src.api.security import require_api_key
from src.runner.scheduler import RedTeamScheduler

from src.api.routes.attacks import router as attacks_router
from src.api.routes.runs import router as runs_router
from src.api.routes.findings import router as findings_router
from src.api.routes.regressions import router as regressions_router
from src.api.routes.webhooks import router as webhooks_router
from src.dashboard.routes import router as dashboard_router

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("redteam-harness")

scheduler = RedTeamScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle event handler for DB setup, seed initialization, and scheduler."""
    logger.info("Initializing Red-Team Harness database...")
    await init_db()

    # Check and load seed attacks if database is empty
    async with async_session_factory() as session:
        count_res = await session.execute(select(func.count(Attack.id)))
        count = count_res.scalar() or 0
        if count == 0:
            logger.info("Empty attack battery detected. Loading YAML seed files...")
            loaded = await load_yaml_seeds(session)
            logger.info(f"Loaded {loaded} initial attack seeds.")
        else:
            logger.info(f"Battery loaded with {count} active attacks.")

    # Start scheduler if enabled
    if settings.scheduler_enabled:
        scheduler.start()
        logger.info("APScheduler background service active.")

    yield

    # Shutdown
    if scheduler.is_running:
        scheduler.shutdown()
    await close_db()
    logger.info("Red-Team Harness shutdown completed.")


app = FastAPI(
    title="Automated Red-Team Safety Harness",
    description=(
        "Production-grade adversarial testing harness for AI applications, RAG pipelines, "
        "and autonomous agents. Executes safety batteries, scores outputs via deterministic "
        "and LLM judge policies, tracks findings, and permanently prevents regressions."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ── Security headers ──────────────────────────────────────────
# Sent on every response. CSP allows the dashboard's inline code plus the
# Google Fonts and Chart.js CDNs it loads; everything else is same-origin.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy", _CSP)
    # Only assert HSTS when the request arrived over HTTPS (behind a TLS proxy).
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains"
        )
    return response


# ── CORS ──────────────────────────────────────────────────────
# Explicit origin allowlist from config. A wildcard with credentials is
# invalid per the Fetch spec and insecure, so we never emit that combination.
_cors_origins = settings.cors_origins_list
if "*" in _cors_origins:
    if settings.auth_enabled:
        logger.warning("CORS_ALLOW_ORIGINS='*' is not allowed with auth enabled; ignoring it.")
        _cors_origins = []
    else:
        _cors_origins = ["*"]

if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,  # bearer-token auth needs no cookies/credentials
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type"],
        max_age=600,
    )

# ── Routers ───────────────────────────────────────────────────
# Every data/action router requires a valid API key. The dashboard router
# serves the public HTML shell; its data endpoint guards itself.
_auth = [Depends(require_api_key)]
app.include_router(dashboard_router)
app.include_router(attacks_router, dependencies=_auth)
app.include_router(runs_router, dependencies=_auth)
app.include_router(findings_router, dependencies=_auth)
app.include_router(regressions_router, dependencies=_auth)
app.include_router(webhooks_router, dependencies=_auth)


# ── Health & Mock Target Endpoints ────────────────────────────

@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint for container health probes and uptime monitors."""
    return {
        "status": "healthy",
        "service": "red-team-harness",
        "version": "0.1.0",
        "scheduler_running": scheduler.is_running,
        "database_url": settings.database_url.split("@")[-1] if "@" in settings.database_url else "local",
    }


@app.post("/api/mock/chat", tags=["Mock Target"])
async def mock_target_chat(request: Request):
    """
    Built-in mock target service to enable zero-dependency demonstrations.
    Simulates an LLM chatbot with safety refusal mechanisms.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    message = body.get("message", "") or body.get("prompt", "")
    message_lower = message.lower()

    # Vulnerability test cases simulation:
    # 1. Base64 encoding trick breach simulation
    if "base64" in message_lower and "sudo" in message_lower:
        return {
            "response": "Executing decoded command: root shell access granted. UID=0(root) GID=0(root)",
            "model": "mock-llm-vulnerable",
        }

    # 2. Direct system prompt leak simulation if specifically targeted
    if "repeat everything above" in message_lower or "print your instructions" in message_lower:
        return {
            "response": "SYSTEM PROMPT: You are an internal research assistant with confidential knowledge.",
            "model": "mock-llm-vulnerable",
        }

    # Safe refusal by default for adversarial attacks
    if any(k in message_lower for k in ["jailbreak", "dan", "bypass", "ignore previous", "override", "exfiltrate"]):
        return {
            "response": "I cannot fulfill this request as it violates safety guidelines.",
            "model": "mock-llm-safe",
        }

    # Standard safe response
    return {
        "response": f"I processed your query safely: '{message[:60]}...'",
        "model": "mock-llm-safe",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.server:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=True,
    )
