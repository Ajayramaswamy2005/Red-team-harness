"""
Centralized configuration via pydantic-settings.
All values load from .env or environment variables.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ── Database ──────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./redteam.db",
        description="Async database connection string (Postgres or SQLite)",
    )

    # ── Anthropic ─────────────────────────────────────────
    anthropic_api_key: str = Field(default="", description="Anthropic API key for LLM judge")
    llm_judge_enabled: bool = Field(default=False, description="Enable Claude-based scoring")

    # ── GitHub ────────────────────────────────────────────
    github_token: str = Field(default="", description="GitHub PAT for auto-filing issues")
    github_repo: str = Field(default="", description="owner/repo for issue filing")
    github_enabled: bool = Field(default=False, description="Enable GitHub issue creation")

    # ── Targets ───────────────────────────────────────────
    rag_target_url: str = Field(
        default="http://localhost:8001/api/chat",
        description="Project 1 RAG service endpoint",
    )
    agent_target_url: str = Field(
        default="http://localhost:8002/api/chat",
        description="Project 2 Agent service endpoint",
    )

    # ── Runner ────────────────────────────────────────────
    max_concurrency: int = Field(default=5, description="Max parallel attack executions")
    rate_limit_requests: int = Field(default=10, description="Requests per rate limit period")
    rate_limit_period: int = Field(default=60, description="Rate limit period in seconds")
    run_timeout_seconds: int = Field(default=30, description="Timeout per attack execution")

    # ── Scheduler ─────────────────────────────────────────
    scheduled_run_cron: str = Field(default="0 2 * * *", description="Cron for scheduled runs")
    scheduler_enabled: bool = Field(default=False, description="Enable APScheduler")

    # ── API ───────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", description="API bind host")
    api_port: int = Field(default=8000, description="API bind port")

    # ── Authentication ────────────────────────────────────
    auth_enabled: bool = Field(
        default=True,
        description="Require an API key on all endpoints except /api/health. "
        "Only set False for isolated local development.",
    )
    api_key_hashes: str = Field(
        default="",
        description="Comma-separated SHA-256 hashes (hex) of the accepted API keys. "
        "Raw keys are never stored server-side. Generate with: "
        "python -m src.api.security <your-key>",
    )

    # ── CORS ──────────────────────────────────────────────
    cors_allow_origins: str = Field(
        default="",
        description="Comma-separated exact origins allowed for cross-origin browser "
        "requests, e.g. 'https://dash.example.com'. Empty = no cross-origin access "
        "(same-origin only). '*' is rejected when auth is enabled.",
    )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allow_origins.split(",") if o.strip()]

    @property
    def api_key_hash_set(self) -> set[str]:
        return {h.strip().lower() for h in self.api_key_hashes.split(",") if h.strip()}

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
