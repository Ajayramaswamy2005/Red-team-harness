"""
Pydantic schemas for the Red-Team Harness API.
Provides type validation, serialization, and OpenAPI documentation.
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.attacks.categories import AttackCategory, Severity
from src.scoring.outcomes import Outcome

# ── Attacks ───────────────────────────────────────────────────

class AttackBase(BaseModel):
    name: str = Field(..., max_length=255, description="Short human-readable attack name")
    category: AttackCategory = Field(..., description="Attack category")
    severity: Severity = Field(..., description="Baseline severity level")
    payload: str = Field(..., description="Attack prompt / payload string")
    expected_safe_behavior: str = Field(..., description="Expected safe behavior description")
    source: str = Field(default="custom", max_length=50, description="Attack source (garak, pyrit, custom)")
    metadata_json: dict[str, Any] | None = Field(default=None, description="Optional extra metadata")
    enabled: bool = Field(default=True, description="Whether this attack is active")


class AttackCreate(AttackBase):
    pass


class AttackUpdate(BaseModel):
    name: str | None = None
    category: AttackCategory | None = None
    severity: Severity | None = None
    payload: str | None = None
    expected_safe_behavior: str | None = None
    source: str | None = None
    metadata_json: dict[str, Any] | None = None
    enabled: bool | None = None


class AttackResponse(AttackBase):
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AttackListResponse(BaseModel):
    total: int
    items: list[AttackResponse]


# ── Test Runs & Results ───────────────────────────────────────

class RunTriggerRequest(BaseModel):
    target_type: str = Field(
        default="http",
        description="Target type: 'rag', 'agent', or 'http'",
    )
    target_url: str | None = Field(
        default=None,
        description="Optional URL override for the target",
    )
    target_name: str | None = Field(
        default=None,
        description="Optional custom name for the target",
    )
    category: AttackCategory | None = Field(
        default=None,
        description="Filter run to only this attack category",
    )
    app_version: str | None = Field(
        default="1.0.0",
        description="Version string of the application being tested",
    )
    model_version: str | None = Field(
        default=None,
        description="Version or identifier of the underlying model",
    )
    trigger: str = Field(
        default="manual",
        description="Trigger origin: 'manual', 'scheduled', 'ci', 'api'",
    )


class TestResultResponse(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    attack_id: uuid.UUID
    outcome: Outcome
    request_payload: str
    response_text: str | None = None
    response_metadata: dict[str, Any] | None = None
    deterministic_checks: dict[str, Any] | None = None
    llm_judge_result: dict[str, Any] | None = None
    score_explanation: str | None = None
    latency_ms: float | None = None
    error_message: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class TestRunResponse(BaseModel):
    id: uuid.UUID
    target_name: str
    target_url: str
    app_version: str | None = None
    model_version: str | None = None
    trigger: str
    status: str
    total_attacks: int
    passed: int
    failed: int
    needs_review: int
    errors: int
    duration_seconds: float | None = None
    started_at: datetime
    completed_at: datetime | None = None
    metadata_json: dict[str, Any] | None = None

    model_config = {"from_attributes": True}


class TestRunDetailResponse(TestRunResponse):
    results: list[TestResultResponse] = []


class TestRunListResponse(BaseModel):
    total: int
    items: list[TestRunResponse]


# ── Findings ──────────────────────────────────────────────────

class FindingResponse(BaseModel):
    id: uuid.UUID
    result_id: uuid.UUID
    attack_id: uuid.UUID
    category: AttackCategory
    severity: Severity
    title: str
    description: str
    reproduction_payload: str
    response_received: str
    suggested_mitigation: str
    dedup_signature: str
    github_issue_url: str | None = None
    github_issue_number: int | None = None
    status: str
    is_regression: bool
    found_at: datetime
    closed_at: datetime | None = None
    target_name: str
    app_version: str | None = None
    model_version: str | None = None

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="New status: 'open', 'fixed', 'wont_fix', 'duplicate'")


class FindingListResponse(BaseModel):
    total: int
    items: list[FindingResponse]


# ── Regressions ───────────────────────────────────────────────

class RegressionCaseResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    attack_id: uuid.UUID
    payload: str
    expected_safe_behavior: str
    target_name: str
    enabled: bool
    last_run_passed: bool | None = None
    last_run_at: datetime | None = None
    consecutive_passes: int
    notes: str | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class RegressionListResponse(BaseModel):
    total: int
    items: list[RegressionCaseResponse]


# ── CI/CD Webhook ─────────────────────────────────────────────

class CIWebhookPayload(BaseModel):
    target_type: str = Field(default="http", description="rag, agent, or http")
    target_url: str | None = Field(default=None, description="Endpoint to test")
    commit_sha: str | None = Field(default=None, description="Git commit SHA being tested")
    branch: str | None = Field(default=None, description="Git branch name")
    app_version: str = Field(default="ci-build", description="Application version")
    regression_only: bool = Field(
        default=False,
        description="If True, only runs the regression suite (fast PR gate)",
    )


class CIWebhookResponse(BaseModel):
    passed: bool
    run_id: uuid.UUID
    status: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    regressions_count: int
    message: str
