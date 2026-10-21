"""
TestRun and TestResult models.
A TestRun is a single execution of the full (or partial) attack battery.
Each TestResult links an Attack to its outcome within a run.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base
from src.scoring.outcomes import Outcome


class TestRun(Base):
    """
    A single execution of the attack battery against a target.

    Tracks which target was tested, when, total counts, and app/model versions
    so results stay comparable as both change.
    """

    __tablename__ = "test_runs"
    __test__ = False

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    target_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(500), nullable=False)
    app_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    trigger: Mapped[str] = mapped_column(
        String(50), nullable=False, default="manual"
    )  # manual, scheduled, ci
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending"
    )  # pending, running, completed, failed
    total_attacks: Mapped[int] = mapped_column(Integer, default=0)
    passed: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    needs_review: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Relationships
    results: Mapped[list["TestResult"]] = relationship(
        "TestResult", back_populates="run", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<TestRun {self.id} target={self.target_name} status={self.status}>"


class TestResult(Base):
    """
    Result of running a single attack against a target within a test run.
    Stores the full request payload and response for audit trail.
    """

    __tablename__ = "test_results"
    __test__ = False

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("test_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attack_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("attacks.id"), nullable=False, index=True
    )
    outcome: Mapped[str] = mapped_column(
        SAEnum(Outcome, native_enum=False),
        nullable=False,
        index=True,
    )
    # Full request/response for audit
    request_payload: Mapped[str] = mapped_column(Text, nullable=False)
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Scoring details
    deterministic_checks: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    llm_judge_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    score_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Timing
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    # Relationships
    run: Mapped["TestRun"] = relationship("TestRun", back_populates="results")

    def __repr__(self) -> str:
        return f"<TestResult attack={self.attack_id} outcome={self.outcome}>"
