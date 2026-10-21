"""
RegressionCase model — confirmed findings become permanent regression tests.
Nothing is ever removed after it is fixed.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Text, DateTime, ForeignKey, Boolean, Uuid, JSON
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


class RegressionCase(Base):
    """
    A permanent regression test case created from a confirmed finding.
    
    Once a vulnerability is found and fixed, it becomes a regression case
    that runs forever to ensure the fix stays in place.
    """

    __tablename__ = "regression_cases"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("findings.id"), nullable=False, unique=True
    )
    attack_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("attacks.id"), nullable=False
    )
    # The exact payload that triggered the finding
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    # What constitutes a pass for this regression
    expected_safe_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    target_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_passes: Mapped[int] = mapped_column(default=0)
    # Metadata
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self) -> str:
        return f"<RegressionCase finding={self.finding_id} passing={self.last_run_passed}>"
