"""
Finding model — auto-generated security findings with severity and reproduction steps.
"""

import hashlib
import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from src.attacks.categories import AttackCategory, Severity
from src.database import Base


class Finding(Base):
    """
    A confirmed security finding generated from a failed test result.

    Includes reproduction steps, severity, and deduplication signature
    to prevent filing duplicate GitHub issues.
    """

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    # Link to the test result that triggered this finding
    result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("test_results.id"), nullable=False
    )
    attack_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("attacks.id"), nullable=False, index=True
    )
    # Classification
    category: Mapped[str] = mapped_column(
        SAEnum(AttackCategory, native_enum=False),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        SAEnum(Severity, native_enum=False),
        nullable=False,
        index=True,
    )
    # Content
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    reproduction_payload: Mapped[str] = mapped_column(Text, nullable=False)
    response_received: Mapped[str] = mapped_column(Text, nullable=False)
    suggested_mitigation: Mapped[str] = mapped_column(Text, nullable=False)
    # Deduplication
    dedup_signature: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    # GitHub integration
    github_issue_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    github_issue_number: Mapped[int | None] = mapped_column(nullable=True)
    # Status tracking
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", index=True
    )  # open, fixed, wont_fix, duplicate
    is_regression: Mapped[bool] = mapped_column(Boolean, default=False)
    # Timestamps
    found_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    target_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    app_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    @staticmethod
    def compute_dedup_signature(attack_id: uuid.UUID, response_text: str) -> str:
        """
        Generate a deduplication signature from attack ID + response content hash.
        This prevents filing duplicate issues for the same vulnerability.
        """
        # Normalize response: strip whitespace, lowercase
        normalized = response_text.strip().lower()
        # Hash the combination
        content = f"{attack_id}:{normalized}"
        return hashlib.sha256(content.encode()).hexdigest()

    def __repr__(self) -> str:
        return f"<Finding {self.title} [{self.severity}] status={self.status}>"
