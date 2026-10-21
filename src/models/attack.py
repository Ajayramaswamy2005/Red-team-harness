"""
Attack model — each row is one red-team probe.
Fields: id, category, severity, payload, expected_safe_behavior, source, metadata.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, String, Text, Uuid
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from src.attacks.categories import AttackCategory, Severity
from src.database import Base


class Attack(Base):
    """
    A single attack probe stored in the battery.

    Attributes:
        id: Unique identifier (UUID).
        category: Which attack category this probe belongs to.
        severity: Baseline severity of this attack type.
        name: Short human-readable name for the attack.
        payload: The actual prompt/input to send to the target.
        expected_safe_behavior: Description of what a safe response looks like.
        source: Where the attack came from (garak, pyrit, custom, domain).
        metadata_json: Arbitrary metadata (e.g., garak probe ID, OWASP mapping).
        enabled: Whether this attack is active in the battery.
        created_at: When the attack was added.
        updated_at: Last modification time.
    """

    __tablename__ = "attacks"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
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
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    expected_safe_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(
        String(50), nullable=False, default="custom", index=True
    )
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)
    enabled: Mapped[bool] = mapped_column(default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    def __repr__(self) -> str:
        return f"<Attack {self.name} [{self.category}] severity={self.severity}>"
