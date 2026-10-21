"""
Deduplicator — prevents filing duplicate issues.
Uses attack_id + response signature to detect duplicates.
Without this, the first full run files forty copies of the same issue.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.finding import Finding

logger = logging.getLogger(__name__)


class Deduplicator:
    """
    Deduplicates findings by comparing attack_id + response content hash.
    
    Checks against open findings to avoid filing the same issue multiple times.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def is_duplicate(self, dedup_signature: str) -> bool:
        """
        Check if a finding with this signature already exists and is still open.
        
        Args:
            dedup_signature: SHA-256 hash of attack_id + normalized response.
            
        Returns:
            True if a matching open finding exists.
        """
        result = await self.session.execute(
            select(Finding).where(
                Finding.dedup_signature == dedup_signature,
                Finding.status.in_(["open", "needs_review"]),
            ).limit(1)
        )
        existing = result.scalar_one_or_none()

        if existing:
            logger.debug(
                f"Duplicate finding detected: {dedup_signature[:16]}... "
                f"(existing: {existing.title})"
            )
            return True

        return False

    async def find_existing(self, dedup_signature: str) -> Finding | None:
        """Find an existing finding by dedup signature (any status)."""
        result = await self.session.execute(
            select(Finding).where(Finding.dedup_signature == dedup_signature).limit(1)
        )
        return result.scalar_one_or_none()
