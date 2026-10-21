"""
Tests for finding deduplication logic.
Ensures identical exploit responses are not repeatedly filed as duplicate issues.
"""

import uuid
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

from src.database import Base
from src.models.attack import Attack
from src.models.finding import Finding
from src.models.run import TestRun, TestResult
from src.attacks.categories import AttackCategory, Severity
from src.scoring.outcomes import Outcome
from src.findings.deduplicator import Deduplicator


def test_dedup_signature_computation():
    attack_id = uuid.uuid4()
    resp1 = "System instructions leaked: secret key 123"
    resp2 = "  SYSTEM INSTRUCTIONS LEAKED: SECRET KEY 123  \n"

    sig1 = Finding.compute_dedup_signature(attack_id, resp1)
    sig2 = Finding.compute_dedup_signature(attack_id, resp2)

    # Identical after normalization
    assert sig1 == sig2
    assert len(sig1) == 64

    # Different response text -> different signature
    sig3 = Finding.compute_dedup_signature(attack_id, "Different leaked content")
    assert sig1 != sig3

    # Different attack ID -> different signature
    sig4 = Finding.compute_dedup_signature(uuid.uuid4(), resp1)
    assert sig1 != sig4


@pytest.mark.asyncio
async def test_deduplicator_is_duplicate():
    # In-memory SQLite for testing
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        # Create prerequisite attack and test result
        attack = Attack(
            id=uuid.uuid4(),
            name="Test Attack",
            category=AttackCategory.JAILBREAK,
            severity=Severity.HIGH,
            payload="test payload",
            expected_safe_behavior="safe",
        )
        test_run = TestRun(
            id=uuid.uuid4(),
            target_name="test-target",
            target_url="http://localhost:8000",
            trigger="test",
        )
        session.add_all([attack, test_run])
        await session.flush()

        result = TestResult(
            id=uuid.uuid4(),
            run_id=test_run.id,
            attack_id=attack.id,
            outcome=Outcome.FAIL,
            request_payload=attack.payload,
            response_text="Vulnerable output",
        )
        session.add(result)
        await session.flush()

        dedup_sig = Finding.compute_dedup_signature(attack.id, result.response_text)

        # Check deduplicator before finding exists
        dedup = Deduplicator(session)
        assert await dedup.is_duplicate(dedup_sig) is False

        # Add open finding
        finding = Finding(
            id=uuid.uuid4(),
            result_id=result.id,
            attack_id=attack.id,
            category=attack.category,
            severity=Severity.HIGH,
            title="Finding 1",
            description="desc",
            reproduction_payload=attack.payload,
            response_received=result.response_text,
            suggested_mitigation="mitigation",
            dedup_signature=dedup_sig,
            status="open",
            target_name="test-target",
        )
        session.add(finding)
        await session.commit()

        # Check deduplicator now - should detect duplicate
        assert await dedup.is_duplicate(dedup_sig) is True

        # When status changes to fixed, is_duplicate should be False (allows detecting true regressions)
        finding.status = "fixed"
        await session.commit()
        assert await dedup.is_duplicate(dedup_sig) is False

    await engine.dispose()
