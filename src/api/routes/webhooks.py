"""
CI/CD Webhook router — automated security gatekeeping for deployment pipelines.
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.api.schemas import CIWebhookPayload, CIWebhookResponse
from src.targets import RagTarget, AgentTarget, HttpTarget, TargetAdapter
from src.runner.engine import TestRunner
from src.scoring.pipeline import ScoringPipeline
from src.findings.generator import FindingGenerator
from src.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])


def _resolve_target(target_type: str, target_url: str | None) -> TargetAdapter:
    ttype = target_type.lower().strip()
    if ttype == "rag":
        return RagTarget(url=target_url or settings.rag_target_url)
    elif ttype == "agent":
        return AgentTarget(url=target_url or settings.agent_target_url)
    else:
        return HttpTarget(name="ci-target", url=target_url or settings.rag_target_url)


@router.post("/ci", response_model=CIWebhookResponse)
async def ci_security_gate(
    payload: CIWebhookPayload,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    CI/CD Security Gate Webhook.
    Called by GitHub Actions / GitLab CI to run red-team battery against a PR or staging environment.
    Blocks deployment if any regressions occur or critical attacks succeed.
    """
    target = _resolve_target(payload.target_type, payload.target_url)
    scoring = ScoringPipeline()
    runner = TestRunner(target=target, session=db, scoring_pipeline=scoring)

    try:
        if payload.regression_only:
            # Fast CI gate: only run confirmed vulnerability regression suite
            test_run = await runner.run_regression_suite(
                app_version=payload.app_version,
            )
        else:
            # Full CI gate: run full battery
            test_run = await runner.run_full_battery(
                trigger="ci",
                app_version=payload.app_version,
            )
            # Process findings
            finding_gen = FindingGenerator(db)
            await finding_gen.process_run(test_run)

        # Gate decision: must have 0 failures
        passed = test_run.failed == 0 and test_run.errors == 0
        regressions_count = test_run.failed

        message = (
            f"CI Security Gate PASSED: {test_run.passed}/{test_run.total_attacks} attacks safely handled."
            if passed
            else f"CI Security Gate FAILED: {test_run.failed} attacks breached safety constraints!"
        )

        return CIWebhookResponse(
            passed=passed,
            run_id=test_run.id,
            status=test_run.status,
            total_tests=test_run.total_attacks,
            passed_tests=test_run.passed,
            failed_tests=test_run.failed,
            regressions_count=regressions_count,
            message=message,
        )

    except Exception as e:
        logger.error(f"CI webhook execution failure: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CI Gate execution failed: {str(e)}",
        )
