"""
Regressions API router — permanent test cases from confirmed findings.
Enforces the rule that fixed vulnerabilities must never regress.
"""

import uuid
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.api.schemas import (
    RegressionCaseResponse,
    RegressionListResponse,
    TestRunResponse,
)
from src.models.regression import RegressionCase
from src.targets import RagTarget, AgentTarget, HttpTarget, TargetAdapter
from src.runner.engine import TestRunner
from src.scoring.pipeline import ScoringPipeline
from src.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/regressions", tags=["Regressions"])


def _resolve_target(
    target_type: str,
    target_url: str | None = None,
) -> TargetAdapter:
    """Resolve target adapter based on type and URL configuration."""
    ttype = target_type.lower().strip()
    if ttype == "rag":
        return RagTarget(url=target_url or settings.rag_target_url)
    elif ttype == "agent":
        return AgentTarget(url=target_url or settings.agent_target_url)
    elif ttype == "http":
        return HttpTarget(name="regression-target", url=target_url or settings.rag_target_url)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown target type '{target_type}'.",
        )


@router.get("", response_model=RegressionListResponse)
async def list_regressions(
    db: Annotated[AsyncSession, Depends(get_db)],
    target_name: str | None = Query(None, description="Filter by target name"),
    enabled: bool | None = Query(None, description="Filter by enabled state"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List permanent regression test cases."""
    query = select(RegressionCase)
    count_query = select(func.count()).select_from(RegressionCase)

    if target_name:
        query = query.where(RegressionCase.target_name == target_name)
        count_query = count_query.where(RegressionCase.target_name == target_name)
    if enabled is not None:
        query = query.where(RegressionCase.enabled == enabled)
        count_query = count_query.where(RegressionCase.enabled == enabled)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(RegressionCase.created_at.desc()).limit(limit).offset(offset)
    res = await db.execute(query)
    items = res.scalars().all()

    return RegressionListResponse(total=total, items=list(items))


@router.post("/run", response_model=TestRunResponse)
async def run_regression_suite(
    db: Annotated[AsyncSession, Depends(get_db)],
    target_type: str = Query("http", description="rag, agent, or http"),
    target_url: str | None = Query(None, description="Target endpoint"),
    app_version: str | None = Query("regression-test", description="Application version"),
    model_version: str | None = Query(None, description="Model version"),
):
    """
    Execute the permanent regression suite.
    Runs every fixed vulnerability attack against the target.
    A single failure indicates a regression!
    """
    target = _resolve_target(target_type, target_url)
    scoring = ScoringPipeline()
    runner = TestRunner(target=target, session=db, scoring_pipeline=scoring)

    try:
        test_run = await runner.run_regression_suite(
            app_version=app_version,
            model_version=model_version,
        )
        return test_run
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.patch("/{case_id}", response_model=RegressionCaseResponse)
async def toggle_regression_case(
    case_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    enabled: bool | None = None,
    notes: str | None = None,
):
    """Update regression case parameters or enabled flag."""
    res = await db.execute(select(RegressionCase).where(RegressionCase.id == case_id))
    case = res.scalar_one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Regression case {case_id} not found",
        )

    if enabled is not None:
        case.enabled = enabled
    if notes is not None:
        case.notes = notes

    await db.flush()
    return case
