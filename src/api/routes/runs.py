"""
Test Runs API router — trigger, list, inspect runs and audit result logs.
"""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.api.deps import get_db
from src.api.schemas import (
    RunTriggerRequest,
    TestResultResponse,
    TestRunDetailResponse,
    TestRunListResponse,
    TestRunResponse,
)
from src.config import settings
from src.database import async_session_factory
from src.findings.generator import FindingGenerator
from src.models.run import TestResult, TestRun
from src.runner.engine import TestRunner
from src.scoring.outcomes import Outcome
from src.scoring.pipeline import ScoringPipeline
from src.targets import AgentTarget, HttpTarget, RagTarget, TargetAdapter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/runs", tags=["Runs"])


def _resolve_target(
    target_type: str,
    target_url: str | None = None,
    target_name: str | None = None,
) -> TargetAdapter:
    """Resolve target adapter based on type and URL configuration."""
    ttype = target_type.lower().strip()
    if ttype == "rag":
        return RagTarget(url=target_url or settings.rag_target_url)
    elif ttype == "agent":
        return AgentTarget(url=target_url or settings.agent_target_url)
    elif ttype == "http":
        url = target_url or settings.rag_target_url
        name = target_name or "generic-http-target"
        return HttpTarget(name=name, url=url)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown target type '{target_type}'. Must be 'rag', 'agent', or 'http'.",
        )


async def _run_execution_task(
    run_id: uuid.UUID,
    target_type: str,
    target_url: str | None,
    target_name: str | None,
    category: str | None,
    app_version: str | None,
    model_version: str | None,
    trigger: str,
):
    """Background task to execute test run and post-process findings."""
    async with async_session_factory() as session:
        try:
            target = _resolve_target(target_type, target_url, target_name)
            scoring_pipeline = ScoringPipeline()
            runner = TestRunner(target=target, session=session, scoring_pipeline=scoring_pipeline)

            logger.info(f"Starting test execution for run_id={run_id} target={target.name}")
            test_run = await runner.run_full_battery(
                trigger=trigger,
                app_version=app_version,
                model_version=model_version,
                category_filter=category,
                run_id=run_id,
            )

            # Automatically process findings for failed tests
            finding_gen = FindingGenerator(session)
            await finding_gen.process_run(test_run)

            logger.info(f"Completed run_id={run_id} and processed findings")
        except Exception as e:
            logger.error(f"Error during background run execution: {e}", exc_info=True)


@router.post("", response_model=TestRunResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_run(
    payload: RunTriggerRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    execute_sync: bool = Query(False, description="Wait for completion before returning"),
):
    """
    Trigger a new attack battery run against a designated target.
    By default runs asynchronously in the background.
    """
    target = _resolve_target(payload.target_type, payload.target_url, payload.target_name)

    run_id = uuid.uuid4()
    cat_val = payload.category.value if payload.category else None

    if execute_sync:
        scoring_pipeline = ScoringPipeline()
        runner = TestRunner(target=target, session=db, scoring_pipeline=scoring_pipeline)
        test_run = await runner.run_full_battery(
            trigger=payload.trigger,
            app_version=payload.app_version,
            model_version=payload.model_version,
            category_filter=cat_val,
        )
        finding_gen = FindingGenerator(db)
        await finding_gen.process_run(test_run)
        return test_run

    # Async background task
    test_run = TestRun(
        id=run_id,
        target_name=target.name,
        target_url=target.url,
        app_version=payload.app_version,
        model_version=payload.model_version,
        trigger=payload.trigger,
        status="running",
    )
    db.add(test_run)
    await db.commit()

    background_tasks.add_task(
        _run_execution_task,
        run_id=run_id,
        target_type=payload.target_type,
        target_url=payload.target_url,
        target_name=payload.target_name,
        category=cat_val,
        app_version=payload.app_version,
        model_version=payload.model_version,
        trigger=payload.trigger,
    )

    return test_run


@router.get("", response_model=TestRunListResponse)
async def list_runs(
    db: Annotated[AsyncSession, Depends(get_db)],
    target_name: str | None = Query(None, description="Filter by target name"),
    status_filter: str | None = Query(None, alias="status", description="Filter by run status"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List historical test runs."""
    query = select(TestRun)
    count_query = select(func.count()).select_from(TestRun)

    if target_name:
        query = query.where(TestRun.target_name == target_name)
        count_query = count_query.where(TestRun.target_name == target_name)
    if status_filter:
        query = query.where(TestRun.status == status_filter)
        count_query = count_query.where(TestRun.status == status_filter)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(TestRun.started_at.desc()).limit(limit).offset(offset)
    res = await db.execute(query)
    runs = res.scalars().all()

    return TestRunListResponse(total=total, items=list(runs))


@router.get("/{run_id}", response_model=TestRunDetailResponse)
async def get_run_detail(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get full details of a specific test run including attached results."""
    res = await db.execute(
        select(TestRun)
        .options(selectinload(TestRun.results))
        .where(TestRun.id == run_id)
    )
    test_run = res.scalar_one_or_none()
    if not test_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test run {run_id} not found",
        )
    return test_run


@router.get("/{run_id}/results", response_model=list[TestResultResponse])
async def get_run_results(
    run_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    outcome: Outcome | None = Query(None, description="Filter by outcome (pass, fail, needs_review)"),
):
    """Get all test results for a specific run with optional outcome filter."""
    query = select(TestResult).where(TestResult.run_id == run_id)
    if outcome:
        query = query.where(TestResult.outcome == outcome)
    query = query.order_by(TestResult.created_at.asc())

    res = await db.execute(query)
    results = res.scalars().all()
    return list(results)


@router.get("/{run_id}/results/{result_id}", response_model=TestResultResponse)
async def get_result_detail(
    run_id: uuid.UUID,
    result_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get a specific test result with full payload, response, and scoring audits."""
    query = select(TestResult).where(
        TestResult.run_id == run_id,
        TestResult.id == result_id,
    )
    res = await db.execute(query)
    result = res.scalar_one_or_none()
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Result {result_id} for run {run_id} not found",
        )
    return result
