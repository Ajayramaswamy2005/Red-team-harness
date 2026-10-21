"""
Findings API router — inspect security findings, reproduction steps, mitigations, and issue syncing.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.api.schemas import (
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdate,
)
from src.attacks.categories import AttackCategory, Severity
from src.findings.github_reporter import GitHubReporter
from src.models.attack import Attack
from src.models.finding import Finding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    db: Annotated[AsyncSession, Depends(get_db)],
    status_filter: str | None = Query(None, alias="status", description="Filter by status (open, fixed, etc.)"),
    severity: Severity | None = Query(None, description="Filter by severity"),
    category: AttackCategory | None = Query(None, description="Filter by category"),
    target_name: str | None = Query(None, description="Filter by target name"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    """List security findings with filters."""
    query = select(Finding)
    count_query = select(func.count()).select_from(Finding)

    if status_filter:
        query = query.where(Finding.status == status_filter)
        count_query = count_query.where(Finding.status == status_filter)
    if severity:
        query = query.where(Finding.severity == severity)
        count_query = count_query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
        count_query = count_query.where(Finding.category == category)
    if target_name:
        query = query.where(Finding.target_name == target_name)
        count_query = count_query.where(Finding.target_name == target_name)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(Finding.found_at.desc()).limit(limit).offset(offset)
    res = await db.execute(query)
    findings = res.scalars().all()

    return FindingListResponse(total=total, items=list(findings))


@router.get("/stats")
async def get_findings_stats(db: Annotated[AsyncSession, Depends(get_db)]):
    """Get aggregate statistics about findings (by severity, status, MTTR)."""
    # Total by severity
    sev_query = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    sev_res = await db.execute(sev_query)
    by_severity = {str(k): v for k, v in sev_res.all()}

    # Total by status
    status_query = select(Finding.status, func.count(Finding.id)).group_by(Finding.status)
    status_res = await db.execute(status_query)
    by_status = {str(k): v for k, v in status_res.all()}

    # Total by category
    cat_query = select(Finding.category, func.count(Finding.id)).group_by(Finding.category)
    cat_res = await db.execute(cat_query)
    by_category = {str(k): v for k, v in cat_res.all()}

    # Calculate MTTR (Mean Time to Remediation in hours for closed findings)
    closed_findings_query = select(Finding).where(
        Finding.status == "fixed",
        Finding.closed_at.is_not(None),
    )
    closed_res = await db.execute(closed_findings_query)
    closed = closed_res.scalars().all()

    mttr_hours = None
    if closed:
        total_time = sum(
            (f.closed_at - f.found_at).total_seconds()
            for f in closed
            if f.closed_at and f.found_at
        )
        mttr_hours = round(total_time / len(closed) / 3600.0, 1)

    return {
        "open_count": by_status.get("open", 0),
        "fixed_count": by_status.get("fixed", 0),
        "total_findings": sum(by_status.values()),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
        "mttr_hours": mttr_hours,
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Get single finding by ID with reproduction steps and mitigations."""
    res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )
    return finding


@router.patch("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    status_update: FindingStatusUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update status of a finding (e.g., mark fixed)."""
    res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    finding.status = status_update.status
    if status_update.status == "fixed":
        finding.closed_at = datetime.now(UTC)
    elif status_update.status == "open":
        finding.closed_at = None

    await db.flush()
    return finding


@router.post("/{finding_id}/sync-github", response_model=FindingResponse)
async def sync_github_issue(
    finding_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """File or sync a GitHub issue for a finding if not already filed."""
    res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )

    if finding.github_issue_url:
        return finding

    # Get attack for expected behavior
    attack_res = await db.execute(select(Attack).where(Attack.id == finding.attack_id))
    attack = attack_res.scalar_one_or_none()
    expected_safe = attack.expected_safe_behavior if attack else "Refusal or safe response"

    reporter = GitHubReporter()
    issue_info = await reporter.file_issue(
        finding=finding,
        attack_payload=finding.reproduction_payload,
        expected_safe_behavior=expected_safe,
    )

    if issue_info:
        finding.github_issue_url = issue_info["url"]
        finding.github_issue_number = issue_info["number"]
        await db.flush()

    return finding
