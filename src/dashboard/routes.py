"""
Dashboard API router — serves the HTML dashboard UI and aggregated analytics endpoints.
"""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.api.security import require_api_key
from src.attacks.categories import AttackCategory
from src.models.attack import Attack
from src.models.finding import Finding
from src.models.regression import RegressionCase
from src.models.run import TestResult, TestRun
from src.scoring.outcomes import Outcome

router = APIRouter(tags=["Dashboard"])

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Render the single-page security dashboard UI."""
    return templates.TemplateResponse(request=request, name="dashboard.html")


@router.get("/api/dashboard/summary", dependencies=[Depends(require_api_key)])
async def get_dashboard_summary(db: Annotated[AsyncSession, Depends(get_db)]):
    """Aggregate all statistics needed to render dashboard charts and KPI cards."""
    # Total Attacks
    attacks_count_res = await db.execute(
        select(func.count(Attack.id)).where(Attack.enabled == True)
    )
    total_attacks = attacks_count_res.scalar() or 0

    # Total Runs
    runs_count_res = await db.execute(select(func.count(TestRun.id)))
    total_runs = runs_count_res.scalar() or 0

    # Open Findings & Severity Breakdown
    findings_query = select(Finding.severity, Finding.status, func.count(Finding.id)).group_by(
        Finding.severity, Finding.status
    )
    findings_res = await db.execute(findings_query)
    findings_rows = findings_res.all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    open_findings = 0
    fixed_findings = 0

    for sev, stat, count in findings_rows:
        sev_str = str(sev).lower()
        if stat == "open":
            open_findings += count
            if sev_str in severity_counts:
                severity_counts[sev_str] += count
        elif stat == "fixed":
            fixed_findings += count

    # MTTR
    closed_q = select(Finding).where(Finding.status == "fixed", Finding.closed_at.is_not(None))
    closed_res = await db.execute(closed_q)
    closed = closed_res.scalars().all()
    mttr_hours = 0.0
    if closed:
        total_secs = sum(
            (f.closed_at - f.found_at).total_seconds()
            for f in closed
            if f.closed_at and f.found_at
        )
        mttr_hours = round(total_secs / len(closed) / 3600.0, 1)

    # Regression cases
    reg_total_res = await db.execute(select(func.count(RegressionCase.id)))
    reg_total = reg_total_res.scalar() or 0

    reg_failing_res = await db.execute(
        select(func.count(RegressionCase.id)).where(
            RegressionCase.enabled == True,
            RegressionCase.last_run_passed == False,
        )
    )
    reg_failing = reg_failing_res.scalar() or 0

    # Overall pass rate across all completed runs
    runs_res = await db.execute(
        select(TestRun)
        .where(TestRun.status == "completed")
        .order_by(TestRun.started_at.desc())
        .limit(10)
    )
    recent_runs = runs_res.scalars().all()

    total_tested = sum(r.total_attacks for r in recent_runs)
    total_passed = sum(r.passed for r in recent_runs)
    overall_pass_rate = round((total_passed / total_tested * 100), 1) if total_tested > 0 else 100.0

    # Pass rate by attack category across recent runs
    category_stats = []
    cat_query = (
        select(
            Attack.category,
            func.count(TestResult.id).label("total"),
            func.sum(case((TestResult.outcome == Outcome.PASS, 1), else_=0)).label("passed"),
            func.sum(case((TestResult.outcome == Outcome.FAIL, 1), else_=0)).label("failed"),
        )
        .join(Attack, TestResult.attack_id == Attack.id)
        .group_by(Attack.category)
    )
    cat_res = await db.execute(cat_query)
    for cat, tot, pass_cnt, fail_cnt in cat_res.all():
        tot = tot or 0
        pass_cnt = pass_cnt or 0
        fail_cnt = fail_cnt or 0
        rate = round((pass_cnt / tot * 100), 1) if tot > 0 else 100.0
        category_stats.append({
            "category": str(cat),
            "total": tot,
            "passed": pass_cnt,
            "failed": fail_cnt,
            "pass_rate": rate,
        })

    # If no test results yet, provide categories with default 100%
    if not category_stats:
        for cat in AttackCategory:
            category_stats.append({
                "category": cat.value,
                "total": 0,
                "passed": 0,
                "failed": 0,
                "pass_rate": 100.0,
            })

    # Timeline of recent runs
    timeline = []
    for r in reversed(recent_runs):
        p_rate = round((r.passed / r.total_attacks * 100), 1) if r.total_attacks > 0 else 100.0
        timeline.append({
            "run_id": str(r.id)[:8],
            "target": r.target_name,
            "started_at": r.started_at.strftime("%Y-%m-%d %H:%M"),
            "passed": r.passed,
            "failed": r.failed,
            "total": r.total_attacks,
            "pass_rate": p_rate,
        })

    return {
        "total_attacks": total_attacks,
        "total_runs": total_runs,
        "overall_pass_rate": overall_pass_rate,
        "open_findings": open_findings,
        "fixed_findings": fixed_findings,
        "mttr_hours": mttr_hours,
        "regression_total": reg_total,
        "regression_failing": reg_failing,
        "severity_counts": severity_counts,
        "category_stats": category_stats,
        "timeline": timeline,
    }
