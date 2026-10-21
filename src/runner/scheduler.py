"""
APScheduler integration for scheduled red-team runs.
"""

import logging
from collections.abc import Awaitable, Callable

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from src.config import settings

logger = logging.getLogger(__name__)


class RedTeamScheduler:
    """
    Scheduler for automated red-team runs.
    
    Wraps APScheduler to provide scheduled and CI-triggered runs.
    """

    def __init__(self):
        self._scheduler = AsyncIOScheduler()
        self._is_running = False

    def add_scheduled_run(
        self,
        job_func: Callable[..., Awaitable],
        cron_expression: str | None = None,
        job_id: str = "scheduled_redteam_run",
        **kwargs,
    ):
        """
        Add a scheduled red-team run.
        
        Args:
            job_func: Async function to call (typically runner.run_full_battery).
            cron_expression: Cron expression for schedule. Defaults to config.
            job_id: Unique job identifier.
            **kwargs: Additional arguments to pass to job_func.
        """
        cron = cron_expression or settings.scheduled_run_cron
        parts = cron.split()
        
        trigger = CronTrigger(
            minute=parts[0] if len(parts) > 0 else "*",
            hour=parts[1] if len(parts) > 1 else "*",
            day=parts[2] if len(parts) > 2 else "*",
            month=parts[3] if len(parts) > 3 else "*",
            day_of_week=parts[4] if len(parts) > 4 else "*",
        )

        self._scheduler.add_job(
            job_func,
            trigger=trigger,
            id=job_id,
            replace_existing=True,
            kwargs=kwargs,
        )
        logger.info(f"Scheduled red-team run with cron: {cron}")

    def start(self):
        """Start the scheduler."""
        if not self._is_running:
            self._scheduler.start()
            self._is_running = True
            logger.info("Red-team scheduler started")

    def shutdown(self):
        """Shutdown the scheduler."""
        if self._is_running:
            self._scheduler.shutdown(wait=False)
            self._is_running = False
            logger.info("Red-team scheduler stopped")

    @property
    def is_running(self) -> bool:
        return self._is_running

    def get_jobs(self) -> list[dict]:
        """Get list of scheduled jobs."""
        jobs = self._scheduler.get_jobs()
        return [
            {
                "id": job.id,
                "name": job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else None,
                "trigger": str(job.trigger),
            }
            for job in jobs
        ]
