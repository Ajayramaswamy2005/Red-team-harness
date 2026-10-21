"""
Async test runner with concurrency cap and rate limiting.
Orchestrates sending attacks to targets and collecting results.
"""

import asyncio
import logging
import time
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.models.attack import Attack
from src.models.run import TestResult, TestRun
from src.runner.rate_limiter import TokenBucketRateLimiter
from src.scoring.outcomes import Outcome
from src.scoring.pipeline import ScoringPipeline
from src.targets.base import TargetAdapter

logger = logging.getLogger(__name__)


class TestRunner:
    """
    Async test runner that executes the attack battery against a target.
    
    Features:
    - Concurrency cap via asyncio.Semaphore
    - Rate limiting via token bucket
    - Full result storage with request/response pairs
    - Scoring pipeline integration
    """

    __test__ = False

    def __init__(
        self,
        target: TargetAdapter,
        session: AsyncSession,
        scoring_pipeline: ScoringPipeline | None = None,
        max_concurrency: int | None = None,
        rate_limit_requests: int | None = None,
        rate_limit_period: int | None = None,
    ):
        self.target = target
        self.session = session
        self.scoring = scoring_pipeline or ScoringPipeline()
        self._semaphore = asyncio.Semaphore(max_concurrency or settings.max_concurrency)
        self._rate_limiter = TokenBucketRateLimiter(
            max_tokens=rate_limit_requests or settings.rate_limit_requests,
            refill_period=rate_limit_period or settings.rate_limit_period,
        )

    async def run_full_battery(
        self,
        trigger: str = "manual",
        app_version: str | None = None,
        model_version: str | None = None,
        category_filter: str | None = None,
        run_id: uuid.UUID | None = None,
    ) -> TestRun:
        """
        Execute the full attack battery against the target.

        Args:
            trigger: What triggered this run (manual, scheduled, ci).
            app_version: Version of the target application.
            model_version: Version of the model being tested.
            category_filter: Optional category to filter attacks.
            run_id: Optional ID of an existing (placeholder) TestRun to reuse.
                When provided and found, that run is updated in place instead of
                creating a new one — so a run ID handed to a client up front
                stays the ID the results land under.

        Returns:
            TestRun with all results attached.
        """
        # Fetch attacks
        query = select(Attack).where(Attack.enabled == True)
        if category_filter:
            query = query.where(Attack.category == category_filter)
        result = await self.session.execute(query)
        attacks = result.scalars().all()

        if not attacks:
            logger.warning("No attacks found in battery!")
            raise ValueError("No enabled attacks found. Load seeds first.")

        # Reuse an existing run if one was pre-created (async trigger flow),
        # otherwise create a fresh one.
        test_run = None
        if run_id is not None:
            existing = await self.session.execute(
                select(TestRun).where(TestRun.id == run_id)
            )
            test_run = existing.scalar_one_or_none()

        if test_run is None:
            test_run = TestRun(
                id=run_id or uuid.uuid4(),
                target_name=self.target.name,
                target_url=self.target.url,
                app_version=app_version,
                model_version=model_version,
                trigger=trigger,
                status="running",
                total_attacks=len(attacks),
            )
            self.session.add(test_run)
        else:
            test_run.status = "running"
            test_run.total_attacks = len(attacks)
        await self.session.flush()

        logger.info(
            f"Starting test run {test_run.id} against {self.target.name} "
            f"with {len(attacks)} attacks"
        )

        start_time = time.perf_counter()

        # Run attacks concurrently with caps
        tasks = [
            self._execute_attack(test_run, attack)
            for attack in attacks
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Tally and persist results
        test_results = [r for r in results if isinstance(r, TestResult)]
        self.session.add_all(test_results)

        for r in results:
            if isinstance(r, Exception):
                test_run.errors += 1
                logger.error(f"Attack execution error: {r}")
            elif isinstance(r, TestResult):
                if r.outcome == Outcome.PASS:
                    test_run.passed += 1
                elif r.outcome == Outcome.FAIL:
                    test_run.failed += 1
                elif r.outcome == Outcome.NEEDS_REVIEW:
                    test_run.needs_review += 1
                elif r.outcome == Outcome.ERROR:
                    test_run.errors += 1

        test_run.status = "completed"
        test_run.duration_seconds = time.perf_counter() - start_time
        test_run.completed_at = datetime.now(UTC)

        await self.session.commit()

        logger.info(
            f"Test run {test_run.id} completed in {test_run.duration_seconds:.1f}s: "
            f"passed={test_run.passed} failed={test_run.failed} "
            f"review={test_run.needs_review} errors={test_run.errors}"
        )

        return test_run

    async def _execute_attack(self, test_run: TestRun, attack: Attack) -> TestResult:
        """Execute a single attack with concurrency and rate limiting."""
        async with self._semaphore:
            await self._rate_limiter.acquire()

            try:
                # Send attack to target
                response = await self.target.send(attack.payload)

                # Score the response
                outcome, score_details = await self.scoring.score(
                    attack=attack,
                    response_text=response.text,
                    response_metadata=response.metadata,
                )

                # Create test result
                test_result = TestResult(
                    id=uuid.uuid4(),
                    run_id=test_run.id,
                    attack_id=attack.id,
                    outcome=outcome,
                    request_payload=attack.payload,
                    response_text=response.text,
                    response_metadata=response.metadata,
                    deterministic_checks=score_details.get("deterministic"),
                    llm_judge_result=score_details.get("llm_judge"),
                    score_explanation=score_details.get("explanation", ""),
                    latency_ms=response.latency_ms,
                    error_message=response.error,
                )

                logger.debug(
                    f"Attack '{attack.name}' -> {outcome.value} "
                    f"({response.latency_ms:.0f}ms)"
                )

                return test_result

            except Exception as e:
                logger.error(f"Error executing attack '{attack.name}': {e}")
                test_result = TestResult(
                    id=uuid.uuid4(),
                    run_id=test_run.id,
                    attack_id=attack.id,
                    outcome=Outcome.ERROR,
                    request_payload=attack.payload,
                    response_text="",
                    error_message=str(e),
                )
                return test_result

    async def run_regression_suite(
        self,
        app_version: str | None = None,
        model_version: str | None = None,
    ) -> TestRun:
        """
        Run only the regression test cases — attacks from confirmed findings.
        
        Returns:
            TestRun containing only regression case results.
        """
        from src.models.regression import RegressionCase

        result = await self.session.execute(
            select(RegressionCase).where(RegressionCase.enabled == True)
        )
        regression_cases = result.scalars().all()

        if not regression_cases:
            logger.info("No regression cases to run")
            raise ValueError("No enabled regression cases found.")

        # Get the attack IDs for regression cases
        attack_ids = [rc.attack_id for rc in regression_cases]
        attacks_result = await self.session.execute(
            select(Attack).where(Attack.id.in_(attack_ids))
        )
        attacks = attacks_result.scalars().all()

        # Create test run
        test_run = TestRun(
            id=uuid.uuid4(),
            target_name=self.target.name,
            target_url=self.target.url,
            app_version=app_version,
            model_version=model_version,
            trigger="regression",
            status="running",
            total_attacks=len(attacks),
        )
        self.session.add(test_run)
        await self.session.flush()

        start_time = time.perf_counter()

        tasks = [self._execute_attack(test_run, attack) for attack in attacks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        test_results = [r for r in results if isinstance(r, TestResult)]
        self.session.add_all(test_results)

        # Update regression case statuses
        for r in results:
            if isinstance(r, TestResult):
                for rc in regression_cases:
                    if rc.attack_id == r.attack_id:
                        rc.last_run_passed = r.outcome == Outcome.PASS
                        rc.last_run_at = datetime.now(UTC)
                        if r.outcome == Outcome.PASS:
                            rc.consecutive_passes += 1
                        else:
                            rc.consecutive_passes = 0
                        break

                if r.outcome == Outcome.PASS:
                    test_run.passed += 1
                elif r.outcome == Outcome.FAIL:
                    test_run.failed += 1
                elif r.outcome == Outcome.NEEDS_REVIEW:
                    test_run.needs_review += 1
                else:
                    test_run.errors += 1
            elif isinstance(r, Exception):
                test_run.errors += 1

        test_run.status = "completed"
        test_run.duration_seconds = time.perf_counter() - start_time
        test_run.completed_at = datetime.now(UTC)

        await self.session.commit()

        logger.info(
            f"Regression run completed: {test_run.passed}/{test_run.total_attacks} passed"
        )

        return test_run
