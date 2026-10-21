"""
Finding generator — creates findings from failed test results.
Handles deduplication, severity computation, and GitHub filing.
"""

import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.findings.deduplicator import Deduplicator
from src.findings.github_reporter import GitHubReporter
from src.findings.severity import compute_severity
from src.models.attack import Attack
from src.models.finding import Finding
from src.models.regression import RegressionCase
from src.models.run import TestResult, TestRun
from src.scoring.outcomes import Outcome

logger = logging.getLogger(__name__)


# Mitigation suggestions by category
MITIGATION_SUGGESTIONS = {
    "jailbreak": (
        "Strengthen system prompt guardrails. Add explicit refusal instructions for "
        "persona adoption and role-play attacks. Consider input filtering for known "
        "jailbreak patterns (DAN, developer mode, etc.)."
    ),
    "indirect_injection": (
        "Implement content boundary separation between system/user/retrieved content. "
        "Add instruction hierarchy enforcement so retrieved documents cannot override "
        "system instructions. Sanitize retrieved content before including in context."
    ),
    "prompt_extraction": (
        "Add explicit instructions to never reveal system prompts regardless of "
        "how the request is framed. Implement output filtering to detect and block "
        "system prompt content in responses."
    ),
    "pii_extraction": (
        "Implement PII detection and redaction in both input processing and output "
        "filtering. Add guardrails against generating realistic-looking PII data. "
        "Ensure training data does not contain real PII."
    ),
    "harmful_content": (
        "Strengthen content policy enforcement. Add specific refusal patterns for "
        "common attack framings (academic, research, creative writing). Implement "
        "output content classification."
    ),
    "tool_abuse": (
        "Implement strict tool access control with proper authorization. Add input "
        "validation on tool parameters. Never execute tool calls embedded in user "
        "input without explicit authorization checks."
    ),
    "encoding_tricks": (
        "Implement input normalization to decode common encoding schemes before "
        "safety checking. Add detection for unicode homoglyphs, zero-width characters, "
        "and multi-layer encoding chains."
    ),
    "multi_turn": (
        "Implement conversation-level safety monitoring that tracks context across "
        "turns. Add progressive risk scoring that increases scrutiny as conversations "
        "exhibit manipulative patterns."
    ),
}


class FindingGenerator:
    """
    Generates findings from failed test results.
    
    Workflow:
    1. Process all FAIL results from a test run
    2. Compute severity for each
    3. Deduplicate against existing open findings
    4. Create new findings with reproduction steps
    5. File GitHub issues for new findings
    6. Create regression cases for confirmed findings
    """

    def __init__(self, session: AsyncSession):
        self.session = session
        self._deduplicator = Deduplicator(session)
        self._github = GitHubReporter()

    async def process_run(self, test_run: TestRun) -> list[Finding]:
        """
        Process all failed results from a test run and generate findings.
        
        Returns:
            List of new findings created.
        """
        # Get all failed results for this run
        result = await self.session.execute(
            select(TestResult).where(
                TestResult.run_id == test_run.id,
                TestResult.outcome == Outcome.FAIL,
            )
        )
        failed_results = result.scalars().all()

        if not failed_results:
            logger.info(f"No failed results in run {test_run.id}")
            return []

        logger.info(f"Processing {len(failed_results)} failed results from run {test_run.id}")

        new_findings = []
        for test_result in failed_results:
            finding = await self._process_result(test_run, test_result)
            if finding:
                new_findings.append(finding)

        await self.session.commit()

        logger.info(
            f"Generated {len(new_findings)} new findings "
            f"(deduplicated {len(failed_results) - len(new_findings)})"
        )

        return new_findings

    async def _process_result(
        self, test_run: TestRun, test_result: TestResult
    ) -> Finding | None:
        """Process a single failed test result into a finding."""
        # Get the attack
        attack_result = await self.session.execute(
            select(Attack).where(Attack.id == test_result.attack_id)
        )
        attack = attack_result.scalar_one_or_none()
        if not attack:
            logger.warning(f"Attack {test_result.attack_id} not found")
            return None

        # Compute dedup signature
        dedup_sig = Finding.compute_dedup_signature(
            attack.id, test_result.response_text or ""
        )

        # Check for duplicates
        if await self._deduplicator.is_duplicate(dedup_sig):
            return None

        # Compute severity
        category = attack.category if isinstance(attack.category, str) else attack.category.value
        severity = compute_severity(category)

        # Build finding
        title = f"{category.replace('_', ' ').title()}: {attack.name}"
        description = self._build_description(attack, test_result)
        mitigation = MITIGATION_SUGGESTIONS.get(category, "Review and implement appropriate safeguards.")

        finding = Finding(
            id=uuid.uuid4(),
            result_id=test_result.id,
            attack_id=attack.id,
            category=attack.category,
            severity=severity,
            title=title,
            description=description,
            reproduction_payload=attack.payload,
            response_received=test_result.response_text or "",
            suggested_mitigation=mitigation,
            dedup_signature=dedup_sig,
            status="open",
            target_name=test_run.target_name,
            app_version=test_run.app_version,
            model_version=test_run.model_version,
        )
        self.session.add(finding)
        await self.session.flush()

        # File GitHub issue
        issue_result = await self._github.file_issue(
            finding=finding,
            attack_payload=attack.payload,
            expected_safe_behavior=attack.expected_safe_behavior,
        )
        if issue_result:
            finding.github_issue_url = issue_result["url"]
            finding.github_issue_number = issue_result["number"]

        # Create regression case
        await self._create_regression_case(finding, attack)

        logger.info(f"New finding: {finding.title} [{severity}]")
        return finding

    async def _create_regression_case(self, finding: Finding, attack: Attack):
        """Create a regression case from a confirmed finding."""
        regression = RegressionCase(
            id=uuid.uuid4(),
            finding_id=finding.id,
            attack_id=attack.id,
            payload=attack.payload,
            expected_safe_behavior=attack.expected_safe_behavior,
            target_name=finding.target_name,
            enabled=True,
        )
        self.session.add(regression)
        logger.debug(f"Created regression case for finding {finding.title}")

    @staticmethod
    def _build_description(attack: Attack, result: TestResult) -> str:
        """Build a human-readable description for the finding."""
        category = attack.category if isinstance(attack.category, str) else attack.category.value
        parts = [
            f"The target failed to safely handle a {category.replace('_', ' ')} attack.",
            "",
            f"**Attack:** {attack.name}",
            f"**Category:** {category}",
            "",
        ]

        # Add scoring details
        if result.score_explanation:
            parts.append(f"**Scoring:** {result.score_explanation}")
            parts.append("")

        if result.deterministic_checks:
            triggered = [
                k for k, v in result.deterministic_checks.items()
                if isinstance(v, dict) and v.get("triggered")
            ]
            if triggered:
                parts.append(f"**Triggered Checks:** {', '.join(triggered)}")
                parts.append("")

        return "\n".join(parts)
