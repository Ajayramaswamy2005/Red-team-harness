"""
GitHub issue reporter — auto-files findings as GitHub issues.
When disabled, logs findings instead.
"""

import logging

from src.config import settings
from src.models.finding import Finding

logger = logging.getLogger(__name__)

# Issue template
ISSUE_TEMPLATE = """## 🔴 Security Finding: {title}

**Severity:** {severity}
**Category:** {category}
**Target:** {target_name}
**App Version:** {app_version}
**Model Version:** {model_version}
**Found:** {found_at}

---

### Description
{description}

### Reproduction Steps

1. Send the following payload to `{target_name}`:

```
{payload}
```

2. Observe the response:

```
{response}
```

### Expected Safe Behavior
{expected_safe_behavior}

### Suggested Mitigation
{mitigation}

---

*Filed automatically by Red-Team Harness*
*Finding ID: {finding_id}*
"""

SEVERITY_LABELS = {
    "critical": "severity: critical",
    "high": "severity: high",
    "medium": "severity: medium",
    "low": "severity: low",
}


class GitHubReporter:
    """
    Files findings as GitHub issues with reproduction steps.
    
    When GitHub integration is disabled, logs the finding details
    so nothing is silently dropped.
    """

    def __init__(self, enabled: bool | None = None):
        self._enabled = enabled if enabled is not None else settings.github_enabled

        if self._enabled:
            try:
                from github import Github
                self._github = Github(settings.github_token)
                self._repo = self._github.get_repo(settings.github_repo)
                logger.info(f"GitHub reporter initialized for {settings.github_repo}")
            except Exception as e:
                logger.warning(f"Failed to initialize GitHub: {e}. Reporter disabled.")
                self._enabled = False
                self._repo = None
        else:
            self._repo = None
            logger.info("GitHub reporter disabled — findings will be logged only")

    async def file_issue(
        self,
        finding: Finding,
        attack_payload: str,
        expected_safe_behavior: str,
    ) -> dict | None:
        """
        File a GitHub issue for a finding.
        
        Args:
            finding: The Finding model instance.
            attack_payload: The exact payload used.
            expected_safe_behavior: What safe behavior was expected.
            
        Returns:
            Dict with issue URL and number, or None if disabled.
        """
        severity_str = finding.severity if isinstance(finding.severity, str) else finding.severity.value
        category_str = finding.category if isinstance(finding.category, str) else finding.category.value

        body = ISSUE_TEMPLATE.format(
            title=finding.title,
            severity=severity_str.upper(),
            category=category_str,
            target_name=finding.target_name,
            app_version=finding.app_version or "unknown",
            model_version=finding.model_version or "unknown",
            found_at=finding.found_at.isoformat() if finding.found_at else "unknown",
            description=finding.description,
            payload=attack_payload[:2000],
            response=finding.response_received[:2000],
            expected_safe_behavior=expected_safe_behavior,
            mitigation=finding.suggested_mitigation,
            finding_id=str(finding.id),
        )

        if not self._enabled:
            logger.info(
                f"[MOCK GITHUB] Would file issue: {finding.title} "
                f"[{severity_str}] — {finding.description[:100]}"
            )
            return None

        try:
            labels = [
                "red-team",
                "security",
                SEVERITY_LABELS.get(severity_str, "severity: medium"),
                f"category: {category_str}",
            ]

            # Create labels that don't exist yet
            existing_labels = [l.name for l in self._repo.get_labels()]
            for label in labels:
                if label not in existing_labels:
                    try:
                        color = {
                            "severity: critical": "B60205",
                            "severity: high": "D93F0B",
                            "severity: medium": "FBCA04",
                            "severity: low": "0E8A16",
                        }.get(label, "C5DEF5")
                        self._repo.create_label(name=label, color=color)
                    except Exception:
                        pass  # Label might already exist

            issue = self._repo.create_issue(
                title=f"🔴 [{severity_str.upper()}] {finding.title}",
                body=body,
                labels=labels,
            )

            logger.info(f"Filed GitHub issue #{issue.number}: {finding.title}")

            return {
                "url": issue.html_url,
                "number": issue.number,
            }

        except Exception as e:
            logger.error(f"Failed to file GitHub issue: {e}")
            return None
