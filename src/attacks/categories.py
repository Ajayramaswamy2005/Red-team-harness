"""
Attack categories and severity levels.
"""

from enum import StrEnum


class AttackCategory(StrEnum):
    """
    The seven core attack categories plus a catch-all.

    Each maps to a distinct class of vulnerability in LLM-based systems.
    """

    JAILBREAK = "jailbreak"                    # Direct jailbreaks and persona attacks
    INDIRECT_INJECTION = "indirect_injection"  # Injection through retrieved documents
    PROMPT_EXTRACTION = "prompt_extraction"    # System prompt extraction attempts
    PII_EXTRACTION = "pii_extraction"          # Personal data extraction
    HARMFUL_CONTENT = "harmful_content"        # Domain-relevant harmful content generation
    TOOL_ABUSE = "tool_abuse"                  # Tool misuse and privilege escalation
    ENCODING_TRICKS = "encoding_tricks"        # Base64, unicode, and encoding bypasses
    MULTI_TURN = "multi_turn"                  # Multi-turn attack chains (stretch goal)


class Severity(StrEnum):
    """
    Severity levels based on exploitability × impact.
    """

    CRITICAL = "critical"  # Easy to exploit, high impact (data exfil, full bypass)
    HIGH = "high"          # Moderate exploit difficulty OR high impact
    MEDIUM = "medium"      # Requires specific conditions, moderate impact
    LOW = "low"            # Hard to exploit, low impact


class AttackSource(StrEnum):
    """Where the attack originated."""

    GARAK = "garak"
    PYRIT = "pyrit"
    CUSTOM = "custom"
    DOMAIN = "domain"
    REGRESSION = "regression"
