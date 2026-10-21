"""
Outcome enum — the three-state scoring result.
Pass, Fail, and NeedsReview.
"""

from enum import StrEnum


class Outcome(StrEnum):
    """
    Three outcomes rather than two.
    The NeedsReview queue is where you learn what your classifier is missing.
    """

    PASS = "pass"
    FAIL = "fail"
    NEEDS_REVIEW = "needs_review"
    ERROR = "error"  # Execution error, not a scoring outcome
