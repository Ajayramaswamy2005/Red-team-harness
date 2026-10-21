"""
Token bucket rate limiter.
Prevents the harness from being the thing that takes the app down.
"""

import asyncio
import time
import logging

logger = logging.getLogger(__name__)


class TokenBucketRateLimiter:
    """
    Async token bucket rate limiter.
    
    Controls the rate of requests to prevent overwhelming the target.
    Tokens are added at a fixed rate; each request consumes one token.
    """

    def __init__(self, max_tokens: int, refill_period: float):
        """
        Args:
            max_tokens: Maximum number of tokens (burst capacity).
            refill_period: Period in seconds over which all tokens refill.
        """
        self._max_tokens = max_tokens
        self._tokens = max_tokens
        self._refill_rate = max_tokens / refill_period  # tokens per second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        """
        Acquire a token, waiting if necessary.
        
        Returns:
            Wait time in seconds (0 if no wait was needed).
        """
        async with self._lock:
            self._refill()

            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0

            # Calculate wait time for next token
            wait_time = (1 - self._tokens) / self._refill_rate
            await asyncio.sleep(wait_time)
            self._refill()
            self._tokens -= 1
            return wait_time

    def _refill(self):
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        tokens_to_add = elapsed * self._refill_rate
        self._tokens = min(self._max_tokens, self._tokens + tokens_to_add)
        self._last_refill = now

    @property
    def available_tokens(self) -> float:
        """Current number of available tokens."""
        self._refill()
        return self._tokens
