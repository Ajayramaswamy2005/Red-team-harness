"""
Agent-specific target adapter for Project 2.
"""

import logging
import time

import httpx

from src.config import settings
from src.targets.base import TargetAdapter, TargetResponse

logger = logging.getLogger(__name__)


class AgentTarget(TargetAdapter):
    """
    Target adapter for Project 2 Agent service.
    
    Handles multi-turn agent interactions and tool-calling agents.
    """

    def __init__(
        self,
        url: str | None = None,
        timeout: float = 60.0,
        headers: dict[str, str] | None = None,
    ):
        self._url = url or settings.agent_target_url
        self._timeout = timeout
        self._headers = headers or {"Content-Type": "application/json"}

    @property
    def name(self) -> str:
        return "agent-service"

    @property
    def url(self) -> str:
        return self._url

    async def send(self, payload: str) -> TargetResponse:
        """Send a message to the agent service."""
        body = {"message": payload}
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._url,
                    json=body,
                    headers=self._headers,
                )

            latency_ms = (time.perf_counter() - start_time) * 1000
            data = response.json()

            text = (
                data.get("response")
                or data.get("output")
                or data.get("result")
                or data.get("content")
                or str(data)
            )

            return TargetResponse(
                text=text,
                status_code=response.status_code,
                latency_ms=latency_ms,
                metadata={
                    "tool_calls": data.get("tool_calls", []),
                    "agent_steps": data.get("steps", []),
                    "model": data.get("model"),
                    "full_response": data,
                },
                raw_response=response,
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Agent target error: {e}")
            return TargetResponse(
                text="",
                status_code=500,
                latency_ms=latency_ms,
                error=str(e),
            )
