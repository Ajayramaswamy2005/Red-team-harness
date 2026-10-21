"""
Generic HTTP target adapter.
Works with any API that accepts a JSON payload and returns text.
"""

import logging
import time
from typing import Any

import httpx

from src.targets.base import TargetAdapter, TargetResponse

logger = logging.getLogger(__name__)


class HttpTarget(TargetAdapter):
    """
    Generic HTTP target adapter for any REST API.
    
    Sends payloads as JSON POST requests and extracts the response text.
    Configurable request/response field mappings allow it to work with
    different API shapes.
    """

    def __init__(
        self,
        name: str,
        url: str,
        request_field: str = "message",
        response_field: str = "response",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        extra_body: dict[str, Any] | None = None,
    ):
        """
        Args:
            name: Human-readable target name.
            url: API endpoint URL.
            request_field: JSON field name for the payload in the request body.
            response_field: JSON field name to extract from the response.
                           Use dot notation for nested fields (e.g., "data.content").
            headers: Additional HTTP headers.
            timeout: Request timeout in seconds.
            extra_body: Additional fields to include in the request body.
        """
        self._name = name
        self._url = url
        self._request_field = request_field
        self._response_field = response_field
        self._headers = headers or {"Content-Type": "application/json"}
        self._timeout = timeout
        self._extra_body = extra_body or {}

    @property
    def name(self) -> str:
        return self._name

    @property
    def url(self) -> str:
        return self._url

    async def send(self, payload: str) -> TargetResponse:
        """Send the payload to the HTTP endpoint."""
        body = {self._request_field: payload, **self._extra_body}
        start_time = time.perf_counter()

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._url,
                    json=body,
                    headers=self._headers,
                )

            latency_ms = (time.perf_counter() - start_time) * 1000

            # Extract response text using dot notation
            response_data = response.json()
            text = self._extract_field(response_data, self._response_field)

            return TargetResponse(
                text=text,
                status_code=response.status_code,
                latency_ms=latency_ms,
                metadata={
                    "response_headers": dict(response.headers),
                    "response_data": response_data,
                },
                raw_response=response,
            )

        except httpx.TimeoutException:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                text="",
                status_code=408,
                latency_ms=latency_ms,
                error=f"Request timed out after {self._timeout}s",
            )
        except httpx.ConnectError:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return TargetResponse(
                text="",
                status_code=503,
                latency_ms=latency_ms,
                error=f"Connection failed to {self._url}",
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Error sending to {self._url}: {e}")
            return TargetResponse(
                text="",
                status_code=500,
                latency_ms=latency_ms,
                error=str(e),
            )

    @staticmethod
    def _extract_field(data: dict, field_path: str) -> str:
        """Extract a field from nested dict using dot notation."""
        parts = field_path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return str(data)  # Fall back to full response
        return str(current)
