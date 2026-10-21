"""
Target adapter abstract base class.
A function taking a payload and returning a response plus metadata.
This interface lets the harness point at any application you build.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetResponse:
    """
    Response from a target application.
    
    Attributes:
        text: The text content of the response.
        status_code: HTTP status code (if applicable).
        latency_ms: Time taken for the request in milliseconds.
        metadata: Additional metadata from the target (model version, etc.).
        raw_response: The raw response object for detailed inspection.
        error: Error message if the request failed.
    """
    text: str = ""
    status_code: int = 200
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_response: Any = None
    error: str | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None or self.status_code >= 400


class TargetAdapter(ABC):
    """
    Abstract base class for target adapters.
    
    Implement this for each AI application you want to test.
    The interface is intentionally simple: send a payload, get a response.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this target."""
        ...

    @property
    @abstractmethod
    def url(self) -> str:
        """Base URL of the target."""
        ...

    @abstractmethod
    async def send(self, payload: str) -> TargetResponse:
        """
        Send an attack payload to the target and return the response.
        
        Args:
            payload: The attack prompt/input to send.
            
        Returns:
            TargetResponse with the target's response and metadata.
        """
        ...

    async def health_check(self) -> bool:
        """Check if the target is reachable. Override for custom checks."""
        try:
            response = await self.send("Hello, are you there?")
            return not response.is_error
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} url={self.url}>"
