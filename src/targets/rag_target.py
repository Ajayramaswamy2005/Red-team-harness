"""
RAG-specific target adapter for Project 1.
Includes support for poisoned document injection.
"""

import logging
import time
from typing import Any

import httpx

from src.config import settings
from src.targets.base import TargetAdapter, TargetResponse

logger = logging.getLogger(__name__)


class RagTarget(TargetAdapter):
    """
    Target adapter for Project 1 RAG service.
    
    Beyond standard query/response, this adapter supports:
    - Injecting poisoned documents into the corpus before attack
    - Retrieving what documents were consulted in the response
    - Testing with different retrieval configurations
    """

    def __init__(
        self,
        url: str | None = None,
        ingest_url: str | None = None,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ):
        self._url = url or settings.rag_target_url
        self._ingest_url = ingest_url or self._url.replace("/chat", "/ingest")
        self._timeout = timeout
        self._headers = headers or {"Content-Type": "application/json"}

    @property
    def name(self) -> str:
        return "rag-service"

    @property
    def url(self) -> str:
        return self._url

    async def send(self, payload: str) -> TargetResponse:
        """Send a query to the RAG service."""
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

            # Try to extract response text from common field names
            text = (
                data.get("response")
                or data.get("answer")
                or data.get("content")
                or data.get("text")
                or str(data)
            )

            return TargetResponse(
                text=text,
                status_code=response.status_code,
                latency_ms=latency_ms,
                metadata={
                    "sources": data.get("sources", []),
                    "model": data.get("model"),
                    "retrieval_count": data.get("retrieval_count"),
                    "full_response": data,
                },
                raw_response=response,
            )

        except Exception as e:
            latency_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"RAG target error: {e}")
            return TargetResponse(
                text="",
                status_code=500,
                latency_ms=latency_ms,
                error=str(e),
            )

    async def inject_poison_document(
        self,
        content: str,
        title: str = "Poisoned Test Document",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Inject a poisoned document into the RAG corpus for testing.
        
        This is how you test whether the pipeline follows instructions
        from retrieved documents — the core indirect injection attack.
        
        Args:
            content: The poisoned document content.
            title: Document title.
            metadata: Additional document metadata.
            
        Returns:
            True if injection succeeded.
        """
        body = {
            "content": content,
            "title": title,
            "metadata": metadata or {"test": True, "type": "poison"},
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    self._ingest_url,
                    json=body,
                    headers=self._headers,
                )
            return response.status_code < 400
        except Exception as e:
            logger.error(f"Failed to inject poison document: {e}")
            return False

    async def cleanup_poison_documents(self) -> bool:
        """Remove test documents from the corpus."""
        try:
            cleanup_url = self._ingest_url.replace("/ingest", "/cleanup-test")
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.delete(
                    cleanup_url,
                    headers=self._headers,
                )
            return response.status_code < 400
        except Exception as e:
            logger.warning(f"Cleanup failed (may not be implemented): {e}")
            return False
