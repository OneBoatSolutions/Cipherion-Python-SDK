"""
http.py - Python 3 port of the TypeScript HttpClient (src/utils/http.ts).

Replaces axios with the ``requests`` library. Interceptor logic is inlined
into the request/response pipeline since ``requests`` has no interceptor API.
"""

from __future__ import annotations

import json
import math
import random
import time
from typing import Any, Optional, TypeVar

import requests
from requests import Response, Session

from ..errors.cipherion_error import CipherionError
from .logger import CipherionLogger

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Request metadata (mirrors axios InternalAxiosRequestConfig.metadata)
# ---------------------------------------------------------------------------

class _RequestMetadata:
    __slots__ = ("start_time", "retry_count")

    def __init__(self, start_time: float, retry_count: int = 0) -> None:
        self.start_time = start_time
        self.retry_count = retry_count


# ---------------------------------------------------------------------------
# HttpClient
# ---------------------------------------------------------------------------

class HttpClient:
    MAX_RETRIES: int = 3
    RETRY_DELAY_MS: int = 1_000

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30_000,
        logger: CipherionLogger = None,
    ) -> None:
        self._logger = logger
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout_s: float = timeout / 1_000   # convert ms → seconds
        self._validate_configuration(base_url, api_key, timeout)
        self._session: Session = self._create_session()

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _validate_configuration(self, base_url: str, api_key: str, timeout: int) -> None:
        if not base_url or not isinstance(base_url, str):
            raise CipherionError("Invalid base URL provided", 400)

        if not api_key or not isinstance(api_key, str):
            raise CipherionError("Invalid API key provided", 400)

        if timeout < 1_000 or timeout > 300_000:
            raise CipherionError("Timeout must be between 1000ms and 300000ms", 400)

    def _create_session(self) -> Session:
        session = requests.Session()
        session.headers.update({
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "User-Agent": "Cipherion-SDK/1.0",
        })
        session.max_redirects = 0
        return session

    # ------------------------------------------------------------------
    # Request handling (mirrors handleRequest interceptor)
    # ------------------------------------------------------------------

    def _handle_request(self, method: str, url: str, data: Any) -> _RequestMetadata:
        """Called just before each outgoing request."""
        metadata = _RequestMetadata(start_time=time.time())

        if data is not None and self._logger:
            self._logger.debug("Outgoing request", {
                "method": method.upper(),
                "url": url,
                "hasData": bool(data),
            })

        return metadata

    # ------------------------------------------------------------------
    # Response handling (mirrors handleSuccessResponse interceptor)
    # ------------------------------------------------------------------

    def _handle_success_response(self, response: Response, metadata: _RequestMetadata) -> Response:
        """Validates the response structure."""
        _ = time.time() - metadata.start_time   # duration available for future logging

        try:
            body = response.json()
        except ValueError:
            body = None

        if body is None or not isinstance(body, dict):
            raise CipherionError("Invalid API response format", 500)

        return response

    # ------------------------------------------------------------------
    # Error / retry handling (mirrors handleErrorResponse interceptor)
    # ------------------------------------------------------------------

    def _handle_error_response(
        self,
        error: Exception,
        metadata: _RequestMetadata,
        method: str,
        url: str,
        data: Any,
    ) -> Response:
        """
        Converts the raw exception into a CipherionError and retries when
        appropriate, mirroring the Axios error interceptor + retry logic.
        """
        cipherion_error = CipherionError.from_requests_error(error)

        if self._should_retry(cipherion_error, metadata.retry_count):
            delay_s = self._calculate_retry_delay(metadata.retry_count) / 1_000
            if self._logger:
                self._logger.warn(
                    f"Retrying request "
                    f"(attempt {metadata.retry_count + 1}/{self.MAX_RETRIES})",
                    {"delay": delay_s * 1_000},
                )

            time.sleep(delay_s)
            metadata.retry_count += 1
            return self._execute_with_retry(method, url, data, metadata)

        raise cipherion_error

    def _should_retry(self, error: CipherionError, retry_count: int) -> bool:
        return retry_count < self.MAX_RETRIES and error.is_retryable()

    def _calculate_retry_delay(self, retry_count: int) -> float:
        """Exponential back-off with ±500 ms jitter, capped at 10 s."""
        base_delay = self.RETRY_DELAY_MS
        exponential_delay = base_delay * math.pow(2, retry_count)
        jitter = random.random() * 500          # 0–500 ms
        return min(exponential_delay + jitter, 10_000)

    # ------------------------------------------------------------------
    # Core request execution
    # ------------------------------------------------------------------

    def _execute_with_retry(
        self,
        method: str,
        url: str,
        data: Any,
        metadata: _RequestMetadata,
    ) -> Response:
        """
        Sends a single HTTP request and runs the interceptor-equivalent hooks.
        Raises CipherionError on failure (after exhausting retries).
        """
        full_url = f"{self._base_url}{url}"

        try:
            response: Response = self._session.request(
                method=method.upper(),
                url=full_url,
                json=data,
                timeout=self._timeout_s,
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as exc:
            return self._handle_error_response(exc, metadata, method, url, data)

        return self._handle_success_response(response, metadata)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def post(self, url: str, data: Any) -> dict:
        """
        Makes a POST request to ``url`` with JSON ``data``.

        Returns the parsed JSON response body as a dict.
        Raises CipherionError for any failure (including non-2xx status codes),
        with automatic retry for transient / network errors.
        """
        if not url or not isinstance(url, str):
            raise CipherionError("Invalid URL provided", 400)

        if data is None:
            raise CipherionError("Request data is required", 400)

        metadata = self._handle_request("POST", url, data)

        try:
            response = self._execute_with_retry("POST", url, data, metadata)
        except CipherionError:
            raise
        except Exception as exc:
            if self._logger:
                self._logger.error("POST request failed", {"error": str(exc)})
            raise CipherionError.from_requests_error(exc)

        # Status gate – mirrors the post() check in the TS source
        if not (200 <= response.status_code < 300):
            try:
                error_data: dict = response.json()
            except ValueError:
                error_data = {}

            error_message: str = error_data.get("message", "Unexpected response status")
            error_details: str = (
                (error_data.get("error") or {}).get("details")
                or json.dumps(error_data)
            )

            raise CipherionError(error_message, response.status_code, error_details)

        return response.json()

    def get_session(self) -> Session:
        """Returns the underlying requests.Session (mirrors getClient())."""
        return self._session