from __future__ import annotations

import math
import random
import asyncio
import time
from typing import Any, TypeVar

import aiohttp

from ..errors.cipherion_error import CipherionError
from ..utils.logger import CipherionLogger

T = TypeVar("T")


class _RequestMetadata:
    __slots__ = ("start_time", "retry_count")

    def __init__(self, start_time: float, retry_count: int = 0) -> None:
        self.start_time = start_time
        self.retry_count = retry_count


class HttpClient:
    MAX_RETRIES: int = 3
    RETRY_DELAY_MS: int = 1000

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30000,
        logger: CipherionLogger = None,
    ) -> None:

        self._logger = logger
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout / 1000

        self._validate_configuration(base_url, api_key, timeout)

        self._headers = {
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "User-Agent": "Cipherion-SDK/1.0",
        }

        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._timeout),
            headers=self._headers,
        )

    def _validate_configuration(self, base_url: str, api_key: str, timeout: int):

        if not base_url or not isinstance(base_url, str):
            raise CipherionError("Invalid base URL provided", 400)

        if not api_key or not isinstance(api_key, str):
            raise CipherionError("Invalid API key provided", 400)

        if timeout < 1000 or timeout > 300000:
            raise CipherionError("Timeout must be between 1000ms and 300000ms", 400)

    async def _execute_with_retry(self, method: str, url: str, data: Any, metadata):

        full_url = f"{self._base_url}{url}"

        try:

            async with self._session.request(
                method,
                full_url,
                json=data,
            ) as response:

                status = response.status
                body = await response.json()

                return status, body

        except Exception as exc:

            cipherion_error = CipherionError.from_requests_error(exc)

            if self._should_retry(cipherion_error, metadata.retry_count):

                delay = self._calculate_retry_delay(metadata.retry_count) / 1000

                if self._logger:
                    self._logger.warn(
                        f"Retrying request ({metadata.retry_count + 1}/{self.MAX_RETRIES})",
                        {"delay": delay * 1000},
                    )

                await asyncio.sleep(delay)

                metadata.retry_count += 1

                return await self._execute_with_retry(method, url, data, metadata)

            raise cipherion_error

    def _should_retry(self, error: CipherionError, retry_count: int):

        return retry_count < self.MAX_RETRIES and error.is_retryable()

    def _calculate_retry_delay(self, retry_count: int):

        base = self.RETRY_DELAY_MS
        exp = base * math.pow(2, retry_count)
        jitter = random.random() * 500

        return min(exp + jitter, 10000)

    async def post(self, url: str, data: Any) -> dict:

        if not url:
            raise CipherionError("Invalid URL provided", 400)

        metadata = _RequestMetadata(time.time())

        status, response_data = await self._execute_with_retry(
            "POST", url, data, metadata
        )

        if not (200 <= status < 300):

            error_message = response_data.get("message", "Unexpected response status")

            raise CipherionError(error_message, status)

        return response_data

    async def close(self):

        await self._session.close()