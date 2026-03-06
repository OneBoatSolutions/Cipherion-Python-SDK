from __future__ import annotations

import asyncio
import random
from typing import TYPE_CHECKING, Any, Optional

from ..types.client import (
    ExclusionOptions,
    MigrationOptions,
    MigrationProgress,
    MigrationResult,
    FailedMigrationItem,
)

if TYPE_CHECKING:
    from ..client.cipherion_client import CipherionClient


class MigrationHelper:

    def __init__(self, client: "CipherionClient"):
        self._client = client

    async def encrypt_migration(
        self,
        data_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:

        opts = options or MigrationOptions()

        batch_size = opts.batch_size or 10
        delay = opts.delay_between_batches or 1000
        retries = opts.max_retries or 3

        result = MigrationResult(
            successful=[],
            failed=[],
            summary=MigrationProgress(
                total=len(data_array),
                processed=0,
                successful=0,
                failed=0,
                percentage=0,
            ),
        )

        for i in range(0, len(data_array), batch_size):

            batch = data_array[i : i + batch_size]

            tasks = [
                self._process_encryption_with_retry(item, retries, opts.exclusion_options)
                for item in batch
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for item, res in zip(batch, results):

                if isinstance(res, Exception):

                    result.failed.append(FailedMigrationItem(item=item, error=res))
                    result.summary.failed += 1

                else:

                    result.successful.append(res)
                    result.summary.successful += 1

                result.summary.processed += 1

                result.summary.percentage = round(
                    (result.summary.processed / result.summary.total) * 100
                )

            if i + batch_size < len(data_array):

                await asyncio.sleep(delay / 1000)

        return result

    async def decrypt_migration(
        self,
        encrypted_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:

        opts = options or MigrationOptions()

        batch_size = opts.batch_size or 10
        delay = opts.delay_between_batches or 1000
        retries = opts.max_retries or 3

        result = MigrationResult(
            successful=[],
            failed=[],
            summary=MigrationProgress(
                total=len(encrypted_array),
                processed=0,
                successful=0,
                failed=0,
                percentage=0,
            ),
        )

        for i in range(0, len(encrypted_array), batch_size):

            batch = encrypted_array[i : i + batch_size]

            tasks = [
                self._process_decryption_with_retry(item, retries, opts.exclusion_options)
                for item in batch
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for item, res in zip(batch, results):

                if isinstance(res, Exception):

                    result.failed.append(FailedMigrationItem(item=item, error=res))
                    result.summary.failed += 1

                else:

                    result.successful.append(res)
                    result.summary.successful += 1

                result.summary.processed += 1

                result.summary.percentage = round(
                    (result.summary.processed / result.summary.total) * 100
                )

            if i + batch_size < len(encrypted_array):

                await asyncio.sleep(delay / 1000)

        return result

    async def _process_encryption_with_retry(
        self,
        data,
        max_retries,
        exclusion_options=None,
    ):

        last_error = None

        for attempt in range(1, max_retries + 1):

            try:
                return await self._client.deep_encrypt(data, exclusion_options)

            except Exception as exc:

                last_error = exc

                if attempt < max_retries:

                    await self._backoff(attempt)

        raise last_error

    async def _process_decryption_with_retry(
        self,
        encrypted_data,
        max_retries,
        exclusion_options=None,
    ):

        last_error = None

        for attempt in range(1, max_retries + 1):

            try:
                return await self._client.deep_decrypt(encrypted_data, exclusion_options)

            except Exception as exc:

                last_error = exc

                if attempt < max_retries:

                    await self._backoff(attempt)

        raise last_error

    async def _backoff(self, attempt):

        base_delay = 1000 * attempt
        jitter = random.random() * 500

        await asyncio.sleep((base_delay + jitter) / 1000)