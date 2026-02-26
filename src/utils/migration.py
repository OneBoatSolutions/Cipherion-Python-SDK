"""
migration.py - Python 3 port of the TypeScript MigrationHelper (src/utils/migration.ts).

Key differences from the TS original:
- ``Promise.allSettled`` → ``concurrent.futures.ThreadPoolExecutor`` for
  parallel batch processing with the same settle-all semantics.
- ``async/await`` is not used; the public methods are synchronous, matching
  how the SDK's CipherionClient calls them in the previously converted code.
- Exponential back-off + jitter are reproduced with ``time.sleep``.
"""

from __future__ import annotations

import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from typing import TYPE_CHECKING, Any, Optional

from ..types.client import ExclusionOptions, MigrationOptions, MigrationProgress, MigrationResult, FailedMigrationItem

if TYPE_CHECKING:
    from ..client.cipherion_client import CipherionClient


class MigrationHelper:
    def __init__(self, client: "CipherionClient") -> None:
        self._client = client

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def encrypt_migration(
        self,
        data_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        """
        Encrypts every item in *data_array* in parallel batches.
        Mirrors ``encryptMigration`` from the TypeScript source.
        """
        opts = options or MigrationOptions()
        safe_batch_size, safe_delay, safe_retries = self._sanitise_options(opts)

        result = self._make_result(len(data_array))

        for batch_start in range(0, len(data_array), safe_batch_size):
            batch = data_array[batch_start : batch_start + safe_batch_size]

            self._process_batch(
                batch=batch,
                operation=lambda item: self._process_encryption_with_retry(
                    item, safe_retries, opts.exclusion_options
                ),
                result=result,
                on_progress=opts.on_progress,
                on_error=opts.on_error,
            )

            # Inter-batch delay to avoid rate limiting
            has_more = batch_start + safe_batch_size < len(data_array)
            if has_more and safe_delay > 0:
                time.sleep(safe_delay / 1_000)

        return result

    def decrypt_migration(
        self,
        encrypted_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        """
        Decrypts every item in *encrypted_array* in parallel batches.
        Mirrors ``decryptMigration`` from the TypeScript source.
        """
        opts = options or MigrationOptions()
        safe_batch_size, safe_delay, safe_retries = self._sanitise_options(opts)

        result = self._make_result(len(encrypted_array))

        for batch_start in range(0, len(encrypted_array), safe_batch_size):
            batch = encrypted_array[batch_start : batch_start + safe_batch_size]

            self._process_batch(
                batch=batch,
                operation=lambda item: self._process_decryption_with_retry(
                    item, safe_retries, opts.exclusion_options
                ),
                result=result,
                on_progress=opts.on_progress,
                on_error=opts.on_error,
            )

            has_more = batch_start + safe_batch_size < len(encrypted_array)
            if has_more and safe_delay > 0:
                time.sleep(safe_delay / 1_000)

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _sanitise_options(opts: MigrationOptions) -> tuple[int, float, int]:
        """
        Returns (safe_batch_size, safe_delay_ms, safe_retries) with the
        same clamping logic as the TypeScript SECURITY FIX comments.
        """
        batch_size         = opts.batch_size           if opts.batch_size           is not None else 10
        delay_between      = opts.delay_between_batches if opts.delay_between_batches is not None else 1_000
        max_retries        = opts.max_retries           if opts.max_retries           is not None else 3

        safe_batch_size = min(max(1, batch_size), 100)   # clamp 1–100
        safe_delay      = max(0.0, float(delay_between)) # non-negative
        safe_retries    = min(max(1, max_retries), 10)   # clamp 1–10

        return safe_batch_size, safe_delay, safe_retries

    @staticmethod
    def _make_result(total: int) -> MigrationResult:
        return MigrationResult(
            successful=[],
            failed=[],
            summary=MigrationProgress(
                total=total,
                processed=0,
                successful=0,
                failed=0,
                percentage=0.0,
            ),
        )

    def _process_batch(
        self,
        batch: list[Any],
        operation,           # Callable[[Any], Any]
        result: MigrationResult,
        on_progress,         # Optional[Callable[[MigrationProgress], None]]
        on_error,            # Optional[Callable[[Exception, Any], None]]
    ) -> None:
        """
        Runs *operation* on every item in *batch* concurrently
        (mirrors ``Promise.allSettled``), then updates *result* and fires
        the progress / error callbacks — all errors are swallowed to keep
        the migration running.
        """
        # Map future → original item so we can attribute failures
        future_to_item: dict[Future, Any] = {}

        with ThreadPoolExecutor() as executor:
            for item in batch:
                future = executor.submit(operation, item)
                future_to_item[future] = item

            # Collect results as they complete (settle-all semantics)
            for future in as_completed(future_to_item):
                item = future_to_item[future]
                exc = future.exception()

                if exc is None:
                    result.successful.append(future.result())
                    result.summary.successful += 1
                else:
                    result.failed.append(FailedMigrationItem(item=item, error=exc))
                    result.summary.failed += 1
                    if on_error is not None:
                        try:
                            on_error(exc, item)
                        except Exception as cb_exc:
                            print(f"Error in on_error callback: {cb_exc}")

                # finally-equivalent: always update processed + percentage
                result.summary.processed += 1
                result.summary.percentage = round(
                    (result.summary.processed / result.summary.total) * 100
                )

                if on_progress is not None:
                    try:
                        on_progress(result.summary)
                    except Exception as cb_exc:
                        print(f"Error in on_progress callback: {cb_exc}")

    def _process_encryption_with_retry(
        self,
        data: Any,
        max_retries: int,
        exclusion_options: Optional[ExclusionOptions] = None,
    ) -> Any:
        """
        Attempts to encrypt *data* up to *max_retries* times with
        exponential back-off + jitter.  Mirrors
        ``processEncryptionWithRetry``.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                return self._client.deep_encrypt(data, exclusion_options)
            except Exception as exc:
                last_error = exc
                if attempt < max_retries:
                    self._backoff(attempt)

        raise last_error  # type: ignore[misc]  # always set after ≥1 iteration

    def _process_decryption_with_retry(
        self,
        encrypted_data: Any,
        max_retries: int,
        exclusion_options: Optional[ExclusionOptions] = None,
    ) -> Any:
        """
        Attempts to decrypt *encrypted_data* up to *max_retries* times with
        exponential back-off + jitter.  Mirrors
        ``processDecryptionWithRetry``.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                return self._client.deep_decrypt(encrypted_data, exclusion_options)
            except Exception as exc:
                last_error = exc
                if attempt < max_retries:
                    self._backoff(attempt)

        raise last_error  # type: ignore[misc]

    @staticmethod
    def _backoff(attempt: int) -> None:
        """
        Exponential back-off with up to 500 ms jitter.
        ``baseDelay = 1000 * attempt`` matches the TS source exactly.
        """
        base_delay_ms = 1_000 * attempt
        jitter_ms = random.random() * 500          # 0–500 ms
        time.sleep((base_delay_ms + jitter_ms) / 1_000)