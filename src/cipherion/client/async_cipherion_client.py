"""
async_client.py - Async CipherionClient
"""

from __future__ import annotations

import os
import time
from typing import Any, Optional

from dotenv import load_dotenv

from ..errors.cipherion_error import CipherionError
from ..utils.async_migration import MigrationHelper
from ..utils.async_http import HttpClient
from ..utils.logger import CipherionLogger
from ..utils.validation import Validator

from ..types.client import (
    CipherionConfig,
    MigrationOptions,
    MigrationProgress,
    MigrationResult,
)

from ..types.api import DeepDecryptOptions, DeepEncryptOptions

load_dotenv()


class AsyncCipherionClient:

    def __init__(self, config: Optional[dict] = None):

        self._config = self._build_config(config or {})

        Validator.validate_config(self._config)

        self._logger = CipherionLogger(self._config.log_level)

        self._http_client = self._make_http_client()

        self._migration_helper = MigrationHelper(self)

        if self._config.enable_logging:
            self._logger.info("CipherionClient initialized")

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _build_config(self, provided: dict) -> CipherionConfig:

        return CipherionConfig(
            base_url=provided.get("base_url")
            or os.environ.get("CIPHERION_BASE_URL", ""),
            project_id=provided.get("project_id")
            or os.environ.get("CIPHERION_PROJECT_ID", ""),
            api_key=provided.get("api_key")
            or os.environ.get("CIPHERION_API_KEY", ""),
            passphrase=provided.get("passphrase")
            or os.environ.get("CIPHERION_PASSPHRASE", ""),
            timeout=provided.get("timeout", 30000),
            retries=provided.get("retries", 3),
            log_level=provided.get("log_level", "info"),
            enable_logging=provided.get("enable_logging", True),
        )

    def _make_http_client(self) -> HttpClient:

        return HttpClient(
            self._config.base_url,
            self._config.api_key,
            self._config.timeout,
            self._logger,
        )

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _get_data_type(data: Any) -> str:

        if data is None:
            return "null"

        if isinstance(data, list):
            return "array"

        if isinstance(data, dict):
            return "object"

        if isinstance(data, bool):
            return "boolean"

        if isinstance(data, int):
            return "number"

        if isinstance(data, float):
            return "number"

        if isinstance(data, str):
            return "string"

        return type(data).__name__

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    async def encrypt(self, data: str) -> str:

        start_time = time.time()

        try:

            Validator.validate_data(data)

            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            Validator.validate_passphrase(passphrase)

            response = await self._http_client.post(
                f"/api/v1/crypto/encrypt/{self._config.project_id}",
                {"data": data, "passphrase": passphrase},
            )

            if self._config.enable_logging:

                duration = int((time.time() - start_time) * 1000)

                self._logger.log_crypto_operation(
                    "encrypt",
                    "success",
                    {
                        "dataType": self._get_data_type(data),
                        "dataLength": len(data),
                        "durationMs": duration,
                        "statusCode": 200,
                    },
                )

            return response["data"]["encrypted_output"]

        except CipherionError:
            raise

        except Exception as exc:

            status = getattr(exc, "status_code", 500)

            raise CipherionError(str(exc), status) from exc

    # ------------------------------------------------------------------

    async def decrypt(self, encrypted_data: str) -> str:

        start_time = time.time()

        try:

            Validator.validate_encrypted_data(encrypted_data)

            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            response = await self._http_client.post(
                f"/api/v1/crypto/decrypt/{self._config.project_id}",
                {"data": encrypted_data, "passphrase": passphrase},
            )

            if self._config.enable_logging:

                duration = int((time.time() - start_time) * 1000)

                self._logger.log_crypto_operation(
                    "decrypt",
                    "success",
                    {
                        "dataType": "string",
                        "dataLength": len(encrypted_data),
                        "durationMs": duration,
                        "statusCode": 200,
                    },
                )

            return response["data"]["plaintext"]

        except CipherionError:
            raise

        except Exception as exc:

            status = getattr(exc, "status_code", 500)

            raise CipherionError(str(exc), status) from exc

    # ------------------------------------------------------------------
    # Deep Encryption
    # ------------------------------------------------------------------

    async def deep_encrypt(
        self,
        data: Any,
        options: Optional[DeepEncryptOptions] = None,
    ) -> dict:

        Validator.validate_data(data)

        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required", 400)

        request_body = {"data": data, "passphrase": passphrase}

        if options:

            if options.exclude_fields:
                request_body["exclude_fields"] = options.exclude_fields

            if options.exclude_patterns:
                request_body["exclude_patterns"] = options.exclude_patterns

        response = await self._http_client.post(
            f"/api/v1/crypto/deep_encrypt/{self._config.project_id}",
            request_body,
        )

        return response["data"]

    # ------------------------------------------------------------------

    async def deep_decrypt(
        self,
        encrypted_data: Any,
        options: Optional[DeepDecryptOptions] = None,
    ) -> dict:

        Validator.validate_encrypted_data(encrypted_data)

        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required", 400)

        request_body = {"encrypted": encrypted_data, "passphrase": passphrase}

        if options:

            if options.exclude_fields:
                request_body["exclude_fields"] = options.exclude_fields

            if options.exclude_patterns:
                request_body["exclude_patterns"] = options.exclude_patterns

            if options.fail_gracefully is not None:
                request_body["fail_gracefully"] = options.fail_gracefully

        response = await self._http_client.post(
            f"/api/v1/crypto/deep_decrypt/{self._config.project_id}",
            request_body,
        )

        return response["data"]

    # ------------------------------------------------------------------
    # Migration
    # ------------------------------------------------------------------

    async def migrate_encrypt(
        self,
        data_array: list[Any],
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:

        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required", 400)

        return await self._migration_helper.encrypt_migration(
            data_array,
            passphrase,
            options,
        )

    async def migrate_decrypt(
        self,
        encrypted_array: list[Any],
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:

        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required", 400)

        return await self._migration_helper.decrypt_migration(
            encrypted_array,
            passphrase,
            options,
        )

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def get_config(self) -> dict:

        return {
            "base_url": self._config.base_url,
            "project_id": self._config.project_id,
            "timeout": self._config.timeout,
            "retries": self._config.retries,
            "log_level": self._config.log_level,
            "enable_logging": self._config.enable_logging,
        }

    def update_config(self, new_config: dict):

        if "api_key" in new_config or "passphrase" in new_config:

            raise CipherionError(
                "Cannot update api_key or passphrase after initialization.",
                403,
            )

        for key, value in new_config.items():

            if hasattr(self._config, key):
                setattr(self._config, key, value)

        Validator.validate_config(self._config)

        if "base_url" in new_config or "timeout" in new_config:
            self._http_client = self._make_http_client()

    async def close(self):
        await self._http_client.close()