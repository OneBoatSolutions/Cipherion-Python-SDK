"""
CipherionClient - Python 3 port of the TypeScript CipherionClient
"""

from __future__ import annotations

import json
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
import requests
from dotenv import load_dotenv
from ..errors.cipherion_error import CipherionError
from ..utils.migration import MigrationHelper
from ..utils.http import HttpClient
from ..utils.logger import CipherionLogger
from ..utils.validation import Validator
from ..types.client import CipherionConfig, MigrationOptions, MigrationProgress,MigrationResult
from ..types.api import DeepDecryptOptions, DeepEncryptOptions

load_dotenv()
# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------

class CipherionClient:
    """
        Python client for interacting with the Cipherion encryption API.

        This client provides utilities for:
        - Simple string encryption/decryption
        - Deep encryption of nested data structures
        - Batch migration utilities
        - Configuration management

        Environment variables (optional):
            CIPHERION_BASE_URL
            CIPHERION_PROJECT_ID
            CIPHERION_API_KEY
            CIPHERION_PASSPHRASE

        Example:
            >>> client = CipherionClient()
            >>> encrypted = client.encrypt("hello")
            >>> decrypted = client.decrypt(encrypted)
    """
    def __init__(self, config: Optional[dict] = None) -> None:
        """
        Initialize the Cipherion client.

        Builds configuration from the provided dictionary and environment
        variables, validates it, and prepares HTTP and migration helpers.

        Args:
            config (Optional[dict]): Partial configuration overrides. Any
                missing values will be read from environment variables.

        Raises:
            CipherionError: If required configuration values are missing.

        Example:
            >>> client = CipherionClient({
            ...     "base_url": "https://api.cipherion.com",
            ...     "project_id": "proj_123",
            ...     "api_key": "key_abc",
            ...     "passphrase": "secret"
            ... })
        """
        self._config = self._build_config(config or {})
        Validator.validate_config(self._config)

        self._logger = CipherionLogger(self._config.log_level)
        self._http_client = self._make_http_client()
        self._migration_helper = MigrationHelper(self)

        if self._config.enable_logging:
            self._logger.info("CipherionClient initialized")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_config(self, provided: dict) -> CipherionConfig:
        """
        Construct the final client configuration.

        Priority order:
            1. Explicit values in `provided`
            2. Environment variables
            3. Default values

        Args:
            provided (dict): User-supplied configuration values.

        Returns:
            CipherionConfig: Fully populated configuration object.
         """
        return CipherionConfig(
            base_url=provided.get("base_url") or os.environ.get("CIPHERION_BASE_URL", ""),
            project_id=provided.get("project_id") or os.environ.get("CIPHERION_PROJECT_ID", ""),
            api_key=provided.get("api_key") or os.environ.get("CIPHERION_API_KEY", ""),
            passphrase=provided.get("passphrase") or os.environ.get("CIPHERION_PASSPHRASE", ""),
            timeout=provided.get("timeout", 30_000),
            retries=provided.get("retries", 3),
            log_level=provided.get("log_level", "info"),
            enable_logging=provided.get("enable_logging", True),
        )

    def _make_http_client(self) -> HttpClient:
        """
        Create and configure the internal HTTP client.

        Returns:
            HttpClient: Configured HTTP client instance used for API calls.
        """
        return HttpClient(
            self._config.base_url,
            self._config.api_key,
            self._config.timeout,
            self._logger,
        )

    @staticmethod
    def _get_data_type(data: Any) -> str:
        """
        Determine a normalized data type label for logging purposes.

        Args:
            data (Any): Input data.

        Returns:
            str: One of 'null', 'array', 'object', 'boolean',
            'number', 'string', or the Python type name.
        """
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
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, data: str) -> str:
        """Encrypts a simple string.  Args:
                data (str): The plaintext string to encrypt.

            Returns:
                str: Encrypted string output from Cipherion.

            Raises:
            CipherionError: If validation fails or API returns an error.

            Example:
            >>> result = client.encrypt("my-secret-data")
        """
        start_time = time.time()

        try:
            Validator.validate_data(data)
            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            Validator.validate_passphrase(passphrase)

            response = self._http_client.post(
                f"/api/v1/crypto/encrypt/{self._config.project_id}",
                {"data": data, "passphrase": passphrase},
            )

            if self._config.enable_logging:
                duration_ms = int((time.time() - start_time) * 1_000)
                self._logger.log_crypto_operation("encrypt", "success", {
                    "dataType": self._get_data_type(data),
                    "dataLength": len(data),
                    "durationMs": duration_ms,
                    "statusCode": 200,
                })

            return response["data"]["encrypted_output"]

        except CipherionError:
            raise
        except Exception as exc:
            status = getattr(exc, "status_code", 500)
            server_message = str(exc)
            duration_ms = int((time.time() - start_time) * 1_000)

            if self._config.enable_logging:
                self._logger.log_crypto_operation("encrypt", "error", {
                    "dataType": self._get_data_type(data),
                    "dataLength": len(data) if data else None,
                    "durationMs": duration_ms,
                    "statusCode": status,
                    "errorMessage": server_message,
                })

            raise CipherionError(server_message, status) from exc

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypts a simple string.Args:
            encrypted_data (str): The encrypted string to decrypt.

            Returns:
                str: Decrypted plaintext.

            Raises:
                CipherionError: If validation fails or API returns an error.

            Example:
                >>> result = client.decrypt(encrypted_text)
        """
        start_time = time.time()

        try:
            Validator.validate_encrypted_data(encrypted_data)
            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            response = self._http_client.post(
                f"/api/v1/crypto/decrypt/{self._config.project_id}",
                {"data": encrypted_data, "passphrase": passphrase},
            )

            if self._config.enable_logging:
                duration_ms = int((time.time() - start_time) * 1_000)
                self._logger.log_crypto_operation("decrypt", "success", {
                    "dataType": "string",
                    "dataLength": len(encrypted_data),
                    "durationMs": duration_ms,
                    "statusCode": 200,
                })

            return response["data"]["plaintext"]

        except CipherionError:
            raise
        except Exception as exc:
            status = getattr(exc, "status_code", 500)
            server_message = str(exc)
            duration_ms = int((time.time() - start_time) * 1_000)

            if self._config.enable_logging:
                self._logger.log_crypto_operation("decrypt", "error", {
                    "dataType": self._get_data_type(encrypted_data),
                    "dataLength": len(encrypted_data) if encrypted_data else None,
                    "durationMs": duration_ms,
                    "statusCode": status,
                    "errorMessage": server_message,
                })

            raise CipherionError(server_message, status) from exc

    def deep_encrypt(
        self,
        data: Any,
        options: Optional[DeepEncryptOptions] = None,
    ) -> dict:
        """ Encrypts complex data structures while preserving structure.

        Supports nested dictionaries, lists, and mixed data types.
        Specific fields or patterns can be excluded from encryption.

        Args:
            data (Any): The data structure to encrypt.
            options (DeepEncryptOptions, optional):
                - exclude_fields: Explicit field paths to skip.
                - exclude_patterns: Wildcard patterns to skip.

        Returns:
            dict: Encrypted data along with metadata.

        Raises:
            CipherionError: If validation fails or API returns an error.

        Example:
            >>> result = client.deep_encrypt(data)

            >>> result = client.deep_encrypt(
            ...     data,
            ...     DeepEncryptOptions(
            ...         exclude_fields=["profile.id"],
            ...         exclude_patterns=["*_at"]
            ...     )
            ... )
        """
        start_time = time.time()

        try:
            Validator.validate_data(data)
            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            Validator.validate_passphrase(passphrase)

            request_body: dict = {"data": data, "passphrase": passphrase}
            if options and options.exclude_fields:
                request_body["exclude_fields"] = options.exclude_fields
            if options and options.exclude_patterns:
                request_body["exclude_patterns"] = options.exclude_patterns

            response = self._http_client.post(
                f"/api/v1/crypto/deep_encrypt/{self._config.project_id}",
                request_body,
            )

            if self._config.enable_logging:
                duration_ms = int((time.time() - start_time) * 1_000)
                self._logger.log_crypto_operation("deepEncrypt", "success", {
                    "dataType": self._get_data_type(data),
                    "totalFields": response["data"]["meta"]["totalFields"],
                    "billableFields": response["data"]["meta"]["billableFields"],
                    "excludedFields": len(options.exclude_fields) if options and options.exclude_fields else 0,
                    "excludedPatterns": len(options.exclude_patterns) if options and options.exclude_patterns else 0,
                    "durationMs": duration_ms,
                    "statusCode": 200,
                })

            return response["data"]

        except CipherionError:
            raise
        except Exception as exc:
            status = getattr(exc, "status_code", 500)
            server_message = str(exc)
            duration_ms = int((time.time() - start_time) * 1_000)

            if self._config.enable_logging:
                self._logger.log_crypto_operation("deepEncrypt", "error", {
                    "dataType": self._get_data_type(data),
                    "excludedFields": len(options.exclude_fields) if options and options.exclude_fields else 0,
                    "excludedPatterns": len(options.exclude_patterns) if options and options.exclude_patterns else 0,
                    "durationMs": duration_ms,
                    "statusCode": status,
                    "errorMessage": server_message,
                })

            raise CipherionError(server_message, status) from exc

    def deep_decrypt(
        self,
        encrypted_data: Any,
        options: Optional[DeepDecryptOptions] = None,
    ) -> dict:
        """Decrypts complex data structures that were encrypted using deep_encrypt.

            Args:
                encrypted_data (Any): The encrypted data structure.
                options (DeepDecryptOptions, optional):
                    - exclude_fields: Fields to skip during decryption.
                    - exclude_patterns: Pattern-based exclusions.
                    - fail_gracefully: Continue even if some fields fail.

            Returns:
                dict: Decrypted data with metadata.

            Raises:
                CipherionError: If validation fails or API returns an error.

            Example:
                >>> result = client.deep_decrypt(encrypted_data)

                >>> result = client.deep_decrypt(
                ...     encrypted_data,
                ...     DeepDecryptOptions(fail_gracefully=True)
                ... )
        """
        start_time = time.time()

        try:
            Validator.validate_encrypted_data(encrypted_data)
            passphrase = self._config.passphrase

            if not passphrase:
                raise CipherionError("Passphrase is required", 400)

            request_body: dict = {"encrypted": encrypted_data, "passphrase": passphrase}
            if options and options.exclude_fields:
                request_body["exclude_fields"] = options.exclude_fields
            if options and options.exclude_patterns:
                request_body["exclude_patterns"] = options.exclude_patterns
            if options and options.fail_gracefully is not None:
                request_body["fail_gracefully"] = options.fail_gracefully

            response = self._http_client.post(
                f"/api/v1/crypto/deep_decrypt/{self._config.project_id}",
                request_body,
            )

            if self._config.enable_logging:
                duration_ms = int((time.time() - start_time) * 1_000)
                self._logger.log_crypto_operation("deepDecrypt", "success", {
                    "dataType": self._get_data_type(encrypted_data),
                    "totalFields": response["data"]["meta"]["totalFields"],
                    "billableFields": response["data"]["meta"]["billableFields"],
                    "excludedFields": len(options.exclude_fields) if options and options.exclude_fields else 0,
                    "excludedPatterns": len(options.exclude_patterns) if options and options.exclude_patterns else 0,
                    "failGracefully": options.fail_gracefully if options else None,
                    "durationMs": duration_ms,
                    "statusCode": 200,
                })

            return response["data"]

        except CipherionError:
            raise
        except Exception as exc:
            status = getattr(exc, "status_code", 500)
            server_message = str(exc)
            duration_ms = int((time.time() - start_time) * 1_000)

            if self._config.enable_logging:
                self._logger.log_crypto_operation("deepDecrypt", "error", {
                    "dataType": self._get_data_type(encrypted_data),
                    "excludedFields": len(options.exclude_fields) if options and options.exclude_fields else 0,
                    "excludedPatterns": len(options.exclude_patterns) if options and options.exclude_patterns else 0,
                    "failGracefully": options.fail_gracefully if options else None,
                    "durationMs": duration_ms,
                    "statusCode": status,
                    "errorMessage": "data may be corrupted or " + server_message,
                })

            raise CipherionError(server_message, status) from exc

    def migrate_encrypt(
        self,
        data_array: list[Any],
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        """ Migrates an array of data by encrypting each item in batches.

            Useful for processing large datasets without blocking the event loop
            or hitting API rate limits.

            Args:
                data_array (list[Any]): List of items to encrypt.
                options (MigrationOptions, optional): Batch configuration.

            Returns:
                MigrationResult: Summary of successful and failed items.

            Raises:
                CipherionError: If passphrase is missing or input is invalid.

            Example:
                >>> result = client.migrate_encrypt(data_list)
        """
        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required for migration", 400)
        if not isinstance(data_array, list):
            raise CipherionError("data_array must be a list", 400)

        if len(data_array) == 0:
            self._logger.warn("Empty list provided for encryption migration")
            return MigrationResult(
                successful=[],
                failed=[],
                summary=MigrationProgress(total=0, processed=0, successful=0, failed=0, percentage=100.0),
            )

        if self._config.enable_logging:
            self._logger.log_migration_operation("migrateEncrypt", "started", {
                "totalItems": len(data_array),
                "batchSize": options.batch_size if options else 10,
            })

        try:
            result = self._migration_helper.encrypt_migration(data_array, passphrase, options)

            if self._config.enable_logging:
                self._logger.log_migration_operation("migrateEncrypt", "completed", {
                    "totalItems": result.summary.total,
                    "processed": result.summary.processed,
                    "successful": result.summary.successful,
                    "failed": result.summary.failed,
                    "percentage": result.summary.percentage,
                })

            return result

        except Exception as exc:
            if self._config.enable_logging:
                self._logger.log_migration_operation("migrateEncrypt", "error", {
                    "totalItems": len(data_array),
                    "errorMessage": str(exc),
                })
            raise

    def migrate_decrypt(
        self,
        encrypted_array: list[Any],
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        """ Migrates an array of encrypted data by decrypting each item in batches.

            Args:
                encrypted_array (list[Any]): List of encrypted items.
                options (MigrationOptions, optional): Batch configuration.

            Returns:
                MigrationResult: Summary of successful and failed items.

            Raises:
                CipherionError: If passphrase is missing or input is invalid.

            Example:
                >>> result = client.migrate_decrypt(encrypted_list)
        """
        passphrase = self._config.passphrase

        if not passphrase:
            raise CipherionError("Passphrase is required for migration", 400)
        if not isinstance(encrypted_array, list):
            raise CipherionError("encrypted_array must be a list", 400)

        if len(encrypted_array) == 0:
            self._logger.warn("Empty list provided for decryption migration")
            return MigrationResult(
                successful=[],
                failed=[],
                summary=MigrationProgress(total=0, processed=0, successful=0, failed=0, percentage=100.0),
            )

        if self._config.enable_logging:
            self._logger.log_migration_operation("migrateDecrypt", "started", {
                "totalItems": len(encrypted_array),
                "batchSize": options.batch_size if options else 10,
            })

        try:
            result = self._migration_helper.decrypt_migration(encrypted_array, passphrase, options)

            if self._config.enable_logging:
                self._logger.log_migration_operation("migrateDecrypt", "completed", {
                    "totalItems": result.summary.total,
                    "processed": result.summary.processed,
                    "successful": result.summary.successful,
                    "failed": result.summary.failed,
                    "percentage": result.summary.percentage,
                })

            return result

        except Exception as exc:
            if self._config.enable_logging:
                self._logger.log_migration_operation("migrateDecrypt", "error", {
                    "totalItems": len(encrypted_array),
                    "errorMessage": str(exc),
                })
            raise

    def get_config(self) -> dict:
        """Returns the current client configuration without sensitive fields.

            Sensitive values like api_key and passphrase are intentionally omitted.

            Returns:
                dict: Safe configuration dictionary
        """
        return {
            "base_url": self._config.base_url,
            "project_id": self._config.project_id,
            "timeout": self._config.timeout,
            "retries": self._config.retries,
            "log_level": self._config.log_level,
            "enable_logging": self._config.enable_logging,
        }

    def update_config(self, new_config: dict) -> None:
        """ Updates non-sensitive configuration fields.

            Note:
                api_key and passphrase cannot be updated after initialization.
                Attempting to update them will raise an error.

            Args:
                new_config (dict): Configuration fields to update.

            Raises:
                CipherionError: If attempting to update sensitive credentials.
        """
        if "api_key" in new_config or "passphrase" in new_config:
            self._logger.warn("Attempted to update sensitive credentials - operation ignored")
            raise CipherionError(
                "Cannot update api_key or passphrase after initialization. "
                "Create a new client instance instead.",
                403,
            )

        safe_fields = {k: v for k, v in new_config.items() if k not in ("api_key", "passphrase")}
        for key, value in safe_fields.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)

        Validator.validate_config(self._config)

        if "base_url" in safe_fields or "timeout" in safe_fields:
            self._http_client = self._make_http_client()

        if self._config.enable_logging:
            self._logger.info("Configuration updated", {"updatedFields": list(safe_fields.keys())})