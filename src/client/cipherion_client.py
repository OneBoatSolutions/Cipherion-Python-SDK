"""
CipherionClient - Python 3 port of the TypeScript CipherionClient
"""

from __future__ import annotations

import os
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Types / dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CipherionConfig:
    base_url: str = ""
    project_id: str = ""
    api_key: str = ""
    passphrase: str = ""
    timeout: int = 30_000          # milliseconds, kept consistent with TS
    retries: int = 3
    log_level: str = "info"
    enable_logging: bool = True


@dataclass
class MigrationOptions:
    batch_size: int = 10
    retries: int = 3
    delay_between_batches_ms: int = 0


@dataclass
class MigrationSummary:
    total: int
    processed: int
    successful: int
    failed: int
    percentage: float


@dataclass
class MigrationResult:
    successful: list[Any]
    failed: list[Any]
    summary: MigrationSummary


@dataclass
class DeepEncryptOptions:
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None


@dataclass
class DeepDecryptOptions:
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    fail_gracefully: Optional[bool] = None


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class CipherionError(Exception):
    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover
        return f"CipherionError(message={self.message!r}, status_code={self.status_code})"


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

class CipherionLogger:
    _LEVEL_MAP = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }

    def __init__(self, log_level: str = "info") -> None:
        self._logger = logging.getLogger("cipherion")
        level = self._LEVEL_MAP.get(log_level.lower(), logging.INFO)
        self._logger.setLevel(level)
        if not self._logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
            self._logger.addHandler(handler)

    def info(self, msg: str, extra: Optional[dict] = None) -> None:
        self._logger.info(msg, extra=extra or {})

    def warn(self, msg: str, extra: Optional[dict] = None) -> None:
        self._logger.warning(msg, extra=extra or {})

    def error(self, msg: str, extra: Optional[dict] = None) -> None:
        self._logger.error(msg, extra=extra or {})

    def log_crypto_operation(self, operation: str, status: str, details: dict) -> None:
        self._logger.info("[CryptoOp] %s | %s | %s", operation, status, details)

    def log_migration_operation(self, operation: str, status: str, details: dict) -> None:
        self._logger.info("[MigrationOp] %s | %s | %s", operation, status, details)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class HttpClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_ms: int,
        logger: CipherionLogger,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_ms / 1_000  # convert ms → seconds for requests lib
        self._logger = logger
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "x-api-key": self._api_key,
            "User-Agent": "Cipherion-SDK/1.0",

        })

    def post(self, path: str, body: dict) -> dict:
        url = f"{self._base_url}{path}"
        try:
            response = self._session.post(url, json=body, timeout=self._timeout)
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 500
            try:
                server_message = exc.response.json().get("message", str(exc))
            except Exception:
                server_message = str(exc)
            raise CipherionError(server_message, status) from exc
        except requests.RequestException as exc:
            raise CipherionError(str(exc), 500) from exc


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class Validator:
    @staticmethod
    def validate_config(config: CipherionConfig) -> None:
        if not config.base_url:
            raise CipherionError("baseUrl is required", 400)
        if not config.project_id:
            raise CipherionError("projectId is required", 400)
        if not config.api_key:
            raise CipherionError("apiKey is required", 400)

    @staticmethod
    def validate_data(data: Any) -> None:
        if data is None:
            raise CipherionError("Data cannot be null/None", 400)

    @staticmethod
    def validate_encrypted_data(data: Any) -> None:
        if data is None:
            raise CipherionError("Encrypted data cannot be null/None", 400)

    @staticmethod
    def validate_passphrase(passphrase: str) -> None:
        if not passphrase:
            raise CipherionError("Passphrase cannot be empty", 400)


# ---------------------------------------------------------------------------
# Migration helper
# ---------------------------------------------------------------------------

class MigrationHelper:
    def __init__(self, client: "CipherionClient") -> None:
        self._client = client

    def encrypt_migration(
        self,
        data_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        return self._run_migration(
            data_array,
            passphrase,
            operation="encrypt",
            options=options,
        )

    def decrypt_migration(
        self,
        encrypted_array: list[Any],
        passphrase: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        return self._run_migration(
            encrypted_array,
            passphrase,
            operation="decrypt",
            options=options,
        )

    def _run_migration(
        self,
        items: list[Any],
        passphrase: str,
        operation: str,
        options: Optional[MigrationOptions] = None,
    ) -> MigrationResult:
        import math

        batch_size = options.batch_size if options else 10
        successful: list[Any] = []
        failed: list[Any] = []

        for i in range(0, len(items), batch_size):
            batch = items[i : i + batch_size]
            for item in batch:
                try:
                    if operation == "encrypt":
                        result = self._client.deep_encrypt(item)
                    else:
                        result = self._client.deep_decrypt(item)
                    successful.append(result)
                except Exception as exc:
                    failed.append({"item": item, "error": str(exc)})

            if (
                options
                and options.delay_between_batches_ms > 0
                and i + batch_size < len(items)
            ):
                time.sleep(options.delay_between_batches_ms / 1_000)

        total = len(items)
        processed = len(successful) + len(failed)
        percentage = (len(successful) / total * 100) if total > 0 else 100.0

        return MigrationResult(
            successful=successful,
            failed=failed,
            summary=MigrationSummary(
                total=total,
                processed=processed,
                successful=len(successful),
                failed=len(failed),
                percentage=round(percentage, 2),
            ),
        )


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------

class CipherionClient:
    def __init__(self, config: Optional[dict] = None) -> None:
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
        return HttpClient(
            self._config.base_url,
            self._config.api_key,
            self._config.timeout,
            self._logger,
        )

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
    # Public API
    # ------------------------------------------------------------------

    def encrypt(self, data: str) -> str:
        """Encrypts a simple string."""
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
        """Decrypts a simple string."""
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
        """Encrypts complex data structures while preserving structure."""
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
        """Decrypts complex data structures encrypted with deep_encrypt."""
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
        """Encrypts an array of items in batches."""
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
                summary=MigrationSummary(total=0, processed=0, successful=0, failed=0, percentage=100.0),
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
        """Decrypts an array of encrypted items in batches."""
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
                summary=MigrationSummary(total=0, processed=0, successful=0, failed=0, percentage=100.0),
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
        """Returns the current configuration without sensitive fields."""
        return {
            "base_url": self._config.base_url,
            "project_id": self._config.project_id,
            "timeout": self._config.timeout,
            "retries": self._config.retries,
            "log_level": self._config.log_level,
            "enable_logging": self._config.enable_logging,
        }

    def update_config(self, new_config: dict) -> None:
        """Updates non-sensitive configuration fields."""
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