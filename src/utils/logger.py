"""
logger.py - Python 3 port of the TypeScript CipherionLogger (src/utils/logger.ts).

Replaces winston with Python's built-in ``logging`` module and a rotating
file handler that mirrors winston's maxsize / maxFiles behaviour.
"""

from __future__ import annotations

import json
import logging
import os
import re
import traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Literal, Optional


# ---------------------------------------------------------------------------
# Type aliases (mirror TypeScript union literals)
# ---------------------------------------------------------------------------

CryptoOperation = Literal["encrypt", "decrypt", "deepEncrypt", "deepDecrypt"]
CryptoStatus    = Literal["success", "error"]
MigrateOp       = Literal["migrateEncrypt", "migrateDecrypt"]
MigrateStage    = Literal["started", "completed", "error"]


# ---------------------------------------------------------------------------
# CipherionLogger
# ---------------------------------------------------------------------------

class CipherionLogger:
    """
    Structured logger for the Cipherion SDK.

    * Writes ``error.log`` (ERROR only) and ``combined.log`` (all levels)
      under ``cipherion-logs/`` with 10 MB rotation, 5 back-ups.
    * Adds a colourised console handler when ``NODE_ENV != production``
      (or the Python equivalent: when the ``CIPHERION_ENV`` env-var is
      not ``"production"``).
    * Sanitises sensitive keys and truncates long string values before
      emitting any log line.
    """

    LOG_DIR: str = "cipherion-logs"
    MAX_BYTES: int = 10_485_760   # 10 MB
    BACKUP_COUNT: int = 5
    MAX_DEPTH: int = 5

    _SENSITIVE_PATTERNS: list[re.Pattern] = [
        re.compile(r"passphrase",    re.IGNORECASE),
        re.compile(r"password",      re.IGNORECASE),
        re.compile(r"api[_\-]?key",  re.IGNORECASE),
        re.compile(r"secret",        re.IGNORECASE),
        re.compile(r"token",         re.IGNORECASE),
        re.compile(r"authorization", re.IGNORECASE),
        re.compile(r"credential",    re.IGNORECASE),
    ]

    _LEVEL_MAP: dict[str, int] = {
        "error": logging.ERROR,
        "warn":  logging.WARNING,
        "info":  logging.INFO,
        "debug": logging.DEBUG,
    }

    def __init__(self, log_level: str = "info") -> None:
        self._ensure_log_directory()
        self._logger = self._create_logger(log_level)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _ensure_log_directory(self) -> None:
        try:
            Path(self.LOG_DIR).mkdir(parents=True, exist_ok=True, mode=0o750)
        except OSError as exc:
            print(f"Failed to create log directory: {exc}")

    def _create_logger(self, log_level: str) -> logging.Logger:
        level = self._LEVEL_MAP.get(log_level.lower(), logging.INFO)

        # Use a unique logger name to avoid collisions with the root logger
        logger = logging.getLogger(f"cipherion.{id(self)}")
        logger.setLevel(logging.DEBUG)   # handlers filter by their own level
        logger.propagate = False

        fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # error.log — ERROR only
        error_handler = RotatingFileHandler(
            filename=os.path.join(self.LOG_DIR, "error.log"),
            maxBytes=self.MAX_BYTES,
            backupCount=self.BACKUP_COUNT,
            encoding="utf-8",
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(fmt)
        logger.addHandler(error_handler)

        # combined.log — all levels
        combined_handler = RotatingFileHandler(
            filename=os.path.join(self.LOG_DIR, "combined.log"),
            maxBytes=self.MAX_BYTES,
            backupCount=self.BACKUP_COUNT,
            encoding="utf-8",
        )
        combined_handler.setLevel(level)
        combined_handler.setFormatter(fmt)
        logger.addHandler(combined_handler)

        # Console — non-production only
        if os.environ.get("CIPHERION_ENV") != "production":
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(_ColourisedFormatter(
                fmt="%(asctime)s [%(levelname)s]: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            logger.addHandler(console_handler)

        return logger

    # ------------------------------------------------------------------
    # Sanitisation helpers
    # ------------------------------------------------------------------

    def _is_sensitive_key(self, key: str) -> bool:
        return any(p.search(key) for p in self._SENSITIVE_PATTERNS)

    def _sanitize_metadata(self, obj: Any, depth: int = 0) -> Any:
        if depth > self.MAX_DEPTH or obj is None:
            return obj

        if isinstance(obj, list):
            return [self._sanitize_metadata(item, depth + 1) for item in obj]

        if isinstance(obj, dict):
            sanitized: dict = {}
            for key, value in obj.items():
                if self._is_sensitive_key(str(key)):
                    sanitized[key] = "[REDACTED]"
                elif isinstance(value, (dict, list)):
                    sanitized[key] = self._sanitize_metadata(value, depth + 1)
                elif isinstance(value, str) and len(value) > 100:
                    sanitized[key] = value[:100] + "...[TRUNCATED]"
                else:
                    sanitized[key] = value
            return sanitized

        return obj

    def _sanitize_error(self, error: Any) -> Optional[dict]:
        if error is None:
            return None

        root_error = getattr(error, "original_error", None) or error
        sanitized: dict[str, Any] = {
            "message": getattr(error, "message", None) or str(error) or "Unknown error",
        }

        # requests HTTPError with a response attached
        response = getattr(root_error, "response", None)
        if response is not None:
            sanitized["status"]     = getattr(response, "status_code", None)
            sanitized["statusText"] = getattr(response, "reason", None)
            sanitized["method"]     = getattr(
                getattr(response, "request", None), "method", None
            )
            try:
                body = response.json()
                sanitized["apiError"] = {
                    "message": body.get("message"),
                    "code":    body.get("code"),
                }
            except Exception:
                pass

        # Network / connection error (no response)
        elif isinstance(root_error, OSError):
            sanitized["type"] = "NetworkError"
            sanitized["code"] = getattr(root_error, "errno", None)

        # Standard Python exception
        else:
            sanitized["name"] = type(error).__name__
            if os.environ.get("CIPHERION_ENV") != "production":
                lines = traceback.format_exception(type(error), error, error.__traceback__)
                if lines:
                    sanitized["stackFirstLine"] = lines[0].rstrip()

        return sanitized

    # ------------------------------------------------------------------
    # Meta → string helper
    # ------------------------------------------------------------------

    @staticmethod
    def _meta_to_str(meta: dict) -> str:
        return ", ".join(
            f"{k}={json.dumps(v)}" for k, v in meta.items()
        )

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def info(self, message: str, meta: Optional[dict] = None) -> None:
        if meta:
            sanitized = self._sanitize_metadata(meta)
            self._logger.info("%s | %s", message, self._meta_to_str(sanitized))
        else:
            self._logger.info(message)

    def error(self, message: str, error: Any = None, meta: Optional[dict] = None) -> None:
        parts = [message]

        sanitized_error = self._sanitize_error(error)
        if sanitized_error:
            parts.append(f"error={json.dumps(sanitized_error)}")

        if meta:
            sanitized_meta = self._sanitize_metadata(meta)
            parts.append(self._meta_to_str(sanitized_meta))

        self._logger.error(" | ".join(parts))

    def warn(self, message: str, meta: Optional[dict] = None) -> None:
        if meta:
            sanitized = self._sanitize_metadata(meta)
            self._logger.warning("%s | %s", message, self._meta_to_str(sanitized))
        else:
            self._logger.warning(message)

    def debug(self, message: str, meta: Optional[dict] = None) -> None:
        if os.environ.get("CIPHERION_ENV") == "production":
            return
        if meta:
            sanitized = self._sanitize_metadata(meta)
            self._logger.debug("%s | %s", message, self._meta_to_str(sanitized))
        else:
            self._logger.debug(message)

    # ------------------------------------------------------------------
    # Structured operation loggers
    # ------------------------------------------------------------------

    def log_crypto_operation(
        self,
        operation: CryptoOperation,
        status: CryptoStatus,
        metadata: dict[str, Any],
    ) -> None:
        """
        Emits a single-line log for a crypto operation.

        Expected metadata keys (all optional):
            data_type, data_length, total_fields, billable_fields,
            excluded_fields, excluded_patterns, failed_fields,
            fail_gracefully, duration_ms, status_code, error_message
        """
        level = logging.ERROR if status == "error" else logging.INFO

        parts: list[str] = [f"operation={operation}", f"status={status}"]

        _append_if(parts, metadata, "dataType",         "dataType")
        _append_if(parts, metadata, "dataLength",       "dataLength")
        _append_if(parts, metadata, "totalFields",      "totalFields")
        _append_if(parts, metadata, "billableFields",   "billableFields")
        _append_if(parts, metadata, "excludedFields",   "excludedFields")
        _append_if(parts, metadata, "excludedPatterns", "excludedPatterns")
        _append_if(parts, metadata, "failedFields",     "failedFields")
        _append_if(parts, metadata, "failGracefully",   "failGracefully")
        _append_if(parts, metadata, "durationMs",       "durationMs")
        _append_if(parts, metadata, "statusCode",       "statusCode")

        if metadata.get("errorMessage"):
            parts.append(f'error="{metadata["errorMessage"]}"')

        self._logger.log(level, " | ".join(parts))

    def log_migration_operation(
        self,
        operation: MigrateOp,
        stage: MigrateStage,
        metadata: dict[str, Any],
    ) -> None:
        """
        Emits a single-line log for a migration operation.

        Expected metadata keys (all optional):
            total_items, processed, successful, failed, percentage,
            batch_size, current_batch, error_message
        """
        level = logging.ERROR if stage == "error" else logging.INFO

        parts: list[str] = [f"operation={operation}", f"stage={stage}"]

        _append_if(parts, metadata, "totalItems",    "totalItems")
        _append_if(parts, metadata, "processed",     "processed")
        _append_if(parts, metadata, "successful",    "successful")
        _append_if(parts, metadata, "failed",        "failed")
        _append_if(parts, metadata, "batchSize",     "batchSize")
        _append_if(parts, metadata, "currentBatch",  "currentBatch")

        if metadata.get("percentage") is not None:
            parts.append(f'percentage={metadata["percentage"]:.2f}%')

        if metadata.get("errorMessage"):
            parts.append(f'error="{metadata["errorMessage"]}"')

        self._logger.log(level, " | ".join(parts))


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _append_if(parts: list[str], meta: dict, key: str, label: str) -> None:
    """Appends ``label=value`` to *parts* when *key* is present and not None."""
    value = meta.get(key)
    if value is not None:
        parts.append(f"{label}={value}")


class _ColourisedFormatter(logging.Formatter):
    """
    Mimics winston's colorize() transport for the console handler.
    Falls back gracefully when the terminal does not support ANSI codes.
    """

    _COLOURS: dict[int, str] = {
        logging.DEBUG:   "\033[36m",    # cyan
        logging.INFO:    "\033[32m",    # green
        logging.WARNING: "\033[33m",    # yellow
        logging.ERROR:   "\033[31m",    # red
        logging.CRITICAL:"\033[35m",    # magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        colour = self._COLOURS.get(record.levelno, "")
        record.levelname = f"{colour}{record.levelname}{self._RESET}"
        return super().format(record)