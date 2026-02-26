"""
client_types.py - Python 3 port of the TypeScript client.ts type definitions.

TypeScript interfaces → Python dataclasses with full typing.
Callback fields use Callable from typing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LogLevel = Literal["error", "warn", "info", "debug"]


@dataclass
class CipherionConfig:
    base_url: str
    project_id: str
    api_key: str
    passphrase: str
    timeout: Optional[int] = None
    retries: Optional[int] = None
    log_level: Optional[LogLevel] = None
    enable_logging: Optional[bool] = None


# ---------------------------------------------------------------------------
# Exclusion options
# ---------------------------------------------------------------------------

@dataclass
class ExclusionOptions:
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    fail_gracefully: Optional[bool] = None


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

@dataclass
class MigrationProgress:
    total: int
    processed: int
    successful: int
    failed: int
    percentage: float


@dataclass
class FailedMigrationItem:
    """Mirrors Array<{ item: any; error: Error }> entries."""
    item: Any
    error: Exception


@dataclass
class MigrationOptions:
    batch_size: Optional[int] = None
    delay_between_batches: Optional[int] = None
    max_retries: Optional[int] = None
    on_progress: Optional[Callable[[MigrationProgress], None]] = None
    on_error: Optional[Callable[[Exception, Any], None]] = None
    exclusion_options: Optional[ExclusionOptions] = None


@dataclass
class MigrationResult:
    successful: list[Any] = field(default_factory=list)
    failed: list[FailedMigrationItem] = field(default_factory=list)
    summary: MigrationProgress = field(
        default_factory=lambda: MigrationProgress(
            total=0, processed=0, successful=0, failed=0, percentage=0.0
        )
    )