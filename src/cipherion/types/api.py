"""
api_types.py - Python 3 port of the TypeScript api.ts type definitions.

TypeScript interfaces → Python dataclasses with full typing.
All fields match the original structure and names exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

@dataclass
class BaseResponse:
    success: bool
    status_code: int
    message: str


# ---------------------------------------------------------------------------
# Simple encrypt / decrypt
# ---------------------------------------------------------------------------

@dataclass
class EncryptData:
    encrypted_output: str


@dataclass
class EncryptResponse(BaseResponse):
    data: EncryptData = field(default_factory=lambda: EncryptData(encrypted_output=""))


@dataclass
class DecryptData:
    plaintext: str


@dataclass
class DecryptResponse(BaseResponse):
    data: DecryptData = field(default_factory=lambda: DecryptData(plaintext=""))


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

@dataclass
class EncryptionMetadata:
    excluded_fields: list[str]
    excluded_patterns: list[str]
    operation: str


@dataclass
class DecryptionMetadata:
    excluded_fields: list[str]
    excluded_patterns: list[str]
    failed_fields: list[str]
    fail_gracefully: bool
    operation: str


# ---------------------------------------------------------------------------
# Deep encrypt / decrypt
# ---------------------------------------------------------------------------

@dataclass
class DeepEncryptMeta:
    encryption_metadata: EncryptionMetadata
    total_fields: int
    billable_fields: int
    total_price: float


@dataclass
class DeepEncryptData:
    encrypted: Any
    meta: DeepEncryptMeta


@dataclass
class DeepEncryptResponse(BaseResponse):
    data: Optional[DeepEncryptData] = None


@dataclass
class DeepDecryptMeta:
    decryption_metadata: DecryptionMetadata
    total_fields: int
    billable_fields: int
    total_price: float


@dataclass
class DeepDecryptData:
    data: Any
    meta: DeepDecryptMeta


@dataclass
class DeepDecryptResponse(BaseResponse):
    data: Optional[DeepDecryptData] = None


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------

@dataclass
class ErrorDetail:
    details: str


@dataclass
class ErrorResponse(BaseResponse):
    error: ErrorDetail = field(default_factory=lambda: ErrorDetail(details=""))


# ---------------------------------------------------------------------------
# Request / option types
# ---------------------------------------------------------------------------

@dataclass
class DeepEncryptOptions:
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None


@dataclass
class DeepDecryptOptions:
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    fail_gracefully: Optional[bool] = None


@dataclass
class EncryptRequest:
    data: str
    passphrase: str


@dataclass
class DecryptRequest:
    data: str
    passphrase: str


@dataclass
class DeepEncryptRequest:
    data: Any
    passphrase: str
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None


@dataclass
class DeepDecryptRequest:
    encrypted: Any
    passphrase: str
    exclude_fields: Optional[list[str]] = None
    exclude_patterns: Optional[list[str]] = None
    fail_gracefully: Optional[bool] = None


# ---------------------------------------------------------------------------
# Anonymization
# ---------------------------------------------------------------------------

@dataclass
class DetectedEntity:
    text: str
    type: str
    score: float
    start: int
    end: int


@dataclass
class AnonymizeRequest:
    text: str
    score_threshold: Optional[float] = None
    entities_to_detect: Optional[list[str]] = None
    allow_overlaps: Optional[bool] = None
    context_validation: Optional[bool] = None


@dataclass
class AnonymizeStatistics:
    """Maps entity-type label → count, equivalent to { [key: string]: number }."""
    counts: dict[str, int] = field(default_factory=dict)

    def __getitem__(self, key: str) -> int:
        return self.counts[key]

    def __setitem__(self, key: str, value: int) -> None:
        self.counts[key] = value


@dataclass
class AnonymizeData:
    anonymized_text: str
    entity_count: int
    entities: list[DetectedEntity]
    statistics: dict[str, int]
    processing_time_ms: float


@dataclass
class AnonymizeResponse(BaseResponse):
    data: Optional[AnonymizeData] = None