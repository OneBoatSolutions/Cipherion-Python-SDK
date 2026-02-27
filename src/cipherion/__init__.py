"""
__init__.py - Python 3 port of src/index.ts.

Exposes the full public API of the Cipherion SDK from a single import point.

Usage:
    from cipherion import CipherionClient
    from cipherion import CipherionError
    from cipherion import CipherionConfig, MigrationOptions, ...
"""

from .client.cipherion_client import CipherionClient
from .errors.cipherion_error import CipherionError

from .types.api import (
    BaseResponse,
    EncryptData,
    EncryptResponse,
    DecryptData,
    DecryptResponse,
    EncryptionMetadata,
    DecryptionMetadata,
    DeepEncryptMeta,
    DeepEncryptData,
    DeepEncryptResponse,
    DeepDecryptMeta,
    DeepDecryptData,
    DeepDecryptResponse,
    ErrorDetail,
    ErrorResponse,
    DeepEncryptOptions,
    DeepDecryptOptions,
    EncryptRequest,
    DecryptRequest,
    DeepEncryptRequest,
    DeepDecryptRequest,
    DetectedEntity,
    AnonymizeRequest,
    AnonymizeStatistics,
    AnonymizeData,
    AnonymizeResponse,
)

from .types.client import (
    LogLevel,
    CipherionConfig,
    ExclusionOptions,
    MigrationOptions,
    MigrationProgress,
    FailedMigrationItem,
    MigrationResult,
)

default = CipherionClient

__all__ = [
    "CipherionClient",
    "CipherionError",
    "BaseResponse",
    "EncryptData",
    "EncryptResponse",
    "DecryptData",
    "DecryptResponse",
    "EncryptionMetadata",
    "DecryptionMetadata",
    "DeepEncryptMeta",
    "DeepEncryptData",
    "DeepEncryptResponse",
    "DeepDecryptMeta",
    "DeepDecryptData",
    "DeepDecryptResponse",
    "ErrorDetail",
    "ErrorResponse",
    "DeepEncryptOptions",
    "DeepDecryptOptions",
    "EncryptRequest",
    "DecryptRequest",
    "DeepEncryptRequest",
    "DeepDecryptRequest",
    "DetectedEntity",
    "AnonymizeRequest",
    "AnonymizeStatistics",
    "AnonymizeData",
    "AnonymizeResponse",
    "LogLevel",
    "CipherionConfig",
    "ExclusionOptions",
    "MigrationOptions",
    "MigrationProgress",
    "FailedMigrationItem",
    "MigrationResult",
    "default",
]