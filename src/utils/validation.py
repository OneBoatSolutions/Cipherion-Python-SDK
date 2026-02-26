"""
validation.py - Python 3 port of the TypeScript Validator (src/utils/validation.ts).
"""

from __future__ import annotations

from typing import Any

from ..errors.cipherion_error import CipherionError
from ..types.client import CipherionConfig


class Validator:

    @staticmethod
    def validate_config(config: CipherionConfig) -> None:
        if not config.base_url:
            raise CipherionError("Base URL is required", 400)
        if not config.project_id:
            raise CipherionError("Project ID is required", 400)
        if not config.api_key:
            raise CipherionError("API Key is required", 400)

    @staticmethod
    def validate_passphrase(passphrase: str) -> None:
        if not passphrase or len(passphrase) < 12:
            raise CipherionError("Passphrase must be at least 12 characters long", 400)

    @staticmethod
    def validate_data(data: Any) -> None:
        if data is None:
            raise CipherionError("Data cannot be null or undefined", 400)

    @staticmethod
    def validate_encrypted_data(encrypted: Any) -> None:
        if not encrypted:
            raise CipherionError("Encrypted data is required for decryption", 400)