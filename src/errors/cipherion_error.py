"""
CipherionError - Python 3 port of the TypeScript CipherionError class.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional


class CipherionError(Exception):
    """
    Custom exception for the Cipherion SDK.

    Attributes:
        message:        Human-readable error description.
        status_code:    HTTP-style status code (0 for network/config errors).
        details:        Optional additional context about the failure.
        original_error: The underlying exception that caused this error, if any.
        timestamp:      ISO-8601 UTC timestamp of when the error was created.
    """

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        details: Optional[str] = None,
        original_error: Optional[Exception] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details
        self.original_error = original_error
        self.timestamp: str = datetime.now(timezone.utc).isoformat()

    def __repr__(self) -> str:
        return (
            f"CipherionError(message={self.message!r}, "
            f"status_code={self.status_code}, "
            f"timestamp={self.timestamp!r})"
        )

    # ------------------------------------------------------------------
    # Factory class methods
    # ------------------------------------------------------------------

    @classmethod
    def from_response(cls, response: Any) -> "CipherionError":
        """
        Creates a CipherionError from an API response payload.
        Sanitizes response data to prevent sensitive info leakage.
        """
        message: str = (
            response.get("message", "Unknown API error")
            if isinstance(response, dict)
            else "Unknown API error"
        )
        status_code: int = (
            response.get("statusCode", 500)
            if isinstance(response, dict)
            else 500
        )
        details: Optional[str] = (
            (response.get("error") or {}).get("details")
            if isinstance(response, dict)
            else None
        )

        return cls(message, status_code, details)

    @classmethod
    def from_requests_error(cls, error: Exception) -> "CipherionError":
        """
        Creates a CipherionError from a ``requests`` library exception.
        Handles HTTP response errors, connection errors, and configuration errors.

        Mirrors the behaviour of ``fromAxiosError`` in the TypeScript source:
        - Response received  → extract status + body message
        - No response (network) → status 0, connectivity hint
        - Config / other        → status 0, raw exception message
        """
        import requests  # local import to keep the module usable without requests installed

        # HTTP error with a response (4xx / 5xx)
        if isinstance(error, requests.HTTPError) and error.response is not None:
            try:
                body: dict = error.response.json()
            except Exception:
                body = {}

            message: str = body.get("message", "API request failed")
            status_code: int = error.response.status_code
            details: Optional[str] = (body.get("error") or {}).get("details")

            return cls(message, status_code, details, error)

        # Network / connectivity error — no response received
        if isinstance(error, (requests.ConnectionError, requests.Timeout)):
            return cls(
                "Network error - unable to reach server",
                0,
                "Check your internet connection and firewall settings",
                error,
            )

        # Request configuration or any other requests exception
        return cls(
            "Request configuration error",
            0,
            str(error),
            error,
        )

    # ------------------------------------------------------------------
    # Instance methods
    # ------------------------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """
        Converts the error to a safe dictionary suitable for logging.
        Excludes stack traces and sensitive data.
        """
        return {
            "name": type(self).__name__,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def get_user_message(self) -> str:
        """Returns a user-friendly error message based on the status code."""
        if self.status_code >= 500:
            return "An internal server error occurred. Please try again later."

        if self.status_code in (401, 403):
            return "Authentication failed. Please check your API credentials."

        if self.status_code == 429:
            return "Rate limit exceeded. Please wait before retrying."

        return self.message

    def is_retryable(self) -> bool:
        """
        Returns True when the error is safe to retry.
        Network errors (0), rate-limit (429), and 5xx server errors are retryable.
        """
        return (
            self.status_code == 0
            or self.status_code == 429
            or 500 <= self.status_code < 600
        )