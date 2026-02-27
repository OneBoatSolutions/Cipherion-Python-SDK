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
        """
            Initialize a new CipherionError instance.

            Args:
                message (str): Human-readable error message.
                status_code (int, optional):
                    HTTP-style status code. Defaults to 500.
                    Use 0 for network/client-side errors.
                details (Optional[str], optional):
                    Additional context about the error.
                original_error (Optional[Exception], optional):
                    The underlying exception that caused this error.

            Example:
                >>> raise CipherionError(
                ...     "API request failed",
                ...     status_code=500,
                ...     details="Upstream timeout"
                ... )
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details
        self.original_error = original_error
        self.timestamp: str = datetime.now(timezone.utc).isoformat()

    def __repr__(self) -> str:
        """
            Return a developer-friendly representation of the error.

            Returns:
                str: Debug representation including message, status code,
                and timestamp.
        """
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
         Create a CipherionError from an API response payload.

        This method safely extracts error information from the server
        response while avoiding accidental leakage of sensitive data.

        Args:
            response (Any): Parsed JSON response from the API.

        Returns:
            CipherionError: Normalized SDK error instance.

        Behavior:
            - Extracts `message` if present
            - Extracts `statusCode` if present
            - Extracts nested error details when available
            - Falls back to safe defaults if parsing fails

        Example:
            >>> err = CipherionError.from_response(api_response)
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
        Create a CipherionError from a ``requests`` library exception.

        This method normalizes different categories of network failures:

        Cases handled:
            1. HTTP response errors (4xx / 5xx)
            2. Network/connectivity failures
            3. Timeout errors
            4. Request configuration errors

        Args:
            error (Exception): Exception raised by the requests library.

        Returns:
            CipherionError: Normalized SDK error.

        Notes:
            - HTTP errors preserve server status codes.
            - Network errors use status_code = 0.
            - Mirrors the behavior of the TypeScript
            ``fromAxiosError`` implementation.

        Example:
            >>> try:
            ...     requests.get(url)
            ... except Exception as e:
            ...     raise CipherionError.from_requests_error(e)
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
            Convert the error into a safe, serializable dictionary.

            Intended for structured logging and telemetry. Sensitive data
            such as stack traces are intentionally excluded.

            Returns:
                dict[str, Any]: JSON-safe error representation.

            Example:
                >>> logger.error(error.to_json())
        """
        return {
            "name": type(self).__name__,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    def get_user_message(self) -> str:
        """  Return a user-friendly error message.

            This method maps internal error states to messages suitable
            for display in UI or client applications.

            Returns:
                str: Human-friendly error message.

            Behavior:
                - 5xx → generic server error message
                - 401/403 → authentication guidance
                - 429 → rate limit guidance
                - otherwise → original message

            Example:
                >>> print(error.get_user_message())
        """
        if self.status_code >= 500:
            return "An internal server error occurred. Please try again later."

        if self.status_code in (401, 403):
            return "Authentication failed. Please check your API credentials."

        if self.status_code == 429:
            return "Rate limit exceeded. Please wait before retrying."

        return self.message

    def is_retryable(self) -> bool:
        """
        Determine whether the failed operation is safe to retry.

        Retryable conditions include:

        - Network failures (status_code == 0)
        - Rate limiting (429)
        - Server errors (5xx)

        Returns:
            bool: True if the operation can be retried safely.

        Example:
            >>> if error.is_retryable():
            ...     retry_operation()
        """
        return (
            self.status_code == 0
            or self.status_code == 429
            or 500 <= self.status_code < 600
        )