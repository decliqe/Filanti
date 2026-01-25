"""
Filanti error hierarchy.

All Filanti exceptions inherit from FilantiError, providing a consistent
error handling interface across the framework.
"""

from typing import Any


class FilantiError(Exception):
    """Base exception for all Filanti errors.

    Provides a consistent interface for error handling with optional
    context information for debugging and logging.
    """

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        """Initialize FilantiError.

        Args:
            message: Human-readable error message.
            context: Optional dictionary with additional error context.
        """
        super().__init__(message)
        self.message = message
        self.context = context or {}

    def __str__(self) -> str:
        if self.context:
            context_str = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} [{context_str}]"
        return self.message

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.message!r}, context={self.context!r})"


class FileOperationError(FilantiError):
    """Error during file operations (read, write, delete, etc.)."""

    def __init__(
        self,
        message: str,
        path: str | None = None,
        operation: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize FileOperationError.

        Args:
            message: Human-readable error message.
            path: Path to the file that caused the error.
            operation: Name of the operation that failed.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if path:
            ctx["path"] = path
        if operation:
            ctx["operation"] = operation
        super().__init__(message, ctx)
        self.path = path
        self.operation = operation


class HashingError(FilantiError):
    """Error during hashing operations."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize HashingError.

        Args:
            message: Human-readable error message.
            algorithm: Name of the hashing algorithm.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
        super().__init__(message, ctx)
        self.algorithm = algorithm


class ValidationError(FilantiError):
    """Error during validation operations (integrity checks, signature verification)."""

    def __init__(
        self,
        message: str,
        expected: str | None = None,
        actual: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize ValidationError.

        Args:
            message: Human-readable error message.
            expected: Expected value (e.g., expected hash).
            actual: Actual value that was found.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if expected:
            ctx["expected"] = expected
        if actual:
            ctx["actual"] = actual
        super().__init__(message, ctx)
        self.expected = expected
        self.actual = actual


class EncryptionError(FilantiError):
    """Error during encryption operations."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize EncryptionError.

        Args:
            message: Human-readable error message.
            algorithm: Name of the encryption algorithm.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
        super().__init__(message, ctx)
        self.algorithm = algorithm


class DecryptionError(FilantiError):
    """Error during decryption operations."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize DecryptionError.

        Args:
            message: Human-readable error message.
            algorithm: Name of the encryption algorithm.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
        super().__init__(message, ctx)
        self.algorithm = algorithm


class KeyError(FilantiError):
    """Error related to cryptographic key operations."""

    def __init__(
        self,
        message: str,
        key_type: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize KeyError.

        Args:
            message: Human-readable error message.
            key_type: Type of key involved.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if key_type:
            ctx["key_type"] = key_type
        super().__init__(message, ctx)
        self.key_type = key_type


class IntegrityError(FilantiError):
    """Error during integrity verification (HMAC, checksum)."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        expected: str | None = None,
        actual: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize IntegrityError.

        Args:
            message: Human-readable error message.
            algorithm: Name of the integrity algorithm.
            expected: Expected integrity value.
            actual: Actual integrity value found.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
        if expected:
            ctx["expected"] = expected
        if actual:
            ctx["actual"] = actual
        super().__init__(message, ctx)
        self.algorithm = algorithm
        self.expected = expected
        self.actual = actual


class SignatureError(FilantiError):
    """Error during digital signature operations."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        operation: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize SignatureError.

        Args:
            message: Human-readable error message.
            algorithm: Name of the signature algorithm.
            operation: Operation that failed (sign, verify).
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if algorithm:
            ctx["algorithm"] = algorithm
        if operation:
            ctx["operation"] = operation
        super().__init__(message, ctx)
        self.algorithm = algorithm
        self.operation = operation


class SecretError(FilantiError):
    """Error during secret resolution operations.

    Raised when environment-based secrets cannot be resolved,
    such as when an ENV variable is not set or is empty.
    """

    def __init__(
        self,
        message: str,
        env_var: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """Initialize SecretError.

        Args:
            message: Human-readable error message.
            env_var: Name of the environment variable.
            context: Optional dictionary with additional error context.
        """
        ctx = context or {}
        if env_var:
            ctx["env_var"] = env_var
        super().__init__(message, ctx)
        self.env_var = env_var


