"""Core module initialization."""

from filanti.core.errors import (
    FilantiError,
    FileOperationError,
    HashingError,
    ValidationError,
    SecretError,
)
from filanti.core.file_manager import FileManager
from filanti.core.metadata import FileMetadata
from filanti.core.secrets import (
    resolve_secret,
    resolve_secret_bytes,
    resolve_secret_optional,
    is_env_reference,
    get_env_var_name,
    redact_secret,
    redact_secrets,
    create_safe_json_output,
    validate_env_reference,
    REDACTED_PLACEHOLDER,
)

__all__ = [
    "FilantiError",
    "FileOperationError",
    "HashingError",
    "ValidationError",
    "SecretError",
    "FileManager",
    "FileMetadata",
    # Secrets
    "resolve_secret",
    "resolve_secret_bytes",
    "resolve_secret_optional",
    "is_env_reference",
    "get_env_var_name",
    "redact_secret",
    "redact_secrets",
    "create_safe_json_output",
    "validate_env_reference",
    "REDACTED_PLACEHOLDER",
]

