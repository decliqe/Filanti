"""
Secret resolution module.

Provides secure, runtime-only secret resolution from environment variables.
Secrets are never resolved at import time to prevent accidental exposure.

Usage:
    # Resolve ENV:SECRET_NAME pattern
    password = resolve_secret("ENV:MY_PASSWORD")

    # Check if value is an ENV reference
    if is_env_reference("ENV:SECRET_KEY"):
        ...

    # Redact secrets from output
    safe_output = redact_secret(output_text, secret_value)
"""

import os
import re
from typing import Pattern

from filanti.core.errors import SecretError


# Pattern for ENV-based secret references: ENV:SECRET_NAME
ENV_PATTERN: Pattern[str] = re.compile(r"^ENV:([A-Za-z_][A-Za-z0-9_]*)$")

# Redaction placeholder
REDACTED_PLACEHOLDER = "[REDACTED]"


def is_env_reference(value: str) -> bool:
    """Check if a value is an ENV-based secret reference.

    Args:
        value: String to check.

    Returns:
        True if value matches ENV:SECRET_NAME pattern.
    """
    if value is None:
        return False
    return bool(ENV_PATTERN.match(value))


def get_env_var_name(value: str) -> str | None:
    """Extract environment variable name from ENV reference.

    Args:
        value: ENV reference string (e.g., "ENV:MY_SECRET").

    Returns:
        Environment variable name, or None if not a valid reference.
    """
    match = ENV_PATTERN.match(value)
    return match.group(1) if match else None


def resolve_secret(value: str, allow_empty: bool = False) -> str:
    """Resolve a secret value, handling ENV-based references.

    This function supports runtime-only secret resolution. When a value
    matches the pattern ENV:SECRET_NAME, the actual secret is read from
    the corresponding environment variable at runtime.

    Args:
        value: The value to resolve. Can be:
            - A literal string (returned as-is)
            - An ENV reference (e.g., "ENV:MY_PASSWORD")
        allow_empty: If False (default), raises SecretError for empty values.

    Returns:
        The resolved secret value.

    Raises:
        SecretError: If the environment variable is not set or is empty
                     (when allow_empty=False).

    Example:
        # Set environment variable
        os.environ["ENCRYPTION_KEY"] = "my-secret-key"

        # Resolve it
        key = resolve_secret("ENV:ENCRYPTION_KEY")
        # Returns: "my-secret-key"

        # Literal values pass through unchanged
        literal = resolve_secret("direct-password")
        # Returns: "direct-password"
    """
    if value is None:
        raise SecretError("Secret value cannot be None")

    # Check if this is an ENV reference
    match = ENV_PATTERN.match(value)
    if not match:
        # Not an ENV reference, return as-is
        return value

    # Extract environment variable name
    env_var_name = match.group(1)

    # Resolve from environment at runtime
    resolved = os.environ.get(env_var_name)

    if resolved is None:
        raise SecretError(
            f"Environment variable '{env_var_name}' is not set",
            env_var=env_var_name,
        )

    if not allow_empty and resolved == "":
        raise SecretError(
            f"Environment variable '{env_var_name}' is empty",
            env_var=env_var_name,
        )

    return resolved


def resolve_secret_bytes(
    value: str,
    encoding: str = "utf-8",
    allow_empty: bool = False,
) -> bytes:
    """Resolve a secret and return as bytes.

    Args:
        value: The value to resolve (ENV reference or literal).
        encoding: String encoding (default: utf-8).
        allow_empty: If False (default), raises SecretError for empty values.

    Returns:
        The resolved secret as bytes.

    Raises:
        SecretError: If the environment variable is not set or is empty.
    """
    resolved = resolve_secret(value, allow_empty=allow_empty)
    return resolved.encode(encoding)


def resolve_secret_optional(value: str | None) -> str | None:
    """Resolve a secret value, returning None if not set.

    Unlike resolve_secret(), this function does not raise an error if
    the environment variable is not set. Useful for optional secrets.

    Args:
        value: The value to resolve, or None.

    Returns:
        The resolved secret value, or None if:
            - value is None
            - value is an ENV reference to an unset variable

    Raises:
        SecretError: If the environment variable is set but empty.
    """
    if value is None:
        return None

    match = ENV_PATTERN.match(value)
    if not match:
        return value

    env_var_name = match.group(1)
    resolved = os.environ.get(env_var_name)

    if resolved is None:
        return None

    if resolved == "":
        raise SecretError(
            f"Environment variable '{env_var_name}' is empty",
            env_var=env_var_name,
        )

    return resolved


def redact_secret(text: str, secret: str, placeholder: str = REDACTED_PLACEHOLDER) -> str:
    """Redact a secret from text output.

    Replaces all occurrences of the secret with a placeholder.
    Useful for sanitizing logs and error messages.

    Args:
        text: Text that may contain the secret.
        secret: The secret value to redact.
        placeholder: Replacement text (default: "[REDACTED]").

    Returns:
        Text with secret replaced by placeholder.

    Example:
        output = "Using password: my-secret-123"
        safe = redact_secret(output, "my-secret-123")
        # Returns: "Using password: [REDACTED]"
    """
    if not secret:
        return text
    return text.replace(secret, placeholder)


def redact_secrets(text: str, secrets: list[str], placeholder: str = REDACTED_PLACEHOLDER) -> str:
    """Redact multiple secrets from text output.

    Args:
        text: Text that may contain secrets.
        secrets: List of secret values to redact.
        placeholder: Replacement text (default: "[REDACTED]").

    Returns:
        Text with all secrets replaced by placeholder.
    """
    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, placeholder)
    return result


def create_safe_json_output(
    data: dict,
    secrets: list[str] | None = None,
    secret_keys: list[str] | None = None,
) -> dict:
    """Create a JSON-safe output with secrets redacted.

    Args:
        data: Dictionary to sanitize.
        secrets: List of secret values to redact from string values.
        secret_keys: List of dictionary keys whose values should be redacted.

    Returns:
        Sanitized dictionary safe for JSON output.

    Example:
        data = {"password": "secret123", "message": "Password is secret123"}
        safe = create_safe_json_output(
            data,
            secrets=["secret123"],
            secret_keys=["password"]
        )
        # Returns: {"password": "[REDACTED]", "message": "Password is [REDACTED]"}
    """
    secrets = secrets or []
    secret_keys = secret_keys or []

    def sanitize_value(key: str, value):
        if key in secret_keys:
            return REDACTED_PLACEHOLDER
        if isinstance(value, str):
            return redact_secrets(value, secrets)
        if isinstance(value, dict):
            return {k: sanitize_value(k, v) for k, v in value.items()}
        if isinstance(value, list):
            return [sanitize_value("", item) for item in value]
        return value

    return {k: sanitize_value(k, v) for k, v in data.items()}


def validate_env_reference(value: str) -> tuple[bool, str | None]:
    """Validate an ENV reference without resolving it.

    Checks if the reference is syntactically valid and if the
    environment variable exists.

    Args:
        value: ENV reference to validate.

    Returns:
        Tuple of (is_valid, error_message).
        If valid, error_message is None.

    Example:
        is_valid, error = validate_env_reference("ENV:MY_SECRET")
        if not is_valid:
            print(f"Invalid: {error}")
    """
    if not is_env_reference(value):
        return False, f"Invalid ENV reference format: {value}"

    env_var_name = get_env_var_name(value)
    if env_var_name is None:
        return False, f"Could not extract variable name from: {value}"

    if env_var_name not in os.environ:
        return False, f"Environment variable '{env_var_name}' is not set"

    if os.environ[env_var_name] == "":
        return False, f"Environment variable '{env_var_name}' is empty"

    return True, None

