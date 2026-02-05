"""
Secret resolution module.

Provides secure, runtime-only secret resolution from environment variables
and .env files. Secrets are never resolved at import time to prevent
accidental exposure.

Supported secret reference formats:
    - ENV:SECRET_NAME      (Unix-style, original format)
    - $env:SECRET_NAME     (PowerShell-style)
    - ${SECRET_NAME}       (Shell-style variable expansion)
    - env.SECRET_NAME      (Dot notation, cross-platform friendly)

Usage:
    # Resolve any supported pattern
    password = resolve_secret("ENV:MY_PASSWORD")
    password = resolve_secret("$env:MY_PASSWORD")  # PowerShell
    password = resolve_secret("${MY_PASSWORD}")    # Shell-style
    password = resolve_secret("env.MY_PASSWORD")   # Dot notation

    # Load from .env file
    load_dotenv(".env")
    password = resolve_secret("ENV:MY_PASSWORD")

    # Check if value is an ENV reference
    if is_env_reference("ENV:SECRET_KEY"):
        ...

    # Redact secrets from output
    safe_output = redact_secret(output_text, secret_value)
"""

import os
import re
from pathlib import Path
from typing import Pattern

from filanti.core.errors import SecretError, FileOperationError


# Multiple patterns for secret references
PATTERNS: dict[str, Pattern[str]] = {
    "env_colon": re.compile(r"^ENV:([A-Za-z_][A-Za-z0-9_]*)$"),           # ENV:SECRET
    "powershell": re.compile(r"^\$env:([A-Za-z_][A-Za-z0-9_]*)$"),        # $env:SECRET
    "shell_style": re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$"),       # ${SECRET}
    "dot_notation": re.compile(r"^env\.([A-Za-z_][A-Za-z0-9_]*)$"),       # env.SECRET
}

# Legacy pattern for backward compatibility
ENV_PATTERN: Pattern[str] = PATTERNS["env_colon"]

# Redaction placeholder
REDACTED_PLACEHOLDER = "[REDACTED]"


def is_env_reference(value: str) -> bool:
    """Check if a value is any type of secret reference.

    Supports multiple formats:
        - ENV:SECRET_NAME (Unix-style)
        - $env:SECRET_NAME (PowerShell-style)
        - ${SECRET_NAME} (Shell-style)
        - env.SECRET_NAME (Dot notation)

    Args:
        value: String to check.

    Returns:
        True if value matches any supported secret reference pattern.
    """
    if value is None:
        return False
    return any(pattern.match(value) for pattern in PATTERNS.values())


def get_env_var_name(value: str) -> str | None:
    """Extract environment variable name from any reference format.

    Args:
        value: Secret reference string (e.g., "ENV:MY_SECRET", "$env:MY_SECRET").

    Returns:
        Environment variable name, or None if not a valid reference.
    """
    if value is None:
        return None
    for pattern in PATTERNS.values():
        match = pattern.match(value)
        if match:
            return match.group(1)
    return None


def load_dotenv(
    path: str | Path = ".env",
    override: bool = False,
    encoding: str = "utf-8",
) -> dict[str, str]:
    """Load environment variables from a .env file.

    Supports standard .env format:
        KEY=value
        KEY="quoted value"
        KEY='single quoted'
        # comments
        export KEY=value  (optional export prefix)

    Args:
        path: Path to .env file (default: ".env" in current directory).
        override: If True, override existing environment variables.
        encoding: File encoding (default: utf-8).

    Returns:
        Dictionary of loaded variables (name -> value).

    Raises:
        FileOperationError: If file cannot be read.
    """
    env_path = Path(path)
    loaded: dict[str, str] = {}

    if not env_path.exists():
        return loaded

    try:
        content = env_path.read_text(encoding=encoding)
    except OSError as e:
        raise FileOperationError(
            f"Failed to read .env file: {e}",
            path=str(env_path),
            operation="load_dotenv",
        ) from e

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Remove optional 'export ' prefix
        if line.startswith("export "):
            line = line[7:].strip()

        # Parse KEY=VALUE
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Remove quotes
        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

        # Validate key format
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue

        loaded[key] = value

        # Set in environment
        if override or key not in os.environ:
            os.environ[key] = value

    return loaded


def resolve_secret(
    value: str,
    allow_empty: bool = False,
    dotenv_path: str | Path | None = None,
) -> str:
    """Resolve a secret value from multiple sources.

    Supports multiple reference formats:
        - ENV:SECRET_NAME (Unix-style)
        - $env:SECRET_NAME (PowerShell-style)
        - ${SECRET_NAME} (Shell-style)
        - env.SECRET_NAME (Dot notation)

    Args:
        value: The value to resolve. Can be:
            - A literal string (returned as-is)
            - Any supported ENV reference format
        allow_empty: If False (default), raises SecretError for empty values.
        dotenv_path: Optional path to .env file to load before resolution.

    Returns:
        The resolved secret value.

    Raises:
        SecretError: If the environment variable is not set or is empty
                     (when allow_empty=False).

    Example:
        # Set environment variable
        os.environ["ENCRYPTION_KEY"] = "my-secret-key"

        # Resolve using any format
        key = resolve_secret("ENV:ENCRYPTION_KEY")
        key = resolve_secret("$env:ENCRYPTION_KEY")  # PowerShell
        key = resolve_secret("${ENCRYPTION_KEY}")    # Shell-style
        key = resolve_secret("env.ENCRYPTION_KEY")   # Dot notation

        # Literal values pass through unchanged
        literal = resolve_secret("direct-password")
    """
    if value is None:
        raise SecretError("Secret value cannot be None")

    # Load .env if specified
    if dotenv_path is not None:
        load_dotenv(dotenv_path, override=False)

    # Try to extract env var name from any supported pattern
    env_var_name = get_env_var_name(value)

    if env_var_name is None:
        # Not a reference, return as-is
        return value

    # Resolve from environment
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

    Supports all reference formats:
        - ENV:SECRET_NAME (Unix-style)
        - $env:SECRET_NAME (PowerShell-style)
        - ${SECRET_NAME} (Shell-style)
        - env.SECRET_NAME (Dot notation)

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

    # Try to extract env var name from any supported pattern
    env_var_name = get_env_var_name(value)

    if env_var_name is None:
        # Not a reference, return as-is
        return value

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

    Supports all reference formats:
        - ENV:SECRET_NAME (Unix-style)
        - $env:SECRET_NAME (PowerShell-style)
        - ${SECRET_NAME} (Shell-style)
        - env.SECRET_NAME (Dot notation)

    Args:
        value: ENV reference to validate.

    Returns:
        Tuple of (is_valid, error_message).
        If valid, error_message is None.

    Example:
        is_valid, error = validate_env_reference("ENV:MY_SECRET")
        is_valid, error = validate_env_reference("$env:MY_SECRET")
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


def get_supported_patterns() -> list[str]:
    """Get list of supported secret reference patterns.

    Returns:
        List of pattern descriptions with examples.
    """
    return [
        "ENV:VAR_NAME - Unix-style (e.g., ENV:MY_SECRET)",
        "$env:VAR_NAME - PowerShell-style (e.g., $env:MY_SECRET)",
        "${VAR_NAME} - Shell-style (e.g., ${MY_SECRET})",
        "env.VAR_NAME - Dot notation (e.g., env.MY_SECRET)",
    ]
