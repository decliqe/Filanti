"""
Execution context for Filanti v2.

The ExecutionContext carries all state needed for a single operation
through the pipeline: Threat Engine → Policy Engine → KMS → Crypto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Operation(str, Enum):
    """Supported orchestrator operations."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    HASH = "hash"
    SIGN = "sign"
    VERIFY = "verify"
    MAC = "mac"
    CHECKSUM = "checksum"
    DERIVE = "derive"


@dataclass
class ExecutionContext:
    """Immutable-ish execution context built by the Orchestrator.

    Attributes:
        operation: The high-level operation to perform.
        input_path: Source file / data path (optional for bytes-mode).
        output_path: Destination file path (optional).
        input_bytes: Raw bytes input (mutually exclusive with input_path for files).
        password: Password for password-based operations.
        key: Raw symmetric key bytes (resolved by KMS).
        key_ref: Logical key reference resolved by KMS.
        algorithm: Encryption / hash algorithm override.
        policy_name: Name of the policy to enforce.
        threat_mode: Name of the active threat mode.
        chunk_size: Streaming chunk size override.
        associated_data: AAD bytes for AEAD.
        metadata: Arbitrary string→Any metadata bag.
        kdf_overrides: Overrides for KDF parameters from threat mode.
        resolved: Whether KMS has resolved key material.
        validated: Whether the Policy Engine has validated this context.
        remove_source: Delete source after encrypt.
        secure_delete: Overwrite source before unlinking.
    """

    operation: Operation
    input_path: str | Path | None = None
    output_path: str | Path | None = None
    input_bytes: bytes | None = None
    password: str | None = None
    key: bytes | None = None
    key_ref: str | None = None
    algorithm: str | None = None
    policy_name: str | None = None
    threat_mode: str | None = None
    chunk_size: int | None = None
    associated_data: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    kdf_overrides: dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    validated: bool = False
    remove_source: bool = False
    secure_delete: bool = True

    # --- convenience helpers ---------------------------------------------------

    @property
    def is_file_operation(self) -> bool:
        """Return True when the operation targets files on disk."""
        return self.input_path is not None

    @property
    def is_password_based(self) -> bool:
        """Return True when a password (not raw key) is supplied."""
        return self.password is not None

    def require_key(self) -> bytes:
        """Return the resolved key or raise."""
        if self.key is None:
            from filanti.core.errors import EncryptionError
            raise EncryptionError(
                "No encryption key available in context — "
                "supply a key, password, or key_ref"
            )
        return self.key

    def copy(self, **overrides: Any) -> ExecutionContext:
        """Return a shallow copy with field overrides."""
        from dataclasses import asdict
        data = asdict(self)
        data.update(overrides)
        # Re-wrap enums that asdict converted to strings
        if isinstance(data["operation"], str):
            data["operation"] = Operation(data["operation"])
        return ExecutionContext(**data)
