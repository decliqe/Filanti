"""
KMS — Key Management System abstraction layer.

Provides a pluggable interface for key lifecycle management:
    * **LocalProvider** (default) — generates and wraps keys locally.
    * Future: VaultProvider, AWSKMSProvider, etc.

The KMS resolves ``key_ref`` identifiers in the execution context and
performs envelope encryption (data-key wrapped by a master key).
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from filanti.core.errors import EncryptionError, DecryptionError
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.key_management import generate_key, DEFAULT_KEY_SIZE


# ------------------------------------------------------------------
# Data classes
# ------------------------------------------------------------------

@dataclass(frozen=True)
class DataKey:
    """A generated data-encryption key with its wrapped (encrypted) form.

    Attributes:
        plaintext: The raw key bytes (use and discard).
        wrapped: The key encrypted under the master key (persist this).
        provider: Name of the KMS provider that created it.
        key_id: Unique id of the master key used for wrapping.
    """

    plaintext: bytes
    wrapped: bytes
    provider: str
    key_id: str


# ------------------------------------------------------------------
# Abstract provider
# ------------------------------------------------------------------

class KMSProvider(ABC):
    """Abstract base for all KMS back-ends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name."""
        ...

    @abstractmethod
    def generate_data_key(self, key_id: str, length: int = DEFAULT_KEY_SIZE) -> DataKey:
        """Generate a new data key and wrap it with master key *key_id*.

        Raises:
            EncryptionError: On failure.
        """
        ...

    @abstractmethod
    def unwrap_key(self, wrapped: bytes, key_id: str) -> bytes:
        """Unwrap (decrypt) a previously wrapped data key.

        Raises:
            DecryptionError: On failure.
        """
        ...


# ------------------------------------------------------------------
# Local provider
# ------------------------------------------------------------------

class LocalProvider(KMSProvider):
    """File-system-based local KMS for development and single-node use.

    Master keys are stored in a directory as raw 32-byte files.
    Key wrapping uses AES-256-GCM with an HKDF-derived wrapping key.

    **Not suitable for multi-tenant production.**  Use Vault / AWS KMS
    for production deployments.
    """

    _WRAP_INFO: bytes = b"filanti-kms-wrap"

    def __init__(self, keys_dir: str | Path | None = None) -> None:
        if keys_dir is None:
            keys_dir = Path.home() / ".filanti" / "keys"
        self._keys_dir = Path(keys_dir)
        self._keys_dir.mkdir(parents=True, exist_ok=True)

    @property
    def name(self) -> str:
        return "local"

    # ------------------------------------------------------------------
    # Master key management
    # ------------------------------------------------------------------

    def create_master_key(self, key_id: str) -> Path:
        """Generate and persist a new master key.

        Returns:
            Path to the key file.

        Raises:
            EncryptionError: If key already exists.
        """
        path = self._key_path(key_id)
        if path.exists():
            raise EncryptionError(
                f"Master key '{key_id}' already exists",
                context={"key_id": key_id},
            )
        master = generate_key(DEFAULT_KEY_SIZE)
        path.write_bytes(master)
        # Best-effort permission restriction
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def _load_master(self, key_id: str) -> bytes:
        path = self._key_path(key_id)
        if not path.exists():
            raise EncryptionError(
                f"Master key '{key_id}' not found",
                context={"key_id": key_id, "dir": str(self._keys_dir)},
            )
        return path.read_bytes()

    def _key_path(self, key_id: str) -> Path:
        # Sanitise key_id to prevent path traversal
        safe = "".join(c for c in key_id if c.isalnum() or c in "-_.")
        if not safe:
            raise EncryptionError("Invalid key_id")
        return self._keys_dir / f"{safe}.key"

    # ------------------------------------------------------------------
    # Data-key lifecycle
    # ------------------------------------------------------------------

    def generate_data_key(
        self, key_id: str, length: int = DEFAULT_KEY_SIZE,
    ) -> DataKey:
        master = self._load_master(key_id)
        data_key = generate_key(length)
        wrapped = self._wrap(master, data_key)
        return DataKey(
            plaintext=data_key,
            wrapped=wrapped,
            provider=self.name,
            key_id=key_id,
        )

    def unwrap_key(self, wrapped: bytes, key_id: str) -> bytes:
        master = self._load_master(key_id)
        return self._unwrap(master, wrapped)

    # ------------------------------------------------------------------
    # Wrap / unwrap helpers (AES-GCM envelope)
    # ------------------------------------------------------------------

    def _wrap(self, master: bytes, plaintext_key: bytes) -> bytes:
        nonce = secure_random_bytes(12)
        wrap_key = self._derive_wrap_key(master, nonce)
        cipher = AESGCM(wrap_key)
        ct: bytes = cipher.encrypt(nonce, plaintext_key, None)
        # Format: nonce ‖ ciphertext
        return nonce + ct

    def _unwrap(self, master: bytes, wrapped: bytes) -> bytes:
        if len(wrapped) < 12:
            raise DecryptionError("Invalid wrapped key: too short")
        nonce = wrapped[:12]
        ct = wrapped[12:]
        wrap_key = self._derive_wrap_key(master, nonce)
        cipher = AESGCM(wrap_key)
        try:
            return cipher.decrypt(nonce, ct, None)
        except Exception as exc:
            raise DecryptionError(
                f"Failed to unwrap data key: {exc}"
            ) from exc

    @classmethod
    def _derive_wrap_key(cls, master: bytes, salt: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=cls._WRAP_INFO,
        )
        return hkdf.derive(master)


# ------------------------------------------------------------------
# KeyManager facade
# ------------------------------------------------------------------

class KeyManager:
    """High-level façade used by the Orchestrator.

    Delegates to a pluggable ``KMSProvider``.
    """

    def __init__(self, provider: KMSProvider | None = None) -> None:
        self._provider: KMSProvider = provider or LocalProvider()

    @property
    def provider_name(self) -> str:
        return self._provider.name

    def resolve(self, key_ref: str) -> bytes:
        """Resolve a ``key_ref`` string to raw key bytes.

        Supported formats:
            * ``"env:VAR_NAME"`` — read hex-encoded key from env var
            * ``"file:/path/to/key"`` — read raw key bytes from file
            * ``"kms:<key_id>:<wrapped_hex>"`` — unwrap via provider

        Raises:
            EncryptionError: If resolution fails.
        """
        if key_ref.startswith("env:"):
            return self._resolve_env(key_ref[4:])
        if key_ref.startswith("file:"):
            return self._resolve_file(key_ref[5:])
        if key_ref.startswith("kms:"):
            return self._resolve_kms(key_ref[4:])
        raise EncryptionError(
            f"Unknown key_ref scheme: '{key_ref}'. "
            "Use env:, file:, or kms: prefix."
        )

    def generate_data_key(
        self, key_id: str = "default", length: int = DEFAULT_KEY_SIZE,
    ) -> DataKey:
        """Generate a new data key wrapped by master key *key_id*."""
        return self._provider.generate_data_key(key_id, length)

    def wrap_key(self, key_id: str, plaintext_key: bytes) -> bytes:
        """Wrap an existing key under master key *key_id*.

        Delegates to provider if it supports wrapping explicitly,
        otherwise uses generate_data_key as a workaround.
        """
        if isinstance(self._provider, LocalProvider):
            master = self._provider._load_master(key_id)
            return self._provider._wrap(master, plaintext_key)
        # Fallback: provider doesn't expose direct wrap → error
        raise EncryptionError(
            f"Provider '{self._provider.name}' does not support direct wrap_key"
        )

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_env(var_name: str) -> bytes:
        value = os.environ.get(var_name)
        if value is None:
            raise EncryptionError(
                f"Environment variable '{var_name}' not set",
                context={"key_ref": f"env:{var_name}"},
            )
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise EncryptionError(
                f"Environment variable '{var_name}' is not valid hex",
                context={"key_ref": f"env:{var_name}"},
            )

    @staticmethod
    def _resolve_file(path_str: str) -> bytes:
        p = Path(path_str)
        if not p.exists():
            raise EncryptionError(
                f"Key file not found: {p}",
                context={"key_ref": f"file:{path_str}"},
            )
        data = p.read_bytes()
        if len(data) not in (16, 32, 64):
            raise EncryptionError(
                f"Key file has unexpected size ({len(data)} bytes). "
                "Expected 16, 32, or 64.",
                context={"key_ref": f"file:{path_str}"},
            )
        return data

    def _resolve_kms(self, rest: str) -> bytes:
        parts = rest.split(":", 1)
        if len(parts) != 2:
            raise EncryptionError(
                "kms: ref must be 'kms:<key_id>:<wrapped_hex>'"
            )
        key_id, wrapped_hex = parts
        try:
            wrapped = bytes.fromhex(wrapped_hex)
        except ValueError:
            raise EncryptionError("Wrapped key is not valid hex")
        return self._provider.unwrap_key(wrapped, key_id)
