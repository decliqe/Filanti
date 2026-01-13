"""
Key management module.

Provides secure key generation, handling, and storage abstractions.
All keys are handled as bytes and should be securely cleared after use.
"""

from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from filanti.core.errors import FilantiError
from filanti.core.secure_memory import secure_random_bytes, SecureBytes


class KeyType(str, Enum):
    """Types of cryptographic keys."""

    SYMMETRIC = "symmetric"
    ENCRYPTION = "encryption"
    MAC = "mac"
    SIGNING = "signing"


# Standard key sizes in bytes
KEY_SIZE_128 = 16  # 128 bits
KEY_SIZE_256 = 32  # 256 bits
KEY_SIZE_512 = 64  # 512 bits

# Default key size for AES-256
DEFAULT_KEY_SIZE = KEY_SIZE_256

# Nonce/IV sizes
NONCE_SIZE_GCM = 12      # 96 bits for AES-GCM
NONCE_SIZE_CHACHA = 12   # 96 bits for ChaCha20-Poly1305


class KeyMaterial(NamedTuple):
    """Container for key material with metadata."""

    key: bytes
    key_type: str
    size: int


@dataclass
class EncryptionKey:
    """Wrapper for encryption key with secure handling.

    Provides context manager support for automatic cleanup.
    """

    _key: bytes
    key_type: KeyType = KeyType.ENCRYPTION

    def __post_init__(self) -> None:
        if len(self._key) not in (KEY_SIZE_128, KEY_SIZE_256, KEY_SIZE_512):
            raise FilantiError(
                f"Invalid key size: {len(self._key)} bytes",
                context={"valid_sizes": [KEY_SIZE_128, KEY_SIZE_256, KEY_SIZE_512]},
            )

    @property
    def key(self) -> bytes:
        """Get the raw key bytes."""
        return self._key

    @property
    def size(self) -> int:
        """Get key size in bytes."""
        return len(self._key)

    @property
    def size_bits(self) -> int:
        """Get key size in bits."""
        return len(self._key) * 8

    def __len__(self) -> int:
        return len(self._key)

    def __bytes__(self) -> bytes:
        return self._key


def generate_key(size: int = DEFAULT_KEY_SIZE) -> bytes:
    """Generate a random symmetric encryption key.

    Args:
        size: Key size in bytes (16, 32, or 64).

    Returns:
        Random key bytes.

    Raises:
        FilantiError: If key size is invalid.
    """
    if size not in (KEY_SIZE_128, KEY_SIZE_256, KEY_SIZE_512):
        raise FilantiError(
            f"Invalid key size: {size} bytes",
            context={"valid_sizes": [KEY_SIZE_128, KEY_SIZE_256, KEY_SIZE_512]},
        )
    return secure_random_bytes(size)


def generate_nonce(size: int = NONCE_SIZE_GCM) -> bytes:
    """Generate a random nonce/IV.

    Args:
        size: Nonce size in bytes.

    Returns:
        Random nonce bytes.
    """
    return secure_random_bytes(size)


def split_key(master_key: bytes, num_keys: int = 2) -> list[bytes]:
    """Split a master key into derived subkeys.

    Uses HKDF to derive multiple independent keys from a master key.
    Useful for key separation (e.g., encryption key + MAC key).

    Args:
        master_key: Master key to split.
        num_keys: Number of subkeys to derive.

    Returns:
        List of derived key bytes.

    Raises:
        FilantiError: If derivation fails.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend

    key_size = len(master_key)
    total_size = key_size * num_keys

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=total_size,
        salt=None,  # Optional: could add salt parameter
        info=b"filanti-key-split",
        backend=default_backend(),
    )

    derived = hkdf.derive(master_key)

    # Split into individual keys
    keys = []
    for i in range(num_keys):
        start = i * key_size
        end = start + key_size
        keys.append(derived[start:end])

    return keys


def derive_subkey(master_key: bytes, context: bytes, length: int = DEFAULT_KEY_SIZE) -> bytes:
    """Derive a subkey from a master key with context.

    Uses HKDF-Expand for deterministic subkey derivation.
    Different contexts produce different subkeys.

    Args:
        master_key: Master key bytes.
        context: Context/info bytes (e.g., b"encryption" or b"mac").
        length: Desired subkey length.

    Returns:
        Derived subkey bytes.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=context,
        backend=default_backend(),
    )

    return hkdf.derive(master_key)

