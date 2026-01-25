"""
Encryption module.

Provides authenticated encryption using modern AEAD ciphers.
All encryption operations include authentication tags to detect tampering.

Supported algorithms:
- AES-256-GCM (default, hardware-accelerated on modern CPUs)
- ChaCha20-Poly1305 (excellent software performance)
"""

import json
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from filanti.core.errors import EncryptionError, FileOperationError
from filanti.core.file_manager import FileManager, get_file_manager
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.kdf import derive_key, derive_key_with_salt, KDFParams, DerivedKey
from filanti.crypto.key_management import generate_nonce, NONCE_SIZE_GCM, NONCE_SIZE_CHACHA


class EncryptionAlgorithm(str, Enum):
    """Supported authenticated encryption algorithms."""

    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


# Default algorithm
DEFAULT_ALGORITHM = EncryptionAlgorithm.AES_256_GCM

# File format magic bytes
FILANTI_MAGIC = b"FLNT"
FORMAT_VERSION = 1

# Chunk size for streaming encryption (64 KB)
CHUNK_SIZE = 65536


@dataclass
class EncryptedData:
    """Container for encrypted data and its metadata."""

    ciphertext: bytes
    nonce: bytes
    algorithm: str

    # KDF parameters (for password-based encryption)
    salt: bytes | None = None
    kdf_algorithm: str | None = None
    kdf_params: dict | None = None

    def to_bytes(self) -> bytes:
        """Serialize encrypted data to bytes for storage/transmission.

        Format for password-based encryption:
        - 4 bytes: salt length (big-endian)
        - N bytes: salt
        - 4 bytes: nonce length (big-endian)
        - N bytes: nonce
        - 4 bytes: metadata JSON length (big-endian)
        - N bytes: metadata JSON (algorithm, kdf_algorithm, kdf_params)
        - Remaining: ciphertext
        """
        meta = {
            "algorithm": self.algorithm,
            "kdf_algorithm": self.kdf_algorithm,
            "kdf_params": self.kdf_params,
        }
        meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")

        parts = []
        # Salt (may be None for raw key encryption)
        salt = self.salt or b""
        parts.append(len(salt).to_bytes(4, "big"))
        parts.append(salt)
        # Nonce
        parts.append(len(self.nonce).to_bytes(4, "big"))
        parts.append(self.nonce)
        # Metadata
        parts.append(len(meta_bytes).to_bytes(4, "big"))
        parts.append(meta_bytes)
        # Ciphertext
        parts.append(self.ciphertext)

        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """Deserialize encrypted data from bytes."""
        offset = 0

        # Salt
        salt_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        salt = data[offset:offset+salt_len] if salt_len > 0 else None
        offset += salt_len

        # Nonce
        nonce_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        nonce = data[offset:offset+nonce_len]
        offset += nonce_len

        # Metadata
        meta_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        meta_bytes = data[offset:offset+meta_len]
        meta = json.loads(meta_bytes.decode("utf-8"))
        offset += meta_len

        # Ciphertext
        ciphertext = data[offset:]

        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm=meta["algorithm"],
            salt=salt,
            kdf_algorithm=meta.get("kdf_algorithm"),
            kdf_params=meta.get("kdf_params"),
        )


@dataclass
class EncryptionMetadata:
    """Metadata stored with encrypted files."""

    version: int
    algorithm: str
    nonce: str  # hex-encoded
    salt: str | None = None  # hex-encoded
    kdf_algorithm: str | None = None
    kdf_params: dict | None = None
    original_size: int | None = None

    def to_bytes(self) -> bytes:
        """Serialize metadata to bytes."""
        return json.dumps(asdict(self), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptionMetadata":
        """Deserialize metadata from bytes."""
        parsed = json.loads(data.decode("utf-8"))
        return cls(**parsed)


def _get_cipher(algorithm: EncryptionAlgorithm, key: bytes):
    """Get the appropriate cipher for the algorithm."""
    if algorithm == EncryptionAlgorithm.AES_256_GCM:
        return AESGCM(key)
    elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    else:
        raise EncryptionError(
            f"Unsupported encryption algorithm: {algorithm}",
            algorithm=str(algorithm),
        )


def _get_nonce_size(algorithm: EncryptionAlgorithm) -> int:
    """Get the nonce size for the algorithm."""
    if algorithm == EncryptionAlgorithm.AES_256_GCM:
        return NONCE_SIZE_GCM
    elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
        return NONCE_SIZE_CHACHA
    else:
        return NONCE_SIZE_GCM


def encrypt_bytes(
    plaintext: bytes,
    key: bytes,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    associated_data: bytes | None = None,
) -> EncryptedData:
    """Encrypt bytes using authenticated encryption.

    Args:
        plaintext: Data to encrypt.
        key: Encryption key (32 bytes for AES-256-GCM).
        algorithm: Encryption algorithm to use.
        associated_data: Optional additional authenticated data (AAD).

    Returns:
        EncryptedData containing ciphertext and metadata.

    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        nonce_size = _get_nonce_size(algorithm)
        nonce = generate_nonce(nonce_size)

        cipher = _get_cipher(algorithm, key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data)

        return EncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm=algorithm.value,
        )
    except Exception as e:
        if isinstance(e, EncryptionError):
            raise
        raise EncryptionError(
            f"Encryption failed: {e}",
            algorithm=algorithm.value,
        ) from e


def encrypt_bytes_with_password(
    plaintext: bytes,
    password: str,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    kdf_params: KDFParams | None = None,
    associated_data: bytes | None = None,
) -> EncryptedData:
    """Encrypt bytes using a password.

    Derives an encryption key from the password using a secure KDF.

    Args:
        plaintext: Data to encrypt.
        password: Password for encryption.
        algorithm: Encryption algorithm to use.
        kdf_params: Optional KDF parameters.
        associated_data: Optional additional authenticated data.

    Returns:
        EncryptedData containing ciphertext and KDF parameters.

    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        # Derive key from password
        derived = derive_key(password, params=kdf_params)

        # Encrypt with derived key
        result = encrypt_bytes(plaintext, derived.key, algorithm, associated_data)

        # Add KDF info to result
        return EncryptedData(
            ciphertext=result.ciphertext,
            nonce=result.nonce,
            algorithm=result.algorithm,
            salt=derived.salt,
            kdf_algorithm=derived.algorithm,
            kdf_params=derived.params,
        )
    except Exception as e:
        if isinstance(e, EncryptionError):
            raise
        raise EncryptionError(
            f"Password encryption failed: {e}",
            algorithm=algorithm.value,
        ) from e


def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    file_manager: FileManager | None = None,
) -> EncryptionMetadata:
    """Encrypt a file using authenticated encryption.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        key: Encryption key.
        algorithm: Encryption algorithm to use.
        file_manager: Optional FileManager instance.

    Returns:
        EncryptionMetadata for the encrypted file.

    Raises:
        EncryptionError: If encryption fails.
        FileOperationError: If file operations fail.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read entire file (streaming encryption in Phase 5)
        plaintext = fm.read_bytes(input_path)
        original_size = len(plaintext)

        # Encrypt
        result = encrypt_bytes(plaintext, key, algorithm)

        # Create metadata
        metadata = EncryptionMetadata(
            version=FORMAT_VERSION,
            algorithm=result.algorithm,
            nonce=result.nonce.hex(),
            original_size=original_size,
        )

        # Write encrypted file with header
        output = _build_encrypted_file(result.ciphertext, metadata)
        fm.write_bytes(output_path, output)

        return metadata

    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise EncryptionError(
            f"File encryption failed: {e}",
            algorithm=algorithm.value,
            context={"input": str(input_path)},
        ) from e


def encrypt_file_with_password(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    kdf_params: KDFParams | None = None,
    file_manager: FileManager | None = None,
) -> EncryptionMetadata:
    """Encrypt a file using a password.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        password: Password for encryption.
        algorithm: Encryption algorithm to use.
        kdf_params: Optional KDF parameters.
        file_manager: Optional FileManager instance.

    Returns:
        EncryptionMetadata for the encrypted file.

    Raises:
        EncryptionError: If encryption fails.
        FileOperationError: If file operations fail.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read entire file
        plaintext = fm.read_bytes(input_path)
        original_size = len(plaintext)

        # Encrypt with password
        result = encrypt_bytes_with_password(
            plaintext, password, algorithm, kdf_params
        )

        # Create metadata
        metadata = EncryptionMetadata(
            version=FORMAT_VERSION,
            algorithm=result.algorithm,
            nonce=result.nonce.hex(),
            salt=result.salt.hex() if result.salt else None,
            kdf_algorithm=result.kdf_algorithm,
            kdf_params=result.kdf_params,
            original_size=original_size,
        )

        # Write encrypted file with header
        output = _build_encrypted_file(result.ciphertext, metadata)
        fm.write_bytes(output_path, output)

        return metadata

    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise EncryptionError(
            f"File encryption failed: {e}",
            algorithm=algorithm.value,
            context={"input": str(input_path)},
        ) from e


def _build_encrypted_file(ciphertext: bytes, metadata: EncryptionMetadata) -> bytes:
    """Build encrypted file with header.

    File format:
    - 4 bytes: Magic ("FLNT")
    - 4 bytes: Metadata length (big-endian uint32)
    - N bytes: Metadata (JSON)
    - M bytes: Ciphertext
    """
    meta_bytes = metadata.to_bytes()
    meta_length = len(meta_bytes).to_bytes(4, "big")

    return FILANTI_MAGIC + meta_length + meta_bytes + ciphertext


def parse_encrypted_file(data: bytes) -> tuple[EncryptionMetadata, bytes]:
    """Parse encrypted file header and extract ciphertext.

    Args:
        data: Encrypted file bytes.

    Returns:
        Tuple of (metadata, ciphertext).

    Raises:
        EncryptionError: If file format is invalid.
    """
    if len(data) < 8:
        raise EncryptionError("Invalid encrypted file: too short")

    if data[:4] != FILANTI_MAGIC:
        raise EncryptionError("Invalid encrypted file: bad magic bytes")

    meta_length = int.from_bytes(data[4:8], "big")

    if len(data) < 8 + meta_length:
        raise EncryptionError("Invalid encrypted file: truncated metadata")

    meta_bytes = data[8:8 + meta_length]
    ciphertext = data[8 + meta_length:]

    try:
        metadata = EncryptionMetadata.from_bytes(meta_bytes)
    except Exception as e:
        raise EncryptionError(f"Invalid encrypted file metadata: {e}") from e

    return metadata, ciphertext

