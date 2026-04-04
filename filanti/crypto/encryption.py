"""
Encryption module.

Provides authenticated encryption using modern AEAD ciphers.
All encryption operations include authentication tags to detect tampering.

Supported algorithms:
- AES-256-GCM (default, hardware-accelerated on modern CPUs)
- ChaCha20-Poly1305 (excellent software performance)
"""

import base64
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
FORMAT_VERSION = 1  # Legacy v1 format version (DEPRECATED — plaintext metadata)
FORMAT_VERSION_V2 = 2  # v2 format with encrypted metadata
FORMAT_VERSION_V21 = 3  # v2.1 format with KDF block + encrypted metadata

# Product identifier for header
PRODUCT_NAME = "FLNT"
HEADER_VERSION = "1.1.0"

# Chunk size for streaming encryption (64 KB)
CHUNK_SIZE = 65536

# Minimum password length for password-based encryption
MIN_PASSWORD_LENGTH = 8


def validate_password(password: str, allow_weak: bool = False) -> None:
    """Validate password meets minimum security requirements.

    Args:
        password: Password to validate.
        allow_weak: If True, skip validation (for testing/special cases).

    Raises:
        EncryptionError: If password is too weak.
    """
    if allow_weak:
        return
    if not password:
        raise EncryptionError("Password cannot be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise EncryptionError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
            context={"length": len(password), "minimum": MIN_PASSWORD_LENGTH},
        )


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
        if len(data) < offset + 4:
            raise EncryptionError("Invalid encrypted data: truncated salt length")
        salt_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        if salt_len > 1024:
            raise EncryptionError("Invalid encrypted data: salt length too large")
        if len(data) < offset + salt_len:
            raise EncryptionError("Invalid encrypted data: truncated salt")
        salt = data[offset:offset+salt_len] if salt_len > 0 else None
        offset += salt_len

        # Nonce
        if len(data) < offset + 4:
            raise EncryptionError("Invalid encrypted data: truncated nonce length")
        nonce_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        if nonce_len > 64:
            raise EncryptionError("Invalid encrypted data: nonce length too large")
        if len(data) < offset + nonce_len:
            raise EncryptionError("Invalid encrypted data: truncated nonce")
        nonce = data[offset:offset+nonce_len]
        offset += nonce_len

        # Metadata
        if len(data) < offset + 4:
            raise EncryptionError("Invalid encrypted data: truncated metadata length")
        meta_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4
        if meta_len > 1_048_576:
            raise EncryptionError("Invalid encrypted data: metadata length too large")
        if len(data) < offset + meta_len:
            raise EncryptionError("Invalid encrypted data: truncated metadata")
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
        # Validate required fields
        required = {"version", "algorithm", "nonce"}
        missing = required - set(parsed.keys())
        if missing:
            raise EncryptionError(f"Invalid metadata: missing fields {missing}")
        return cls(**{k: v for k, v in parsed.items() if k in cls.__dataclass_fields__})


@dataclass
class FileHeader:
    """Minimal public header for encrypted files - base64 encoded.

    Only exposes product name and version, no cryptographic details.
    format_id: 2 = v2 (encrypted metadata), 3 = v2.1 (KDF block + encrypted metadata)
    """

    product: str = PRODUCT_NAME
    version: str = HEADER_VERSION
    format_id: int = 2

    def to_base64(self) -> bytes:
        """Encode header as base64 bytes."""
        data = {"p": self.product, "v": self.version}
        if self.format_id != 2:
            data["f"] = self.format_id
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(json_bytes)

    @classmethod
    def from_base64(cls, data: bytes) -> "FileHeader":
        """Decode header from base64 bytes."""
        try:
            json_bytes = base64.b64decode(data)
            parsed = json.loads(json_bytes.decode("utf-8"))
            return cls(
                product=parsed.get("p", "FLNT"),
                version=parsed.get("v", "1.0.0"),
                format_id=parsed.get("f", 2),
            )
        except Exception as e:
            raise EncryptionError(f"Invalid file header: {e}") from e

    def validate(self) -> bool:
        """Validate the header is from Filanti."""
        return self.product == PRODUCT_NAME


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
    allow_weak_password: bool = False,
) -> EncryptedData:
    """Encrypt bytes using a password.

    Derives an encryption key from the password using a secure KDF.

    Args:
        plaintext: Data to encrypt.
        password: Password for encryption.
        algorithm: Encryption algorithm to use.
        kdf_params: Optional KDF parameters.
        associated_data: Optional additional authenticated data.
        allow_weak_password: If True, skip password strength validation.

    Returns:
        EncryptedData containing ciphertext and KDF parameters.

    Raises:
        EncryptionError: If encryption fails or password is too weak.
    """
    validate_password(password, allow_weak=allow_weak_password)
    try:
        # Derive key from password
        derived = derive_key(password, params=kdf_params)
        key_ba = bytearray(derived.key)

        try:
            # Encrypt with derived key
            result = encrypt_bytes(plaintext, bytes(key_ba), algorithm, associated_data)

            # Add KDF info to result
            return EncryptedData(
                ciphertext=result.ciphertext,
                nonce=result.nonce,
                algorithm=result.algorithm,
                salt=derived.salt,
                kdf_algorithm=derived.algorithm,
                kdf_params=derived.params,
            )
        finally:
            # Securely zero the key material
            for i in range(len(key_ba)):
                key_ba[i] = 0
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
    remove_source: bool = False,
    secure_delete: bool = True,
) -> EncryptionMetadata:
    """Encrypt a file using authenticated encryption.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        key: Encryption key.
        algorithm: Encryption algorithm to use.
        file_manager: Optional FileManager instance.
        remove_source: If True, delete original file after successful encryption.
        secure_delete: If True and remove_source is True, securely overwrite
            the original file before deletion (defense in depth).

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

        # Build AAD from stable metadata fields (not nonce, since it changes per encryption)
        metadata_aad = _build_file_aad(FORMAT_VERSION_V2, algorithm.value, original_size)

        # Encrypt with AAD binding
        result = encrypt_bytes(plaintext, key, algorithm, associated_data=metadata_aad)

        # Create metadata with actual nonce
        metadata = EncryptionMetadata(
            version=FORMAT_VERSION_V2,
            algorithm=result.algorithm,
            nonce=result.nonce.hex(),
            original_size=original_size,
        )

        # Write encrypted file with header
        output = _build_encrypted_file(result.ciphertext, metadata, key)
        fm.write_bytes(output_path, output)

        # Remove source file if requested
        if remove_source:
            if secure_delete:
                fm.secure_delete(input_path)
            else:
                fm.delete(input_path)

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
    remove_source: bool = False,
    secure_delete: bool = True,
    allow_weak_password: bool = False,
) -> EncryptionMetadata:
    """Encrypt a file using a password.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        password: Password for encryption.
        algorithm: Encryption algorithm to use.
        kdf_params: Optional KDF parameters.
        file_manager: Optional FileManager instance.
        remove_source: If True, delete original file after successful encryption.
        secure_delete: If True and remove_source is True, securely overwrite
            the original file before deletion (defense in depth).

    Returns:
        EncryptionMetadata for the encrypted file.

    Raises:
        EncryptionError: If encryption fails.
        FileOperationError: If file operations fail.
    """
    validate_password(password, allow_weak=allow_weak_password)
    fm = file_manager or get_file_manager()

    try:
        # Read entire file
        plaintext = fm.read_bytes(input_path)
        original_size = len(plaintext)

        # Derive key from password first to pass to metadata encryption
        derived = derive_key(password, params=kdf_params)
        key_ba = bytearray(derived.key)

        try:
            # Build AAD from stable metadata fields (binds metadata to ciphertext)
            metadata_aad = _build_file_aad(FORMAT_VERSION_V21, algorithm.value, original_size)

            # Encrypt with derived key and AAD
            result = encrypt_bytes(plaintext, bytes(key_ba), algorithm, associated_data=metadata_aad)

            # Create metadata (v2.1 — sensitive fields encrypted, KDF params in public block)
            metadata = EncryptionMetadata(
                version=FORMAT_VERSION_V21,
                algorithm=result.algorithm,
                nonce=result.nonce.hex(),
                salt=derived.salt.hex(),
                kdf_algorithm=derived.algorithm,
                kdf_params=derived.params,
                original_size=original_size,
            )

            # KDF info for the unencrypted public block
            # (only salt + KDF algorithm + KDF params — needed pre-key-derivation)
            kdf_info = {
                "s": derived.salt.hex(),
                "a": derived.algorithm,
                "p": derived.params,
            }

            # Write encrypted file with v2.1 format (KDF block + encrypted metadata)
            output = _build_encrypted_file(result.ciphertext, metadata, bytes(key_ba), kdf_info=kdf_info)
            fm.write_bytes(output_path, output)
        finally:
            # Securely zero the key material
            for i in range(len(key_ba)):
                key_ba[i] = 0

        # Remove source file if requested
        if remove_source:
            if secure_delete:
                fm.secure_delete(input_path)
            else:
                fm.delete(input_path)

        return metadata

    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise EncryptionError(
            f"File encryption failed: {e}",
            algorithm=algorithm.value,
            context={"input": str(input_path)},
        ) from e


def _build_file_aad(version: int, algorithm: str, original_size: int) -> bytes:
    """Build deterministic AAD from stable metadata fields (excludes nonce).

    This is used by both encrypt_file and decrypt_file to produce
    matching AAD for the AEAD binding.
    """
    import json
    return json.dumps(
        {"version": version, "algorithm": algorithm, "original_size": original_size},
        sort_keys=True,
    ).encode("utf-8")


def _build_encrypted_file(ciphertext: bytes, metadata: EncryptionMetadata, encryption_key: bytes | None = None, kdf_info: dict | None = None) -> bytes:
    """Build encrypted file with v2/v2.1 format (encrypted metadata).

    File format v2 (format_id=2, no KDF block):
    - N bytes: Base64 header ({"p":"FLNT","v":"1.1.0"})
    - 2 bytes: Header length (big-endian uint16)
    - 12 bytes: Metadata nonce (for metadata encryption)
    - 4 bytes: Encrypted metadata length (big-endian uint32)
    - M bytes: Encrypted metadata ciphertext
    - K bytes: File ciphertext

    File format v2.1 (format_id=3, with KDF block for password-based):
    - N bytes: Base64 header ({"p":"FLNT","v":"1.1.0","f":3})
    - 2 bytes: Header length (big-endian uint16)
    - 2 bytes: KDF block length (big-endian uint16)
    - J bytes: KDF block (JSON: salt, KDF algorithm, KDF params)
    - 12 bytes: Metadata nonce (for metadata encryption)
    - 4 bytes: Encrypted metadata length (big-endian uint32)
    - M bytes: Encrypted metadata ciphertext
    - K bytes: File ciphertext

    The metadata is encrypted using AES-GCM with a key derived via HKDF
    from the user's encryption key, ensuring only key holders can read metadata.
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    if encryption_key is None:
        raise EncryptionError(
            "encryption_key is required for v2 format — "
            "cannot build encrypted metadata without a key"
        )

    # Determine format: v2.1 if KDF info present, v2 otherwise
    format_id = 3 if kdf_info is not None else 2

    # Create header with format identifier
    header = FileHeader(format_id=format_id)
    header_b64 = header.to_base64()

    # Build KDF block (only for v2.1 / password-based)
    if kdf_info is not None:
        kdf_block = json.dumps(kdf_info, separators=(",", ":")).encode("utf-8")
    else:
        kdf_block = b""

    # Generate a random nonce for metadata encryption
    meta_nonce = generate_nonce(NONCE_SIZE_GCM)

    # Derive metadata encryption key from the user's encryption key via HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=meta_nonce,
        info=b"filanti-meta-v2",
        backend=default_backend(),
    )
    meta_key = hkdf.derive(encryption_key)

    # Encrypt metadata using AES-GCM
    meta_plaintext = metadata.to_bytes()
    meta_cipher = AESGCM(meta_key)
    meta_ciphertext = meta_cipher.encrypt(meta_nonce, meta_plaintext, None)

    # Assemble file
    parts = [
        header_b64,                                    # Base64 header
        len(header_b64).to_bytes(2, "big"),           # Header length (2 bytes)
    ]

    # v2.1: KDF block
    if format_id == 3:
        parts.append(len(kdf_block).to_bytes(2, "big"))   # KDF block length (2 bytes)
        parts.append(kdf_block)                            # KDF block

    parts.extend([
        meta_nonce,                                    # Metadata nonce (12 bytes)
        len(meta_ciphertext).to_bytes(4, "big"),      # Encrypted metadata length (4 bytes)
        meta_ciphertext,                               # Encrypted metadata
        ciphertext,                                    # File ciphertext
    ])

    return b"".join(parts)


def _build_encrypted_file_v1(ciphertext: bytes, metadata: EncryptionMetadata) -> bytes:
    """Build encrypted file with legacy v1 format (plaintext metadata).

    .. deprecated:: 2.1.0
        v1 format exposes all cryptographic metadata in plaintext.
        Use ``_build_encrypted_file()`` with v2/v2.1 format instead.

    File format v1 (legacy):
    - 4 bytes: Magic ("FLNT")
    - 4 bytes: Metadata length (big-endian uint32)
    - N bytes: Metadata (JSON plaintext)
    - M bytes: Ciphertext
    """
    import warnings
    warnings.warn(
        "v1 format is deprecated — metadata is stored in plaintext. "
        "Use _build_encrypted_file() with encrypted metadata instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    meta_bytes = metadata.to_bytes()
    meta_length = len(meta_bytes).to_bytes(4, "big")

    return FILANTI_MAGIC + meta_length + meta_bytes + ciphertext


def parse_encrypted_file(data: bytes, encryption_key: bytes | None = None) -> tuple[EncryptionMetadata, bytes]:
    """Parse encrypted file header and extract ciphertext.

    Supports both v1 (legacy) and v2 formats.

    Args:
        data: Encrypted file bytes.
        encryption_key: Optional encryption key for v2 metadata decryption.

    Returns:
        Tuple of (metadata, ciphertext).

    Raises:
        EncryptionError: If file format is invalid.
    """
    if len(data) < 8:
        raise EncryptionError("Invalid encrypted file: too short")

    # Check for v1 format (starts with raw FLNT magic bytes)
    if data[:4] == FILANTI_MAGIC:
        return _parse_encrypted_file_v1(data)

    # Try v2 format (starts with base64-encoded header)
    return _parse_encrypted_file_v2(data, encryption_key)


def _parse_encrypted_file_v1(data: bytes) -> tuple[EncryptionMetadata, bytes]:
    """Parse legacy v1 format encrypted file."""
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


def extract_kdf_block(data: bytes) -> dict | None:
    """Extract KDF parameters from a v2.1 encrypted file without decrypting metadata.

    This is used by password-based decryption to obtain salt and KDF parameters
    before key derivation — solving the chicken-and-egg problem without
    storing sensitive metadata in plaintext.

    Args:
        data: Encrypted file bytes.

    Returns:
        Dict with keys ``"s"`` (salt hex), ``"a"`` (KDF algorithm),
        ``"p"`` (KDF params dict), or ``None`` if the file is not v2.1
        (e.g., v1 legacy format or v2 without KDF block).

    Raises:
        EncryptionError: If header parsing fails.
    """
    if len(data) < 8:
        return None

    # v1 files start with raw FLNT magic — no KDF block
    if data[:4] == FILANTI_MAGIC:
        return None

    # Scan for v2 base64 header
    for try_len in range(20, 64):
        if try_len + 2 > len(data):
            break
        potential_len = int.from_bytes(data[try_len:try_len+2], "big")
        if potential_len == try_len:
            try:
                header = FileHeader.from_base64(data[:try_len])
                if not header.validate():
                    continue

                # Only v2.1 (format_id=3) has a KDF block
                if header.format_id != 3:
                    return None

                offset = try_len + 2  # past header + header_len

                # Read KDF block length
                if len(data) < offset + 2:
                    return None
                kdf_block_len = int.from_bytes(data[offset:offset+2], "big")
                offset += 2

                if kdf_block_len == 0 or kdf_block_len > 4096:
                    return None
                if len(data) < offset + kdf_block_len:
                    return None

                kdf_block = data[offset:offset + kdf_block_len]
                return json.loads(kdf_block.decode("utf-8"))

            except (Exception, ValueError):
                continue

    return None


def _parse_encrypted_file_v2(data: bytes, encryption_key: bytes | None = None) -> tuple[EncryptionMetadata, bytes]:
    """Parse v2/v2.1 format encrypted file with encrypted metadata.

    File format v2 (format_id=2):
    - N bytes: Base64 header
    - 2 bytes: Header length
    - 12 bytes: Metadata nonce
    - 4 bytes: Encrypted metadata length
    - M bytes: Encrypted metadata
    - K bytes: File ciphertext

    File format v2.1 (format_id=3, with KDF block):
    - N bytes: Base64 header (includes "f":3)
    - 2 bytes: Header length
    - 2 bytes: KDF block length
    - J bytes: KDF block (JSON with salt, algorithm, params)
    - 12 bytes: Metadata nonce
    - 4 bytes: Encrypted metadata length
    - M bytes: Encrypted metadata
    - K bytes: File ciphertext
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    try:
        # Find header boundary by scanning for valid base64 header
        header_b64 = None
        header_len_pos = None
        header = None

        for try_len in range(20, 64):
            if try_len + 2 > len(data):
                break
            potential_header = data[:try_len]
            potential_len = int.from_bytes(data[try_len:try_len+2], "big")
            if potential_len == try_len:
                # Found matching header length
                try:
                    header = FileHeader.from_base64(potential_header)
                    header_b64 = potential_header
                    header_len_pos = try_len
                    break
                except (Exception, ValueError):
                    continue

        if header_b64 is None or header_len_pos is None or header is None:
            raise EncryptionError("Invalid encrypted file: cannot parse v2 header")

        # Parse and validate header
        if not header.validate():
            raise EncryptionError("Invalid encrypted file: wrong product identifier")

        offset = header_len_pos + 2  # Skip header + header length bytes

        # v2.1: Read KDF block if format_id == 3
        kdf_info = None
        if header.format_id == 3:
            if len(data) < offset + 2:
                raise EncryptionError("Invalid encrypted file: truncated KDF block length")
            kdf_block_len = int.from_bytes(data[offset:offset+2], "big")
            offset += 2

            if kdf_block_len > 0:
                if kdf_block_len > 4096:
                    raise EncryptionError("Invalid encrypted file: KDF block too large")
                if len(data) < offset + kdf_block_len:
                    raise EncryptionError("Invalid encrypted file: truncated KDF block")
                kdf_block = data[offset:offset + kdf_block_len]
                try:
                    kdf_info = json.loads(kdf_block.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    raise EncryptionError(f"Invalid KDF block: {e}") from e
                offset += kdf_block_len

        # Read metadata nonce (12 bytes)
        if len(data) < offset + NONCE_SIZE_GCM:
            raise EncryptionError("Invalid encrypted file: truncated")

        meta_nonce = data[offset:offset + NONCE_SIZE_GCM]
        offset += NONCE_SIZE_GCM

        # Read encrypted metadata length
        if len(data) < offset + 4:
            raise EncryptionError("Invalid encrypted file: truncated")

        encrypted_meta_len = int.from_bytes(data[offset:offset+4], "big")
        offset += 4

        # Read encrypted metadata
        if len(data) < offset + encrypted_meta_len:
            raise EncryptionError("Invalid encrypted file: truncated metadata")

        meta_ciphertext = data[offset:offset + encrypted_meta_len]
        offset += encrypted_meta_len

        # Extract file ciphertext
        ciphertext = data[offset:]

        # Derive metadata decryption key from encryption key via HKDF
        if encryption_key is None:
            raise EncryptionError(
                "Cannot decrypt v2 metadata without encryption key. "
                "For password-based files, derive the key from the KDF block first."
            )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=meta_nonce,
            info=b"filanti-meta-v2",
            backend=default_backend(),
        )
        meta_key = hkdf.derive(encryption_key)

        # Decrypt metadata
        meta_cipher = AESGCM(meta_key)
        try:
            meta_plaintext = meta_cipher.decrypt(meta_nonce, meta_ciphertext, None)
        except InvalidTag:
            raise EncryptionError("Invalid encrypted file: metadata authentication failed (wrong key?)")

        # Parse metadata
        metadata = EncryptionMetadata.from_bytes(meta_plaintext)

        # For v2.1 files, populate KDF fields from the KDF block into metadata
        if kdf_info is not None:
            metadata.salt = kdf_info.get("s")
            metadata.kdf_algorithm = kdf_info.get("a")
            metadata.kdf_params = kdf_info.get("p")

        return metadata, ciphertext

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"Invalid encrypted file format: {e}") from e


