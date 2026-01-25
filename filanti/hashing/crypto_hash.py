"""
Cryptographic hashing module.

Provides secure hashing operations using standard cryptographic
hash functions from the cryptography library.

Supported algorithms:
- SHA-256 (default, recommended for general use)
- SHA-384
- SHA-512
- SHA3-256
- SHA3-384
- SHA3-512
- BLAKE2b (high performance)
"""

from collections.abc import Generator, Iterable
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from filanti.core.errors import HashingError, ValidationError
from filanti.core.file_manager import FileManager, get_file_manager
from filanti.core.secure_memory import secure_compare


class HashAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms."""

    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    SHA3_256 = "sha3-256"
    SHA3_384 = "sha3-384"
    SHA3_512 = "sha3-512"
    BLAKE2B = "blake2b"


# Default algorithm for all hashing operations
DEFAULT_ALGORITHM = HashAlgorithm.SHA256


# Map algorithm enum to cryptography hash classes
_ALGORITHM_MAP: dict[HashAlgorithm, type[hashes.HashAlgorithm]] = {
    HashAlgorithm.SHA256: hashes.SHA256,
    HashAlgorithm.SHA384: hashes.SHA384,
    HashAlgorithm.SHA512: hashes.SHA512,
    HashAlgorithm.SHA3_256: hashes.SHA3_256,
    HashAlgorithm.SHA3_384: hashes.SHA3_384,
    HashAlgorithm.SHA3_512: hashes.SHA3_512,
    HashAlgorithm.BLAKE2B: hashes.BLAKE2b,
}


def _get_hash_algorithm(algorithm: HashAlgorithm | str) -> hashes.HashAlgorithm:
    """Get cryptography hash algorithm instance.

    Args:
        algorithm: Algorithm enum or string name.

    Returns:
        Cryptography hash algorithm instance.

    Raises:
        HashingError: If algorithm is not supported.
    """
    # Normalize string to enum
    if isinstance(algorithm, str):
        try:
            algorithm = HashAlgorithm(algorithm.lower())
        except ValueError:
            raise HashingError(
                f"Unsupported hash algorithm: {algorithm}",
                algorithm=algorithm,
                context={"supported": [a.value for a in HashAlgorithm]},
            )

    hash_class = _ALGORITHM_MAP.get(algorithm)
    if hash_class is None:
        raise HashingError(
            f"Unsupported hash algorithm: {algorithm}",
            algorithm=algorithm.value if hasattr(algorithm, 'value') else str(algorithm),
        )

    # BLAKE2b requires a digest size parameter
    if algorithm == HashAlgorithm.BLAKE2B:
        return hash_class(64)  # 512-bit output

    return hash_class()


def hash_bytes(
    data: bytes,
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
) -> str:
    """Compute cryptographic hash of bytes.

    Args:
        data: Bytes to hash.
        algorithm: Hash algorithm to use (default: SHA-256).

    Returns:
        Hexadecimal digest string.

    Raises:
        HashingError: If hashing fails.
    """
    try:
        hasher = hashes.Hash(_get_hash_algorithm(algorithm), backend=default_backend())
        hasher.update(data)
        digest = hasher.finalize()
        return digest.hex()
    except Exception as e:
        if isinstance(e, HashingError):
            raise
        alg_str = algorithm.value if isinstance(algorithm, HashAlgorithm) else algorithm
        raise HashingError(
            f"Failed to hash data: {e}",
            algorithm=alg_str,
        ) from e


def hash_stream(
    stream: Iterable[bytes],
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
) -> str:
    """Compute cryptographic hash from a stream of bytes.

    Memory-efficient hashing for large data sources.

    Args:
        stream: Iterable yielding bytes chunks.
        algorithm: Hash algorithm to use (default: SHA-256).

    Returns:
        Hexadecimal digest string.

    Raises:
        HashingError: If hashing fails.
    """
    try:
        hasher = hashes.Hash(_get_hash_algorithm(algorithm), backend=default_backend())
        for chunk in stream:
            hasher.update(chunk)
        digest = hasher.finalize()
        return digest.hex()
    except Exception as e:
        if isinstance(e, HashingError):
            raise
        alg_str = algorithm.value if isinstance(algorithm, HashAlgorithm) else algorithm
        raise HashingError(
            f"Failed to hash stream: {e}",
            algorithm=alg_str,
        ) from e


def hash_file(
    path: str | Path,
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
    file_manager: FileManager | None = None,
) -> str:
    """Compute cryptographic hash of a file.

    Uses streaming to efficiently hash large files without
    loading them entirely into memory.

    Args:
        path: Path to file to hash.
        algorithm: Hash algorithm to use (default: SHA-256).
        file_manager: Optional FileManager instance.

    Returns:
        Hexadecimal digest string.

    Raises:
        HashingError: If hashing fails.
        FileOperationError: If file cannot be read.
    """
    fm = file_manager or get_file_manager()

    try:
        stream = fm.stream_read(path)
        return hash_stream(stream, algorithm)
    except HashingError:
        raise
    except Exception as e:
        alg_str = algorithm.value if isinstance(algorithm, HashAlgorithm) else algorithm
        raise HashingError(
            f"Failed to hash file: {e}",
            algorithm=alg_str,
            context={"path": str(path)},
        ) from e


def hash_handle(
    handle: BinaryIO,
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
    file_manager: FileManager | None = None,
) -> str:
    """Compute cryptographic hash from a file handle.

    Args:
        handle: Open binary file handle.
        algorithm: Hash algorithm to use (default: SHA-256).
        file_manager: Optional FileManager instance.

    Returns:
        Hexadecimal digest string.

    Raises:
        HashingError: If hashing fails.
    """
    fm = file_manager or get_file_manager()

    try:
        stream = fm.stream_from_handle(handle)
        return hash_stream(stream, algorithm)
    except HashingError:
        raise
    except Exception as e:
        alg_str = algorithm.value if isinstance(algorithm, HashAlgorithm) else algorithm
        raise HashingError(
            f"Failed to hash from handle: {e}",
            algorithm=alg_str,
        ) from e


def verify_hash(
    data: bytes,
    expected_hash: str,
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify that data matches expected hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        data: Bytes to verify.
        expected_hash: Expected hexadecimal hash string.
        algorithm: Hash algorithm used (default: SHA-256).

    Returns:
        True if hash matches, False otherwise.

    Raises:
        HashingError: If hashing fails.
        ValidationError: If expected_hash format is invalid.
    """
    # Validate expected hash format
    try:
        expected_bytes = bytes.fromhex(expected_hash)
    except ValueError as e:
        raise ValidationError(
            "Invalid hash format: expected hexadecimal string",
            expected=expected_hash,
        ) from e

    actual_hash = hash_bytes(data, algorithm)
    actual_bytes = bytes.fromhex(actual_hash)

    return secure_compare(expected_bytes, actual_bytes)


def verify_file_hash(
    path: str | Path,
    expected_hash: str,
    algorithm: HashAlgorithm | str = DEFAULT_ALGORITHM,
    file_manager: FileManager | None = None,
) -> bool:
    """Verify that a file matches expected hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        path: Path to file to verify.
        expected_hash: Expected hexadecimal hash string.
        algorithm: Hash algorithm used (default: SHA-256).
        file_manager: Optional FileManager instance.

    Returns:
        True if hash matches, False otherwise.

    Raises:
        HashingError: If hashing fails.
        FileOperationError: If file cannot be read.
        ValidationError: If expected_hash format is invalid.
    """
    # Validate expected hash format
    try:
        expected_bytes = bytes.fromhex(expected_hash)
    except ValueError as e:
        raise ValidationError(
            "Invalid hash format: expected hexadecimal string",
            expected=expected_hash,
        ) from e

    actual_hash = hash_file(path, algorithm, file_manager)
    actual_bytes = bytes.fromhex(actual_hash)

    return secure_compare(expected_bytes, actual_bytes)


def get_supported_algorithms() -> list[str]:
    """Get list of supported hash algorithm names.

    Returns:
        List of algorithm name strings.
    """
    return [alg.value for alg in HashAlgorithm]

