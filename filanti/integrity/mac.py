"""
Message Authentication Code (MAC) module.

Provides HMAC-based integrity verification to detect tampering.
All MAC operations use cryptographic hash functions for security.

Supported algorithms:
- HMAC-SHA256 (default, recommended for general use)
- HMAC-SHA384
- HMAC-SHA512
- HMAC-SHA3-256
- HMAC-BLAKE2b
"""

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from filanti.core.errors import IntegrityError, FileOperationError
from filanti.core.secure_memory import secure_compare


class MACAlgorithm(str, Enum):
    """Supported HMAC algorithms."""

    HMAC_SHA256 = "hmac-sha256"
    HMAC_SHA384 = "hmac-sha384"
    HMAC_SHA512 = "hmac-sha512"
    HMAC_SHA3_256 = "hmac-sha3-256"
    HMAC_BLAKE2B = "hmac-blake2b"


# Default algorithm for MAC operations
DEFAULT_ALGORITHM = MACAlgorithm.HMAC_SHA256

# Chunk size for streaming operations (64 KB)
CHUNK_SIZE = 65536


# Map algorithm enum to cryptography hash classes
_ALGORITHM_MAP: dict[MACAlgorithm, type[hashes.HashAlgorithm]] = {
    MACAlgorithm.HMAC_SHA256: hashes.SHA256,
    MACAlgorithm.HMAC_SHA384: hashes.SHA384,
    MACAlgorithm.HMAC_SHA512: hashes.SHA512,
    MACAlgorithm.HMAC_SHA3_256: hashes.SHA3_256,
    MACAlgorithm.HMAC_BLAKE2B: hashes.BLAKE2b,
}


@dataclass
class MACResult:
    """Container for MAC computation result."""

    mac: bytes
    algorithm: str
    created_at: str

    def to_hex(self) -> str:
        """Get MAC as hex string."""
        return self.mac.hex()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "mac": self.mac.hex(),
            "algorithm": self.algorithm,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MACResult":
        """Create from dictionary."""
        return cls(
            mac=bytes.fromhex(data["mac"]),
            algorithm=data["algorithm"],
            created_at=data["created_at"],
        )


@dataclass
class IntegrityMetadata:
    """Detached integrity metadata for files."""

    version: str = "1.0"
    mac: str | None = None  # hex-encoded
    algorithm: str | None = None
    filename: str | None = None
    filesize: int | None = None
    created_at: str | None = None

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=indent, sort_keys=True)

    def to_json_minimal(self) -> str:
        """Serialize to minimal JSON (reduced information leakage)."""
        # Only include essential fields: version, mac, algorithm
        # Omit: filename, filesize, created_at
        minimal = {
            "v": "2",  # Minimal format version
            "m": self.mac,
            "a": self._short_algorithm(self.algorithm) if self.algorithm else None,
        }
        return json.dumps(minimal, separators=(",", ":"))

    @staticmethod
    def _short_algorithm(algorithm: str) -> str:
        """Convert algorithm to short form."""
        short_map = {
            "hmac-sha256": "hs256",
            "hmac-sha384": "hs384",
            "hmac-sha512": "hs512",
            "hmac-sha3-256": "hs3256",
            "hmac-blake2b": "hb2b",
        }
        return short_map.get(algorithm, algorithm)

    @staticmethod
    def _expand_algorithm(short: str) -> str:
        """Convert short algorithm to full form."""
        expand_map = {
            "hs256": "hmac-sha256",
            "hs384": "hmac-sha384",
            "hs512": "hmac-sha512",
            "hs3256": "hmac-sha3-256",
            "hb2b": "hmac-blake2b",
        }
        return expand_map.get(short, short)

    @classmethod
    def from_json(cls, json_str: str) -> "IntegrityMetadata":
        """Deserialize from JSON string (supports v1 and v2/minimal formats)."""
        data = json.loads(json_str)

        # Check for minimal v2 format
        if "v" in data and data.get("v") == "2":
            return cls(
                version="2.0",
                mac=data.get("m"),
                algorithm=cls._expand_algorithm(data.get("a", "")),
            )

        # Standard v1 format
        return cls(**data)

    def save(self, path: str | Path, minimal: bool = False) -> None:
        """Save metadata to file.

        Args:
            path: Output path.
            minimal: If True, use minimal format (reduced information leakage).
        """
        path = Path(path)
        if minimal:
            path.write_text(self.to_json_minimal(), encoding="utf-8")
        else:
            path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "IntegrityMetadata":
        """Load metadata from file."""
        path = Path(path)
        return cls.from_json(path.read_text(encoding="utf-8"))


def _get_hash_algorithm(algorithm: MACAlgorithm) -> hashes.HashAlgorithm:
    """Get cryptography hash algorithm instance for HMAC.

    Args:
        algorithm: MAC algorithm enum.

    Returns:
        Cryptography hash algorithm instance.

    Raises:
        IntegrityError: If algorithm is not supported.
    """
    hash_class = _ALGORITHM_MAP.get(algorithm)
    if hash_class is None:
        raise IntegrityError(
            f"Unsupported MAC algorithm: {algorithm}",
            algorithm=str(algorithm),
            context={"supported": [a.value for a in MACAlgorithm]},
        )

    # BLAKE2b requires a digest size parameter
    if algorithm == MACAlgorithm.HMAC_BLAKE2B:
        return hash_class(64)  # 512-bit output

    return hash_class()


def _normalize_algorithm(algorithm: MACAlgorithm | str) -> MACAlgorithm:
    """Normalize algorithm to enum."""
    if isinstance(algorithm, str):
        try:
            return MACAlgorithm(algorithm.lower())
        except ValueError:
            raise IntegrityError(
                f"Unsupported MAC algorithm: {algorithm}",
                algorithm=algorithm,
                context={"supported": [a.value for a in MACAlgorithm]},
            )
    return algorithm


def compute_mac(
    data: bytes,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
) -> MACResult:
    """Compute HMAC of bytes.

    Args:
        data: Data to authenticate.
        key: Secret key for HMAC.
        algorithm: MAC algorithm to use.

    Returns:
        MACResult containing the computed MAC.

    Raises:
        IntegrityError: If MAC computation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        hash_alg = _get_hash_algorithm(algorithm)
        h = hmac.HMAC(key, hash_alg, backend=default_backend())
        h.update(data)
        mac_value = h.finalize()

        return MACResult(
            mac=mac_value,
            algorithm=algorithm.value,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as e:
        raise IntegrityError(
            f"Failed to compute MAC: {e}",
            algorithm=algorithm.value,
        ) from e


def verify_mac(
    data: bytes,
    mac: bytes,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify HMAC of bytes.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        data: Data to verify.
        mac: Expected MAC value.
        key: Secret key for HMAC.
        algorithm: MAC algorithm used.

    Returns:
        True if MAC is valid.

    Raises:
        IntegrityError: If MAC is invalid or verification fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        hash_alg = _get_hash_algorithm(algorithm)
        h = hmac.HMAC(key, hash_alg, backend=default_backend())
        h.update(data)
        h.verify(mac)
        return True
    except InvalidSignature:
        raise IntegrityError(
            "MAC verification failed: data may have been tampered with",
            algorithm=algorithm.value,
        )
    except Exception as e:
        raise IntegrityError(
            f"MAC verification error: {e}",
            algorithm=algorithm.value,
        ) from e


def compute_mac_stream(
    stream: BinaryIO,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
    chunk_size: int = CHUNK_SIZE,
) -> MACResult:
    """Compute HMAC of a stream.

    Memory-efficient for large files.

    Args:
        stream: Binary stream to read from.
        key: Secret key for HMAC.
        algorithm: MAC algorithm to use.
        chunk_size: Size of chunks to read.

    Returns:
        MACResult containing the computed MAC.

    Raises:
        IntegrityError: If MAC computation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        hash_alg = _get_hash_algorithm(algorithm)
        h = hmac.HMAC(key, hash_alg, backend=default_backend())

        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)

        mac_value = h.finalize()

        return MACResult(
            mac=mac_value,
            algorithm=algorithm.value,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as e:
        raise IntegrityError(
            f"Failed to compute MAC from stream: {e}",
            algorithm=algorithm.value,
        ) from e


def compute_file_mac(
    file_path: str | Path,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
) -> MACResult:
    """Compute HMAC of a file.

    Args:
        file_path: Path to file.
        key: Secret key for HMAC.
        algorithm: MAC algorithm to use.

    Returns:
        MACResult containing the computed MAC.

    Raises:
        IntegrityError: If MAC computation fails.
        FileOperationError: If file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileOperationError(
            f"File not found: {file_path}",
            path=str(file_path),
            operation="compute_mac",
        )

    try:
        with open(file_path, "rb") as f:
            return compute_mac_stream(f, key, algorithm)
    except IntegrityError:
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to read file for MAC: {e}",
            path=str(file_path),
            operation="compute_mac",
        ) from e


def verify_file_mac(
    file_path: str | Path,
    mac: bytes,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify HMAC of a file.

    Args:
        file_path: Path to file.
        mac: Expected MAC value.
        key: Secret key for HMAC.
        algorithm: MAC algorithm used.

    Returns:
        True if MAC is valid.

    Raises:
        IntegrityError: If MAC is invalid.
        FileOperationError: If file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileOperationError(
            f"File not found: {file_path}",
            path=str(file_path),
            operation="verify_mac",
        )

    try:
        with open(file_path, "rb") as f:
            result = compute_mac_stream(f, key, algorithm)

        if not secure_compare(result.mac, mac):
            raise IntegrityError(
                "MAC verification failed: data may have been tampered with",
                algorithm=result.algorithm,
                expected=mac.hex(),
                actual=result.mac.hex(),
            )
        return True
    except IntegrityError:
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to verify file MAC: {e}",
            path=str(file_path),
            operation="verify_mac",
        ) from e


def create_integrity_file(
    file_path: str | Path,
    key: bytes,
    algorithm: MACAlgorithm | str = DEFAULT_ALGORITHM,
    output_path: str | Path | None = None,
    minimal: bool = False,
) -> Path:
    """Create detached integrity metadata file.

    Args:
        file_path: Path to file to protect.
        key: Secret key for HMAC.
        algorithm: MAC algorithm to use.
        output_path: Optional output path (default: file_path + '.mac')
        minimal: If True, use minimal format (reduced information leakage).
            Only includes version, MAC, and algorithm (no filename, filesize, timestamp).

    Returns:
        Path to the created integrity file.

    Raises:
        IntegrityError: If MAC computation fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + ".mac")

    result = compute_file_mac(file_path, key, algorithm)

    metadata = IntegrityMetadata(
        mac=result.to_hex(),
        algorithm=result.algorithm,
        filename=file_path.name if not minimal else None,
        filesize=file_path.stat().st_size if not minimal else None,
        created_at=result.created_at if not minimal else None,
    )

    try:
        metadata.save(output_path, minimal=minimal)
        return output_path
    except Exception as e:
        raise FileOperationError(
            f"Failed to save integrity metadata: {e}",
            path=str(output_path),
            operation="create_integrity_file",
        ) from e


def verify_integrity_file(
    file_path: str | Path,
    key: bytes,
    metadata_path: str | Path | None = None,
) -> bool:
    """Verify file integrity using detached metadata.

    Args:
        file_path: Path to file to verify.
        key: Secret key for HMAC.
        metadata_path: Optional metadata path (default: file_path + '.mac')

    Returns:
        True if integrity verification passes.

    Raises:
        IntegrityError: If verification fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    metadata_path = Path(metadata_path) if metadata_path else file_path.with_suffix(file_path.suffix + ".mac")

    if not metadata_path.exists():
        raise FileOperationError(
            f"Integrity metadata not found: {metadata_path}",
            path=str(metadata_path),
            operation="verify_integrity_file",
        )

    try:
        metadata = IntegrityMetadata.load(metadata_path)
    except Exception as e:
        raise IntegrityError(
            f"Failed to load integrity metadata: {e}",
            context={"metadata_path": str(metadata_path)},
        ) from e

    if not metadata.mac or not metadata.algorithm:
        raise IntegrityError(
            "Invalid integrity metadata: missing MAC or algorithm",
            context={"metadata_path": str(metadata_path)},
        )

    expected_mac = bytes.fromhex(metadata.mac)
    return verify_file_mac(file_path, expected_mac, key, metadata.algorithm)

