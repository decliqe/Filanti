"""
Checksum module.

Provides fast non-cryptographic checksums for quick file integrity checks.
These are NOT suitable for security purposes but are useful for:
- Detecting accidental corruption
- Quick file comparison
- Data deduplication

Supported algorithms:
- CRC32 (default, fastest, widely compatible)
- Adler32 (fast, slightly better error detection)
- XXHash64 (very fast, good distribution)
"""

import json
import zlib
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO

from filanti.core.errors import IntegrityError, FileOperationError


class ChecksumAlgorithm(str, Enum):
    """Supported checksum algorithms."""

    CRC32 = "crc32"
    ADLER32 = "adler32"
    XXHASH64 = "xxhash64"


# Default algorithm for checksum operations
DEFAULT_ALGORITHM = ChecksumAlgorithm.CRC32

# Chunk size for streaming operations (64 KB)
CHUNK_SIZE = 65536


@dataclass
class ChecksumResult:
    """Container for checksum computation result."""

    checksum: int
    algorithm: str
    created_at: str

    def to_hex(self) -> str:
        """Get checksum as hex string."""
        if self.algorithm == ChecksumAlgorithm.XXHASH64.value:
            return f"{self.checksum:016x}"  # 16 hex chars for 64-bit
        return f"{self.checksum:08x}"  # 8 hex chars for 32-bit

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "checksum": self.to_hex(),
            "checksum_int": self.checksum,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ChecksumResult":
        """Create from dictionary."""
        checksum = data.get("checksum_int", int(data["checksum"], 16))
        return cls(
            checksum=checksum,
            algorithm=data["algorithm"],
            created_at=data["created_at"],
        )


@dataclass
class ChecksumMetadata:
    """Detached checksum metadata for files."""

    version: str = "1.0"
    checksum: str | None = None  # hex-encoded
    algorithm: str | None = None
    filename: str | None = None
    filesize: int | None = None
    created_at: str | None = None

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> "ChecksumMetadata":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls(**data)

    def save(self, path: str | Path) -> None:
        """Save metadata to file."""
        path = Path(path)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "ChecksumMetadata":
        """Load metadata from file."""
        path = Path(path)
        return cls.from_json(path.read_text(encoding="utf-8"))


def _normalize_algorithm(algorithm: ChecksumAlgorithm | str) -> ChecksumAlgorithm:
    """Normalize algorithm to enum."""
    if isinstance(algorithm, str):
        try:
            return ChecksumAlgorithm(algorithm.lower())
        except ValueError:
            raise IntegrityError(
                f"Unsupported checksum algorithm: {algorithm}",
                algorithm=algorithm,
                context={"supported": [a.value for a in ChecksumAlgorithm]},
            )
    return algorithm


def _get_xxhash():
    """Get xxhash module, raising helpful error if not installed."""
    try:
        import xxhash
        return xxhash
    except ImportError:
        raise IntegrityError(
            "xxhash library not installed. Install with: pip install xxhash",
            algorithm="xxhash64",
            context={"install_command": "pip install xxhash"},
        )


def compute_checksum(
    data: bytes,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
) -> ChecksumResult:
    """Compute checksum of bytes.

    Args:
        data: Data to checksum.
        algorithm: Checksum algorithm to use.

    Returns:
        ChecksumResult containing the computed checksum.

    Raises:
        IntegrityError: If checksum computation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        if algorithm == ChecksumAlgorithm.CRC32:
            value = zlib.crc32(data) & 0xFFFFFFFF  # Ensure unsigned
        elif algorithm == ChecksumAlgorithm.ADLER32:
            value = zlib.adler32(data) & 0xFFFFFFFF
        elif algorithm == ChecksumAlgorithm.XXHASH64:
            xxhash = _get_xxhash()
            value = xxhash.xxh64(data).intdigest()
        else:
            raise IntegrityError(
                f"Unsupported checksum algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        return ChecksumResult(
            checksum=value,
            algorithm=algorithm.value,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
    except IntegrityError:
        raise
    except Exception as e:
        raise IntegrityError(
            f"Failed to compute checksum: {e}",
            algorithm=algorithm.value,
        ) from e


def verify_checksum(
    data: bytes,
    expected: int,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify checksum of bytes.

    Args:
        data: Data to verify.
        expected: Expected checksum value.
        algorithm: Checksum algorithm used.

    Returns:
        True if checksum matches.

    Raises:
        IntegrityError: If checksum does not match.
    """
    result = compute_checksum(data, algorithm)

    if result.checksum != expected:
        raise IntegrityError(
            "Checksum verification failed: data may be corrupted",
            algorithm=result.algorithm,
            expected=f"{expected:08x}",
            actual=result.to_hex(),
        )
    return True


def compute_checksum_stream(
    stream: BinaryIO,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
    chunk_size: int = CHUNK_SIZE,
) -> ChecksumResult:
    """Compute checksum of a stream.

    Memory-efficient for large files.

    Args:
        stream: Binary stream to read from.
        algorithm: Checksum algorithm to use.
        chunk_size: Size of chunks to read.

    Returns:
        ChecksumResult containing the computed checksum.

    Raises:
        IntegrityError: If checksum computation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        if algorithm == ChecksumAlgorithm.CRC32:
            value = 0
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                value = zlib.crc32(chunk, value)
            value = value & 0xFFFFFFFF

        elif algorithm == ChecksumAlgorithm.ADLER32:
            value = 1  # Adler32 starts with 1
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                value = zlib.adler32(chunk, value)
            value = value & 0xFFFFFFFF

        elif algorithm == ChecksumAlgorithm.XXHASH64:
            xxhash = _get_xxhash()
            hasher = xxhash.xxh64()
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
            value = hasher.intdigest()

        else:
            raise IntegrityError(
                f"Unsupported checksum algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        return ChecksumResult(
            checksum=value,
            algorithm=algorithm.value,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    except IntegrityError:
        raise
    except Exception as e:
        raise IntegrityError(
            f"Failed to compute checksum from stream: {e}",
            algorithm=algorithm.value,
        ) from e


def compute_file_checksum(
    file_path: str | Path,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
) -> ChecksumResult:
    """Compute checksum of a file.

    Args:
        file_path: Path to file.
        algorithm: Checksum algorithm to use.

    Returns:
        ChecksumResult containing the computed checksum.

    Raises:
        IntegrityError: If checksum computation fails.
        FileOperationError: If file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileOperationError(
            f"File not found: {file_path}",
            path=str(file_path),
            operation="compute_checksum",
        )

    try:
        with open(file_path, "rb") as f:
            return compute_checksum_stream(f, algorithm)
    except IntegrityError:
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to read file for checksum: {e}",
            path=str(file_path),
            operation="compute_checksum",
        ) from e


def verify_file_checksum(
    file_path: str | Path,
    expected: int,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify checksum of a file.

    Args:
        file_path: Path to file.
        expected: Expected checksum value.
        algorithm: Checksum algorithm used.

    Returns:
        True if checksum matches.

    Raises:
        IntegrityError: If checksum does not match.
        FileOperationError: If file cannot be read.
    """
    result = compute_file_checksum(file_path, algorithm)

    if result.checksum != expected:
        raise IntegrityError(
            "File checksum verification failed: file may be corrupted",
            algorithm=result.algorithm,
            expected=f"{expected:08x}" if algorithm != ChecksumAlgorithm.XXHASH64 else f"{expected:016x}",
            actual=result.to_hex(),
        )
    return True


def create_checksum_file(
    file_path: str | Path,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
    output_path: str | Path | None = None,
) -> Path:
    """Create detached checksum file.

    Args:
        file_path: Path to file to checksum.
        algorithm: Checksum algorithm to use.
        output_path: Optional output path (default: file_path + '.checksum')

    Returns:
        Path to the created checksum file.

    Raises:
        IntegrityError: If checksum computation fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + ".checksum")

    result = compute_file_checksum(file_path, algorithm)

    metadata = ChecksumMetadata(
        checksum=result.to_hex(),
        algorithm=result.algorithm,
        filename=file_path.name,
        filesize=file_path.stat().st_size,
        created_at=result.created_at,
    )

    try:
        metadata.save(output_path)
        return output_path
    except Exception as e:
        raise FileOperationError(
            f"Failed to save checksum metadata: {e}",
            path=str(output_path),
            operation="create_checksum_file",
        ) from e


def verify_checksum_file(
    file_path: str | Path,
    metadata_path: str | Path | None = None,
) -> bool:
    """Verify file using detached checksum metadata.

    Args:
        file_path: Path to file to verify.
        metadata_path: Optional metadata path (default: file_path + '.checksum')

    Returns:
        True if checksum verification passes.

    Raises:
        IntegrityError: If verification fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    metadata_path = Path(metadata_path) if metadata_path else file_path.with_suffix(file_path.suffix + ".checksum")

    if not metadata_path.exists():
        raise FileOperationError(
            f"Checksum metadata not found: {metadata_path}",
            path=str(metadata_path),
            operation="verify_checksum_file",
        )

    try:
        metadata = ChecksumMetadata.load(metadata_path)
    except Exception as e:
        raise IntegrityError(
            f"Failed to load checksum metadata: {e}",
            context={"metadata_path": str(metadata_path)},
        ) from e

    if not metadata.checksum or not metadata.algorithm:
        raise IntegrityError(
            "Invalid checksum metadata: missing checksum or algorithm",
            context={"metadata_path": str(metadata_path)},
        )

    expected = int(metadata.checksum, 16)
    return verify_file_checksum(file_path, expected, metadata.algorithm)


def generate_checksum_line(
    file_path: str | Path,
    algorithm: ChecksumAlgorithm | str = DEFAULT_ALGORITHM,
) -> str:
    """Generate checksum line in standard format.

    Format: "checksum  filename" (compatible with common checksum tools)

    Args:
        file_path: Path to file.
        algorithm: Checksum algorithm to use.

    Returns:
        Checksum line string.
    """
    file_path = Path(file_path)
    result = compute_file_checksum(file_path, algorithm)
    return f"{result.to_hex()}  {file_path.name}"


def parse_checksum_line(line: str) -> tuple[str, str]:
    """Parse a standard checksum line.

    Format: "checksum  filename" or "checksum *filename" (binary mode indicator)

    Args:
        line: Checksum line to parse.

    Returns:
        Tuple of (checksum_hex, filename).

    Raises:
        IntegrityError: If line format is invalid.
    """
    line = line.strip()
    if not line:
        raise IntegrityError("Empty checksum line")

    # Try standard format with two spaces
    parts = line.split("  ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]

    # Try binary mode format with space and asterisk
    parts = line.split(" *", 1)
    if len(parts) == 2:
        return parts[0], parts[1]

    # Try single space
    parts = line.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]

    raise IntegrityError(
        f"Invalid checksum line format: {line}",
        context={"expected_format": "checksum  filename"},
    )

