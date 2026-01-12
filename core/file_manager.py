"""
File Manager - Secure file I/O operations.

Provides a safe abstraction layer for file operations with built-in
error handling, path validation, and streaming support for large files.
"""

from collections.abc import Generator
from pathlib import Path
from typing import BinaryIO

from filanti.core.errors import FileOperationError


# Default buffer size for streaming operations (64 KB)
DEFAULT_BUFFER_SIZE = 65536


class FileManager:
    """Secure file manager with streaming support and error handling.

    Provides safe file operations with:
    - Path validation and normalization
    - Streaming for large files
    - Consistent error handling
    - Context manager support
    """

    def __init__(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> None:
        """Initialize FileManager.

        Args:
            buffer_size: Size of buffer for streaming operations in bytes.
        """
        if buffer_size <= 0:
            raise ValueError("Buffer size must be positive")
        self._buffer_size = buffer_size

    @property
    def buffer_size(self) -> int:
        """Return the buffer size for streaming operations."""
        return self._buffer_size

    @staticmethod
    def validate_path(path: str | Path) -> Path:
        """Validate and normalize a file path.

        Args:
            path: Path to validate.

        Returns:
            Normalized Path object.

        Raises:
            FileOperationError: If path is invalid or empty.
        """
        if not path:
            raise FileOperationError("Path cannot be empty", operation="validate")

        try:
            normalized = Path(path).resolve()
            return normalized
        except (OSError, ValueError) as e:
            raise FileOperationError(
                f"Invalid path: {e}",
                path=str(path),
                operation="validate",
            ) from e

    def exists(self, path: str | Path) -> bool:
        """Check if a file exists.

        Args:
            path: Path to check.

        Returns:
            True if file exists, False otherwise.
        """
        try:
            validated = self.validate_path(path)
            return validated.exists() and validated.is_file()
        except FileOperationError:
            return False

    def read_bytes(self, path: str | Path) -> bytes:
        """Read entire file contents as bytes.

        Args:
            path: Path to file to read.

        Returns:
            File contents as bytes.

        Raises:
            FileOperationError: If file cannot be read.
        """
        validated = self.validate_path(path)

        if not validated.exists():
            raise FileOperationError(
                "File not found",
                path=str(validated),
                operation="read",
            )

        if not validated.is_file():
            raise FileOperationError(
                "Path is not a file",
                path=str(validated),
                operation="read",
            )

        try:
            return validated.read_bytes()
        except PermissionError as e:
            raise FileOperationError(
                "Permission denied",
                path=str(validated),
                operation="read",
            ) from e
        except OSError as e:
            raise FileOperationError(
                f"Failed to read file: {e}",
                path=str(validated),
                operation="read",
            ) from e

    def write_bytes(self, path: str | Path, data: bytes) -> int:
        """Write bytes to a file.

        Args:
            path: Path to file to write.
            data: Bytes to write.

        Returns:
            Number of bytes written.

        Raises:
            FileOperationError: If file cannot be written.
        """
        validated = self.validate_path(path)

        try:
            # Create parent directories if needed
            validated.parent.mkdir(parents=True, exist_ok=True)
            return validated.write_bytes(data)
        except PermissionError as e:
            raise FileOperationError(
                "Permission denied",
                path=str(validated),
                operation="write",
            ) from e
        except OSError as e:
            raise FileOperationError(
                f"Failed to write file: {e}",
                path=str(validated),
                operation="write",
            ) from e

    def stream_read(self, path: str | Path) -> Generator[bytes, None, None]:
        """Stream file contents in chunks.

        Yields chunks of the file for memory-efficient processing
        of large files.

        Args:
            path: Path to file to read.

        Yields:
            Chunks of file content as bytes.

        Raises:
            FileOperationError: If file cannot be read.
        """
        validated = self.validate_path(path)

        if not validated.exists():
            raise FileOperationError(
                "File not found",
                path=str(validated),
                operation="stream_read",
            )

        try:
            with open(validated, "rb") as f:
                while chunk := f.read(self._buffer_size):
                    yield chunk
        except PermissionError as e:
            raise FileOperationError(
                "Permission denied",
                path=str(validated),
                operation="stream_read",
            ) from e
        except OSError as e:
            raise FileOperationError(
                f"Failed to stream file: {e}",
                path=str(validated),
                operation="stream_read",
            ) from e

    def stream_from_handle(self, handle: BinaryIO) -> Generator[bytes, None, None]:
        """Stream content from an open file handle.

        Args:
            handle: Open binary file handle.

        Yields:
            Chunks of content as bytes.
        """
        while chunk := handle.read(self._buffer_size):
            yield chunk

    def get_size(self, path: str | Path) -> int:
        """Get file size in bytes.

        Args:
            path: Path to file.

        Returns:
            File size in bytes.

        Raises:
            FileOperationError: If file size cannot be determined.
        """
        validated = self.validate_path(path)

        if not validated.exists():
            raise FileOperationError(
                "File not found",
                path=str(validated),
                operation="get_size",
            )

        try:
            return validated.stat().st_size
        except OSError as e:
            raise FileOperationError(
                f"Failed to get file size: {e}",
                path=str(validated),
                operation="get_size",
            ) from e

    def delete(self, path: str | Path) -> None:
        """Delete a file.

        Args:
            path: Path to file to delete.

        Raises:
            FileOperationError: If file cannot be deleted.
        """
        validated = self.validate_path(path)

        if not validated.exists():
            raise FileOperationError(
                "File not found",
                path=str(validated),
                operation="delete",
            )

        try:
            validated.unlink()
        except PermissionError as e:
            raise FileOperationError(
                "Permission denied",
                path=str(validated),
                operation="delete",
            ) from e
        except OSError as e:
            raise FileOperationError(
                f"Failed to delete file: {e}",
                path=str(validated),
                operation="delete",
            ) from e


# Default singleton instance for convenience
_default_manager: FileManager | None = None


def get_file_manager() -> FileManager:
    """Get the default FileManager instance.

    Returns:
        Default FileManager singleton.
    """
    global _default_manager
    if _default_manager is None:
        _default_manager = FileManager()
    return _default_manager

