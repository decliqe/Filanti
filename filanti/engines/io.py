"""
IO Engine — Safe file access, streaming, and secure deletion.

Wraps ``filanti.core.file_manager.FileManager`` behind the engine
interface for orchestrator-controlled file operations.
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import BinaryIO

from filanti.core.errors import FileOperationError
from filanti.core.file_manager import FileManager, get_file_manager


class IOEngine:
    """Orchestrator-level wrapper around FileManager.

    Provides safe, confined file access that the orchestrator
    can audit and control.

    Note: IOEngine does not extend BaseEngine because it's a service
    used *by* other engines, not dispatched to by the router.
    """

    def __init__(
        self,
        file_manager: FileManager | None = None,
    ) -> None:
        self._fm = file_manager or get_file_manager()

    @property
    def name(self) -> str:
        return "io"

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def read_bytes(self, path: str | Path) -> bytes:
        """Read entire file contents.

        Args:
            path: File path.

        Returns:
            Raw file bytes.

        Raises:
            FileOperationError: On access failure.
        """
        return self._fm.read_bytes(path)

    def read_stream(self, path: str | Path) -> Generator[bytes, None, None]:
        """Stream file contents in chunks.

        Args:
            path: File path.

        Yields:
            Byte chunks.

        Raises:
            FileOperationError: On access failure.
        """
        yield from self._fm.stream_read(path)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def write_bytes(self, path: str | Path, data: bytes) -> int:
        """Write bytes to a file.

        Args:
            path: Destination path.
            data: Bytes to write.

        Returns:
            Number of bytes written.

        Raises:
            FileOperationError: On access failure.
        """
        return self._fm.write_bytes(path, data)

    def write_stream(self, path: str | Path) -> BinaryIO:
        """Open a file for streaming writes.

        Returns an open binary file handle. Caller is responsible
        for closing it.

        Args:
            path: Destination path.

        Returns:
            Open file handle in write-binary mode.

        Raises:
            FileOperationError: On access failure.
        """
        validated = self._fm.validate_path(path)
        self._fm._check_confined(validated)
        try:
            validated.parent.mkdir(parents=True, exist_ok=True)
            return open(validated, "wb")
        except OSError as exc:
            raise FileOperationError(
                f"Failed to open for writing: {exc}",
                path=str(validated),
                operation="write_stream",
            ) from exc

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def secure_delete(self, path: str | Path, passes: int = 3) -> None:
        """Securely delete a file (overwrite then unlink).

        Args:
            path: File to delete.
            passes: Overwrite passes.

        Raises:
            FileOperationError: On access failure.
        """
        self._fm.secure_delete(path, passes=passes)

    def delete(self, path: str | Path) -> None:
        """Delete a file (non-secure).

        Args:
            path: File to delete.

        Raises:
            FileOperationError: On access failure.
        """
        self._fm.delete(path)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def exists(self, path: str | Path) -> bool:
        """Check whether a file exists."""
        return self._fm.exists(path)

    def get_size(self, path: str | Path) -> int:
        """Get file size in bytes."""
        return self._fm.get_size(path)
