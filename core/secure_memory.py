"""
Secure memory handling utilities.

Provides functions for handling sensitive data in memory with
best-effort secure cleanup.

Note: Python's memory model makes truly secure memory handling
challenging. These utilities provide defense-in-depth but cannot
guarantee complete memory erasure.
"""

import secrets
from typing import Any


def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Uses the system's best source of randomness.

    Args:
        length: Number of random bytes to generate.

    Returns:
        Secure random bytes.

    Raises:
        ValueError: If length is not positive.
    """
    if length <= 0:
        raise ValueError("Length must be positive")
    return secrets.token_bytes(length)


def secure_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.

    Prevents timing attacks by ensuring comparison takes
    the same time regardless of where strings differ.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        True if strings are equal, False otherwise.
    """
    return secrets.compare_digest(a, b)


def clear_bytes(data: bytearray) -> None:
    """Attempt to clear sensitive data from a bytearray.

    Overwrites the bytearray with zeros. Only works with
    mutable bytearray objects.

    Note: This is best-effort only. Python may have copied
    the data elsewhere in memory.

    Args:
        data: Bytearray to clear.
    """
    for i in range(len(data)):
        data[i] = 0


class SecureBytes:
    """Context manager for handling sensitive byte data.

    Attempts to clear sensitive data when context exits.
    Uses bytearray internally for mutability.

    Example:
        with SecureBytes(sensitive_data) as secure:
            # Use secure.data
            process(secure.data)
        # Data is cleared on exit
    """

    def __init__(self, data: bytes | bytearray) -> None:
        """Initialize SecureBytes.

        Args:
            data: Sensitive data to protect.
        """
        self._data = bytearray(data)

    @property
    def data(self) -> bytes:
        """Get the data as immutable bytes.

        Returns:
            Copy of the data as bytes.
        """
        return bytes(self._data)

    def __enter__(self) -> "SecureBytes":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Clear data on context exit."""
        self.clear()

    def clear(self) -> None:
        """Clear the internal data."""
        clear_bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __bytes__(self) -> bytes:
        return self.data

