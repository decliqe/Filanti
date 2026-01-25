"""
Secure memory handling utilities.

Provides functions for handling sensitive data in memory with
best-effort secure cleanup.

Note: Python's memory model makes truly secure memory handling
challenging. These utilities provide defense-in-depth but cannot
guarantee complete memory erasure.
"""

import ctypes
import gc
import secrets
import sys
from typing import Any, Callable


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


def secure_zero_memory(data: bytearray) -> None:
    """Securely zero memory using multiple techniques.

    Attempts to prevent compiler optimizations from removing
    the zeroing operation.

    Args:
        data: Bytearray to zero.
    """
    length = len(data)

    # First pass: simple zeroing
    for i in range(length):
        data[i] = 0

    # Second pass: write random data then zero
    # This helps against memory persistence attacks
    for i in range(length):
        data[i] = secrets.randbelow(256)
    for i in range(length):
        data[i] = 0

    # Try to use ctypes to zero the actual memory location
    try:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, length)
    except (ValueError, TypeError):
        pass  # May fail for small arrays or on some platforms

    # Force garbage collection to clean up any temporary copies
    gc.collect()


def secure_delete(obj: Any) -> None:
    """Attempt to securely delete an object.

    Zeros any bytearray data, removes references, and triggers GC.

    Args:
        obj: Object to delete.
    """
    if isinstance(obj, bytearray):
        secure_zero_memory(obj)
    elif isinstance(obj, SecureBytes):
        obj.clear()
    elif hasattr(obj, '_data') and isinstance(obj._data, bytearray):
        secure_zero_memory(obj._data)

    # Force GC
    gc.collect()


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
        self._cleared = False

    @property
    def data(self) -> bytes:
        """Get the data as immutable bytes.

        Returns:
            Copy of the data as bytes.
        """
        if self._cleared:
            raise ValueError("SecureBytes has been cleared")
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
        """Clear the internal data securely."""
        if not self._cleared:
            secure_zero_memory(self._data)
            self._cleared = True

    def __len__(self) -> int:
        return len(self._data)

    def __bytes__(self) -> bytes:
        return self.data

    def __del__(self) -> None:
        """Clear data on object deletion."""
        self.clear()


class SecureString:
    """Secure string container with automatic cleanup.

    Stores string data as encoded bytes for secure zeroing.

    Example:
        with SecureString("sensitive password") as pwd:
            use_password(pwd.value)
        # Password is cleared
    """

    def __init__(self, value: str, encoding: str = 'utf-8') -> None:
        """Initialize SecureString.

        Args:
            value: String value to protect.
            encoding: Character encoding to use.
        """
        self._data = bytearray(value.encode(encoding))
        self._encoding = encoding
        self._cleared = False

    @property
    def value(self) -> str:
        """Get the string value.

        Returns:
            Decoded string value.
        """
        if self._cleared:
            raise ValueError("SecureString has been cleared")
        return self._data.decode(self._encoding)

    @property
    def bytes(self) -> bytes:
        """Get the encoded bytes.

        Returns:
            Encoded byte representation.
        """
        if self._cleared:
            raise ValueError("SecureString has been cleared")
        return bytes(self._data)

    def __enter__(self) -> "SecureString":
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
        """Clear the internal data securely."""
        if not self._cleared:
            secure_zero_memory(self._data)
            self._cleared = True

    def __len__(self) -> int:
        return len(self.value) if not self._cleared else 0

    def __str__(self) -> str:
        return self.value if not self._cleared else "<cleared>"

    def __del__(self) -> None:
        """Clear data on object deletion."""
        self.clear()


def with_secure_cleanup(func: Callable) -> Callable:
    """Decorator to ensure garbage collection after sensitive operations.

    Forces garbage collection after the decorated function completes
    to help clean up any temporary sensitive data.

    Args:
        func: Function to wrap.

    Returns:
        Wrapped function.
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        finally:
            gc.collect()

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class LockedMemory:
    """Memory region that attempts to prevent swapping to disk.

    Note: This is platform-dependent and may not work on all systems.
    On failure, falls back to regular SecureBytes behavior.

    Example:
        with LockedMemory(key_bytes) as locked:
            perform_crypto(locked.data)
    """

    def __init__(self, data: bytes | bytearray) -> None:
        """Initialize LockedMemory.

        Args:
            data: Sensitive data to protect.
        """
        self._secure = SecureBytes(data)
        self._locked = False
        self._try_lock()

    def _try_lock(self) -> None:
        """Attempt to lock memory from being swapped."""
        # mlock is not directly available in Python
        # This is a placeholder for platform-specific implementations
        # On Linux, one could use ctypes to call mlock()
        try:
            if sys.platform == 'linux':
                import ctypes
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(ctypes.c_char.from_buffer(self._secure._data))
                size = len(self._secure._data)
                result = libc.mlock(addr, size)
                if result == 0:
                    self._locked = True
        except Exception:
            pass  # Fall back to normal SecureBytes

    def _try_unlock(self) -> None:
        """Attempt to unlock memory."""
        try:
            if self._locked and sys.platform == 'linux':
                import ctypes
                libc = ctypes.CDLL('libc.so.6', use_errno=True)
                addr = ctypes.addressof(ctypes.c_char.from_buffer(self._secure._data))
                size = len(self._secure._data)
                libc.munlock(addr, size)
        except Exception:
            pass

    @property
    def data(self) -> bytes:
        """Get the protected data."""
        return self._secure.data

    def __enter__(self) -> "LockedMemory":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Clear and unlock on exit."""
        self._try_unlock()
        self._secure.clear()

    def __del__(self) -> None:
        """Clear and unlock on deletion."""
        self._try_unlock()
        self._secure.clear()

