"""
Filanti - A modular, security-focused file framework.

Provides secure-by-default primitives for file encryption, hashing,
and integrity verification.
"""

__version__ = "1.1.0"
__author__ = "Decliqe"

from filanti.core.errors import (
    FilantiError,
    FileOperationError,
    HashingError,
    ValidationError,
    EncryptionError,
    DecryptionError,
    IntegrityError,
    SignatureError,
    SecretError,
)

__all__ = [
    "__version__",
    # Base errors
    "FilantiError",
    "FileOperationError",
    "HashingError",
    "ValidationError",
    "EncryptionError",
    "DecryptionError",
    "IntegrityError",
    "SignatureError",
    "SecretError",
]

