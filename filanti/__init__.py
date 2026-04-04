"""
Filanti — Secure Cryptographic Execution Platform.

v2: Orchestrator-driven, policy-enforced, streaming-first.
"""

__version__ = "2.0.1"
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
from filanti.core.context import ExecutionContext, Operation
from filanti.core.orchestrator import Orchestrator, ExecutionResult

__all__ = [
    "__version__",
    # v2 core
    "Orchestrator",
    "ExecutionContext",
    "ExecutionResult",
    "Operation",
    # Errors
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

