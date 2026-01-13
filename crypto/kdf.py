"""
Key Derivation Functions (KDF) module.

Provides secure key derivation from passwords using modern,
memory-hard algorithms designed to resist hardware attacks.

Default: Argon2id - combines Argon2i's resistance to side-channel
attacks and Argon2d's resistance to GPU cracking.
"""

import os
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

from filanti.core.errors import FilantiError
from filanti.core.secure_memory import secure_random_bytes


class KDFAlgorithm(str, Enum):
    """Supported key derivation algorithms."""

    ARGON2ID = "argon2id"
    SCRYPT = "scrypt"


# Argon2id parameters (OWASP recommended for password hashing)
# Memory: 64 MiB, Iterations: 3, Parallelism: 4
ARGON2_MEMORY_COST = 65536  # 64 MiB in KiB
ARGON2_TIME_COST = 3
ARGON2_PARALLELISM = 4

# Scrypt parameters (fallback)
SCRYPT_N = 2**17  # CPU/memory cost
SCRYPT_R = 8      # Block size
SCRYPT_P = 1      # Parallelism

# Salt length in bytes
SALT_LENGTH = 32

# Default derived key length
DEFAULT_KEY_LENGTH = 32  # 256 bits for AES-256


class DerivedKey(NamedTuple):
    """Result of key derivation containing the key and parameters."""

    key: bytes
    salt: bytes
    algorithm: str
    params: dict


@dataclass
class KDFParams:
    """Parameters for key derivation functions."""

    algorithm: KDFAlgorithm = KDFAlgorithm.ARGON2ID
    salt_length: int = SALT_LENGTH
    key_length: int = DEFAULT_KEY_LENGTH

    # Argon2 params
    argon2_memory_cost: int = ARGON2_MEMORY_COST
    argon2_time_cost: int = ARGON2_TIME_COST
    argon2_parallelism: int = ARGON2_PARALLELISM

    # Scrypt params
    scrypt_n: int = SCRYPT_N
    scrypt_r: int = SCRYPT_R
    scrypt_p: int = SCRYPT_P


def _derive_argon2id(
    password: bytes,
    salt: bytes,
    key_length: int,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
) -> bytes:
    """Derive key using Argon2id.

    Uses argon2-cffi library for Argon2id support.
    """
    try:
        from argon2.low_level import hash_secret_raw, Type

        return hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=key_length,
            type=Type.ID,
        )
    except ImportError:
        raise FilantiError(
            "argon2-cffi is required for Argon2id support. "
            "Install with: pip install argon2-cffi",
            context={"algorithm": "argon2id"},
        )


def _derive_scrypt(
    password: bytes,
    salt: bytes,
    key_length: int,
    n: int,
    r: int,
    p: int,
) -> bytes:
    """Derive key using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=key_length,
        n=n,
        r=r,
        p=p,
        backend=default_backend(),
    )
    return kdf.derive(password)


def derive_key(
    password: str | bytes,
    salt: bytes | None = None,
    params: KDFParams | None = None,
) -> DerivedKey:
    """Derive a cryptographic key from a password.

    Uses memory-hard key derivation to resist hardware attacks.

    Args:
        password: Password string or bytes.
        salt: Optional salt bytes. If None, generates random salt.
        params: Optional KDF parameters. Uses secure defaults if None.

    Returns:
        DerivedKey containing the key, salt, and parameters used.

    Raises:
        FilantiError: If key derivation fails.
    """
    if params is None:
        params = KDFParams()

    # Ensure password is bytes
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    # Generate salt if not provided
    if salt is None:
        salt = secure_random_bytes(params.salt_length)

    # Derive key based on algorithm
    if params.algorithm == KDFAlgorithm.ARGON2ID:
        key = _derive_argon2id(
            password=password_bytes,
            salt=salt,
            key_length=params.key_length,
            memory_cost=params.argon2_memory_cost,
            time_cost=params.argon2_time_cost,
            parallelism=params.argon2_parallelism,
        )
        param_dict = {
            "memory_cost": params.argon2_memory_cost,
            "time_cost": params.argon2_time_cost,
            "parallelism": params.argon2_parallelism,
        }
    elif params.algorithm == KDFAlgorithm.SCRYPT:
        key = _derive_scrypt(
            password=password_bytes,
            salt=salt,
            key_length=params.key_length,
            n=params.scrypt_n,
            r=params.scrypt_r,
            p=params.scrypt_p,
        )
        param_dict = {
            "n": params.scrypt_n,
            "r": params.scrypt_r,
            "p": params.scrypt_p,
        }
    else:
        raise FilantiError(
            f"Unsupported KDF algorithm: {params.algorithm}",
            context={"algorithm": str(params.algorithm)},
        )

    return DerivedKey(
        key=key,
        salt=salt,
        algorithm=params.algorithm.value,
        params=param_dict,
    )


def derive_key_with_salt(
    password: str | bytes,
    salt: bytes,
    algorithm: str,
    params: dict,
    key_length: int = DEFAULT_KEY_LENGTH,
) -> bytes:
    """Derive a key using existing salt and parameters.

    Used for decryption when parameters are known from metadata.

    Args:
        password: Password string or bytes.
        salt: Salt bytes from metadata.
        algorithm: Algorithm name from metadata.
        params: Algorithm parameters from metadata.
        key_length: Length of key to derive.

    Returns:
        Derived key bytes.

    Raises:
        FilantiError: If key derivation fails.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    if algorithm == KDFAlgorithm.ARGON2ID.value:
        return _derive_argon2id(
            password=password_bytes,
            salt=salt,
            key_length=key_length,
            memory_cost=params["memory_cost"],
            time_cost=params["time_cost"],
            parallelism=params["parallelism"],
        )
    elif algorithm == KDFAlgorithm.SCRYPT.value:
        return _derive_scrypt(
            password=password_bytes,
            salt=salt,
            key_length=key_length,
            n=params["n"],
            r=params["r"],
            p=params["p"],
        )
    else:
        raise FilantiError(
            f"Unsupported KDF algorithm: {algorithm}",
            context={"algorithm": algorithm},
        )


def generate_salt(length: int = SALT_LENGTH) -> bytes:
    """Generate a random salt for key derivation.

    Args:
        length: Salt length in bytes (default: 32).

    Returns:
        Random salt bytes.
    """
    return secure_random_bytes(length)

