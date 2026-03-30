"""
Filanti v2 SDK — Orchestrator-routed, safe-by-default API.

All operations flow through the Orchestrator pipeline:
    Threat Engine → Policy Engine → KMS → Streaming/Cipher Engine

Usage::

    from filanti.api.sdk_v2 import Filanti

    # Safe API — routes through orchestrator
    result = Filanti.execute("encrypt", input="file.txt", policy="enterprise")

    # Convenience wrappers
    Filanti.encrypt("file.txt", password="s3cret-passw0rd")
    Filanti.decrypt("file.txt.enc", password="s3cret-passw0rd")
    Filanti.hash_file("file.txt")
"""

from __future__ import annotations

import functools
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar, ParamSpec

from filanti.core.orchestrator import ExecutionResult, Orchestrator
from filanti.kms.manager import KeyManager

P = ParamSpec("P")
R = TypeVar("R")

# ------------------------------------------------------------------
# @unsafe decorator
# ------------------------------------------------------------------

_UNSAFE_WARNING = (
    "This function bypasses the Orchestrator pipeline. "
    "Policy and threat-mode enforcement are NOT applied."
)


def unsafe(fn: Callable[P, R]) -> Callable[P, R]:
    """Mark a function as *unsafe* — it skips the Orchestrator.

    A ``UserWarning`` is emitted on every call so callers are aware.
    """

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        warnings.warn(_UNSAFE_WARNING, UserWarning, stacklevel=2)
        return fn(*args, **kwargs)

    wrapper._is_unsafe = True  # type: ignore[attr-defined]
    return wrapper


# ------------------------------------------------------------------
# Result wrappers
# ------------------------------------------------------------------

@dataclass
class HashResult:
    """Result of a hash operation."""

    hash: str
    algorithm: str
    file: str | None = None


@dataclass
class EncryptResultV2:
    """Result of an encryption operation (v2)."""

    output_path: str | None = None
    ciphertext: bytes | None = None
    algorithm: str = ""
    streaming: bool = False


@dataclass
class DecryptResultV2:
    """Result of a decryption operation (v2)."""

    output_path: str | None = None
    plaintext: bytes | None = None
    size: int = 0


@dataclass
class SignResult:
    """Result of a sign operation."""

    signature: str
    algorithm: str
    file: str | None = None


@dataclass
class VerifyResult:
    """Result of a verify operation."""

    valid: bool


@dataclass
class MACResult:
    """Result of a MAC operation."""

    mac: str
    algorithm: str
    file: str | None = None


@dataclass
class ChecksumResult:
    """Result of a checksum operation."""

    checksum: str
    algorithm: str
    file: str | None = None


@dataclass
class DeriveResult:
    """Result of a KDF derive operation."""

    key: bytes
    salt: str
    algorithm: str
    params: dict[str, Any]


# ------------------------------------------------------------------
# Filanti v2 SDK
# ------------------------------------------------------------------

class Filanti:
    """Orchestrator-backed high-level API for Filanti v2.

    By default, a module-level ``Orchestrator`` with production threat
    mode is used.  Pass a custom ``Orchestrator`` to the class methods
    via ``_orchestrator=`` kwarg when needed.
    """

    _default_orchestrator: Orchestrator | None = None

    # ------------------------------------------------------------------
    # Orchestrator access
    # ------------------------------------------------------------------

    @classmethod
    def _orch(cls, custom: Orchestrator | None = None) -> Orchestrator:
        if custom is not None:
            return custom
        if cls._default_orchestrator is None:
            cls._default_orchestrator = Orchestrator()
        return cls._default_orchestrator

    @classmethod
    def configure(
        cls,
        key_manager: KeyManager | None = None,
    ) -> None:
        """Replace the default orchestrator with a custom-configured one."""
        cls._default_orchestrator = Orchestrator(key_manager=key_manager)

    # ------------------------------------------------------------------
    # Generic execute
    # ------------------------------------------------------------------

    @classmethod
    def execute(
        cls,
        operation: str,
        *,
        _orchestrator: Orchestrator | None = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        """Route any operation through the Orchestrator.

        Example::

            Filanti.execute("encrypt", input_path="f.txt",
                            password="pw", policy_name="enterprise")
        """
        return cls._orch(_orchestrator).execute(operation, kwargs)

    # ------------------------------------------------------------------
    # Encryption
    # ------------------------------------------------------------------

    @classmethod
    def encrypt(
        cls,
        path: str | Path,
        *,
        password: str | None = None,
        key: bytes | None = None,
        key_ref: str | None = None,
        output: str | Path | None = None,
        algorithm: str = "aes-256-gcm",
        policy: str | None = None,
        threat_mode: str | None = None,
        chunk_size: int | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> EncryptResultV2:
        """Encrypt a file (streaming, v2 format).

        Provide exactly one of *password*, *key*, or *key_ref*.
        """
        result = cls._orch(_orchestrator).execute(
            "encrypt",
            {
                "input_path": str(path),
                "output_path": str(output) if output else None,
                "password": password,
                "key": key,
                "key_ref": key_ref,
                "algorithm": algorithm,
                "policy_name": policy,
                "threat_mode": threat_mode,
                "chunk_size": chunk_size,
            },
        )
        return EncryptResultV2(
            output_path=result.to_dict().get("output_path"),
            ciphertext=result.to_dict().get("ciphertext"),
            algorithm=result.to_dict().get("algorithm", algorithm),
            streaming=result.to_dict().get("streaming", False),
        )

    @classmethod
    def encrypt_bytes(
        cls,
        data: bytes,
        *,
        password: str | None = None,
        key: bytes | None = None,
        algorithm: str = "aes-256-gcm",
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> bytes:
        """Encrypt raw bytes → packed v2 bytes."""
        result = cls._orch(_orchestrator).execute(
            "encrypt",
            {
                "input_bytes": data,
                "password": password,
                "key": key,
                "algorithm": algorithm,
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        return result.ciphertext  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Decryption
    # ------------------------------------------------------------------

    @classmethod
    def decrypt(
        cls,
        path: str | Path,
        *,
        password: str | None = None,
        key: bytes | None = None,
        key_ref: str | None = None,
        output: str | Path | None = None,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> DecryptResultV2:
        """Decrypt a file."""
        result = cls._orch(_orchestrator).execute(
            "decrypt",
            {
                "input_path": str(path),
                "output_path": str(output) if output else None,
                "password": password,
                "key": key,
                "key_ref": key_ref,
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        return DecryptResultV2(
            output_path=result.to_dict().get("output_path"),
            size=result.to_dict().get("size", 0),
        )

    @classmethod
    def decrypt_bytes(
        cls,
        data: bytes,
        *,
        key: bytes,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> bytes:
        """Decrypt packed v2 bytes → plaintext."""
        result = cls._orch(_orchestrator).execute(
            "decrypt",
            {
                "input_bytes": data,
                "key": key,
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        return result.plaintext  # type: ignore[no-any-return]

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    @classmethod
    def hash_file(
        cls,
        path: str | Path,
        algorithm: str = "sha256",
        _orchestrator: Orchestrator | None = None,
    ) -> HashResult:
        result = cls._orch(_orchestrator).execute(
            "hash",
            {"input_path": str(path), "algorithm": algorithm},
        )
        return HashResult(
            hash=result.hash,  # type: ignore[attr-defined]
            algorithm=algorithm,
            file=str(path),
        )

    @classmethod
    def hash_bytes(
        cls,
        data: bytes,
        algorithm: str = "sha256",
        _orchestrator: Orchestrator | None = None,
    ) -> HashResult:
        result = cls._orch(_orchestrator).execute(
            "hash",
            {"input_bytes": data, "algorithm": algorithm},
        )
        return HashResult(hash=result.hash, algorithm=algorithm)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    @classmethod
    def sign(
        cls,
        path: str | Path,
        *,
        private_key: bytes,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> SignResult:
        """Sign a file with a private key."""
        result = cls._orch(_orchestrator).execute(
            "sign",
            {
                "input_path": str(path),
                "metadata": {"private_key": private_key},
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        d = result.to_dict()
        return SignResult(
            signature=d["signature"],
            algorithm=d.get("algorithm", ""),
            file=str(path),
        )

    @classmethod
    def sign_bytes(
        cls,
        data: bytes,
        *,
        private_key: bytes,
        _orchestrator: Orchestrator | None = None,
    ) -> SignResult:
        """Sign raw bytes."""
        result = cls._orch(_orchestrator).execute(
            "sign",
            {"input_bytes": data, "metadata": {"private_key": private_key}},
        )
        d = result.to_dict()
        return SignResult(signature=d["signature"], algorithm=d.get("algorithm", ""))

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    @classmethod
    def verify(
        cls,
        path: str | Path,
        *,
        signature: str | bytes,
        public_key: bytes,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> VerifyResult:
        """Verify a file's signature."""
        sig_hex = signature.hex() if isinstance(signature, bytes) else signature
        result = cls._orch(_orchestrator).execute(
            "verify",
            {
                "input_path": str(path),
                "metadata": {"public_key": public_key, "signature": sig_hex},
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        return VerifyResult(valid=result.valid)  # type: ignore[attr-defined]

    @classmethod
    def verify_bytes(
        cls,
        data: bytes,
        *,
        signature: str | bytes,
        public_key: bytes,
        _orchestrator: Orchestrator | None = None,
    ) -> VerifyResult:
        """Verify a signature on raw bytes."""
        sig_hex = signature.hex() if isinstance(signature, bytes) else signature
        result = cls._orch(_orchestrator).execute(
            "verify",
            {
                "input_bytes": data,
                "metadata": {"public_key": public_key, "signature": sig_hex},
            },
        )
        return VerifyResult(valid=result.valid)  # type: ignore[attr-defined]

    # ------------------------------------------------------------------
    # MAC
    # ------------------------------------------------------------------

    @classmethod
    def mac(
        cls,
        path: str | Path,
        *,
        key: bytes,
        algorithm: str = "hmac-sha256",
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> MACResult:
        """Compute MAC for a file."""
        result = cls._orch(_orchestrator).execute(
            "mac",
            {
                "input_path": str(path),
                "key": key,
                "algorithm": algorithm,
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        d = result.to_dict()
        return MACResult(mac=d["mac"], algorithm=d.get("algorithm", algorithm), file=str(path))

    @classmethod
    def mac_bytes(
        cls,
        data: bytes,
        *,
        key: bytes,
        algorithm: str = "hmac-sha256",
        _orchestrator: Orchestrator | None = None,
    ) -> MACResult:
        """Compute MAC for raw bytes."""
        result = cls._orch(_orchestrator).execute(
            "mac",
            {"input_bytes": data, "key": key, "algorithm": algorithm},
        )
        d = result.to_dict()
        return MACResult(mac=d["mac"], algorithm=d.get("algorithm", algorithm))

    # ------------------------------------------------------------------
    # Checksum
    # ------------------------------------------------------------------

    @classmethod
    def checksum(
        cls,
        path: str | Path,
        algorithm: str = "crc32",
        *,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> ChecksumResult:
        """Compute checksum for a file."""
        result = cls._orch(_orchestrator).execute(
            "checksum",
            {
                "input_path": str(path),
                "algorithm": algorithm,
                "policy_name": policy,
                "threat_mode": threat_mode,
            },
        )
        d = result.to_dict()
        return ChecksumResult(
            checksum=d["checksum"], algorithm=d.get("algorithm", algorithm), file=str(path),
        )

    @classmethod
    def checksum_bytes(
        cls,
        data: bytes,
        algorithm: str = "crc32",
        _orchestrator: Orchestrator | None = None,
    ) -> ChecksumResult:
        """Compute checksum for raw bytes."""
        result = cls._orch(_orchestrator).execute(
            "checksum",
            {"input_bytes": data, "algorithm": algorithm},
        )
        d = result.to_dict()
        return ChecksumResult(checksum=d["checksum"], algorithm=d.get("algorithm", algorithm))

    # ------------------------------------------------------------------
    # Key Derivation
    # ------------------------------------------------------------------

    @classmethod
    def derive(
        cls,
        password: str,
        *,
        algorithm: str | None = None,
        memory_cost: int | None = None,
        time_cost: int | None = None,
        parallelism: int | None = None,
        key_length: int | None = None,
        salt: str | None = None,
        policy: str | None = None,
        threat_mode: str | None = None,
        _orchestrator: Orchestrator | None = None,
    ) -> DeriveResult:
        """Derive a key from a password via KDF engine."""
        kdf_overrides: dict[str, Any] = {}
        if algorithm is not None:
            kdf_overrides["algorithm"] = algorithm
        if memory_cost is not None:
            kdf_overrides["memory_cost"] = memory_cost
        if time_cost is not None:
            kdf_overrides["time_cost"] = time_cost
        if parallelism is not None:
            kdf_overrides["parallelism"] = parallelism
        if key_length is not None:
            kdf_overrides["key_length"] = key_length

        ctx: dict[str, Any] = {
            "password": password,
            "policy_name": policy,
            "threat_mode": threat_mode,
        }
        if kdf_overrides:
            ctx["kdf_overrides"] = kdf_overrides
        if salt is not None:
            ctx["metadata"] = {"salt": salt}

        result = cls._orch(_orchestrator).execute("derive", ctx)
        d = result.to_dict()
        return DeriveResult(
            key=d["key"],
            salt=d["salt"],
            algorithm=d["algorithm"],
            params=d.get("params", {}),
        )

    # ------------------------------------------------------------------
    # Unsafe wrappers (bypass orchestrator)
    # ------------------------------------------------------------------

    @staticmethod
    @unsafe
    def encrypt_bytes_raw(
        data: bytes,
        key: bytes,
        algorithm: str = "aes-256-gcm",
    ) -> tuple[bytes, bytes]:
        """LOW-LEVEL: Encrypt bytes without orchestrator.

        Returns ``(ciphertext, nonce)``.  No policy or threat-mode
        enforcement.
        """
        from filanti.crypto.cipher_engine import CipherEngine
        from filanti.crypto.encryption import EncryptionAlgorithm

        engine = CipherEngine(EncryptionAlgorithm(algorithm))
        return engine.encrypt(key, data)

    @staticmethod
    @unsafe
    def decrypt_bytes_raw(
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        algorithm: str = "aes-256-gcm",
    ) -> bytes:
        """LOW-LEVEL: Decrypt bytes without orchestrator."""
        from filanti.crypto.cipher_engine import CipherEngine
        from filanti.crypto.encryption import EncryptionAlgorithm

        engine = CipherEngine(EncryptionAlgorithm(algorithm))
        return engine.decrypt(key, ciphertext, nonce)

    # ------------------------------------------------------------------
    # Key generation (delegates to v1 modules directly)
    # ------------------------------------------------------------------

    @staticmethod
    @unsafe
    def generate_keypair(
        algorithm: str = "ed25519",
        password: bytes | None = None,
    ) -> Any:
        """Generate a signing key pair (Ed25519 / ECDSA).

        Returns a ``KeyPair`` with ``private_key``, ``public_key``,
        ``algorithm`` attributes.
        """
        from filanti.integrity.signature import generate_keypair
        return generate_keypair(algorithm, password)

    @staticmethod
    @unsafe
    def save_keypair(
        keypair: Any,
        output_path: str | Path,
    ) -> tuple[Path, Path]:
        """Save a signing key pair to files.

        Returns ``(private_key_path, public_key_path)``.
        """
        from filanti.integrity.signature import save_keypair
        return save_keypair(keypair, Path(output_path))

    @staticmethod
    @unsafe
    def generate_key(size: int = 32) -> bytes:
        """Generate *size* random bytes suitable for use as a symmetric key."""
        from filanti.crypto.key_management import generate_key
        return generate_key(size)

    @staticmethod
    @unsafe
    def generate_asymmetric_keypair(
        algorithm: str = "x25519",
        password: bytes | None = None,
        rsa_key_size: int = 4096,
    ) -> Any:
        """Generate an asymmetric key pair for hybrid encryption.

        Returns an ``AsymmetricKeyPair`` object.
        """
        from filanti.crypto.asymmetric import generate_asymmetric_keypair
        return generate_asymmetric_keypair(algorithm, password, rsa_key_size)

    @staticmethod
    @unsafe
    def save_asymmetric_keypair(
        keypair: Any,
        output_path: str | Path,
    ) -> tuple[Path, Path]:
        """Save an asymmetric key pair to files.

        Returns ``(private_key_path, public_key_path)``.
        """
        from filanti.crypto.asymmetric import save_asymmetric_keypair
        return save_asymmetric_keypair(keypair, Path(output_path))

    # ------------------------------------------------------------------
    # Hybrid encryption (delegates to v1 modules directly)
    # ------------------------------------------------------------------

    @staticmethod
    @unsafe
    def hybrid_encrypt(
        path: str | Path,
        public_keys: list[str | Path],
        *,
        output: str | Path | None = None,
        algorithm: str = "x25519",
        recipient_ids: list[str] | None = None,
    ) -> Any:
        """Encrypt a file for recipients using public-key hybrid encryption."""
        from filanti.crypto.asymmetric import (
            AsymmetricAlgorithm,
            hybrid_encrypt_file,
        )
        out_path = Path(output) if output else Path(str(path) + ".henc")
        return hybrid_encrypt_file(
            input_path=Path(path),
            output_path=out_path,
            recipient_public_keys=[str(k) for k in public_keys],
            algorithm=AsymmetricAlgorithm(algorithm),
            recipient_ids=recipient_ids,
        )

    @staticmethod
    @unsafe
    def hybrid_decrypt(
        path: str | Path,
        private_key: str | Path,
        *,
        output: str | Path | None = None,
        password: bytes | None = None,
        recipient_id: str | None = None,
    ) -> int:
        """Decrypt a hybrid encrypted file. Returns size in bytes."""
        from filanti.crypto.asymmetric import hybrid_decrypt_file
        if output is None:
            s = str(path)
            out_path = Path(s[:-5]) if s.endswith(".henc") else Path(s + ".dec")
        else:
            out_path = Path(output)
        return hybrid_decrypt_file(
            input_path=Path(path),
            output_path=out_path,
            private_key=str(private_key),
            password=password,
            recipient_id=recipient_id,
        )

    @staticmethod
    @unsafe
    def hybrid_encrypt_bytes(
        data: bytes,
        public_keys: list[str | Path],
        *,
        algorithm: str = "x25519",
    ) -> Any:
        """Encrypt bytes for recipients using hybrid encryption."""
        from filanti.crypto.asymmetric import (
            AsymmetricAlgorithm,
            hybrid_encrypt_bytes as _heb,
        )
        return _heb(data, [str(k) for k in public_keys], AsymmetricAlgorithm(algorithm))

    @staticmethod
    @unsafe
    def hybrid_decrypt_bytes(
        data: Any,
        private_key: str | Path,
        *,
        password: bytes | None = None,
    ) -> bytes:
        """Decrypt hybrid encrypted bytes."""
        from filanti.crypto.asymmetric import hybrid_decrypt_bytes as _hdb
        return _hdb(data, str(private_key), password)

    @staticmethod
    @unsafe
    def get_hybrid_file_info(path: str | Path) -> Any:
        """Read metadata from a hybrid encrypted file."""
        from filanti.crypto.asymmetric import get_hybrid_file_metadata
        return get_hybrid_file_metadata(Path(path))

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    @classmethod
    def verify_hash(
        cls,
        path: str | Path,
        expected: str,
        algorithm: str = "sha256",
        _orchestrator: Orchestrator | None = None,
    ) -> bool:
        """Hash a file and compare against *expected*. Returns True if match."""
        result = cls.hash_file(path, algorithm, _orchestrator)
        import secrets as _sec
        return _sec.compare_digest(result.hash.lower(), expected.lower())

    @classmethod
    def verify_mac_value(
        cls,
        path: str | Path,
        *,
        key: bytes,
        expected_mac: str,
        algorithm: str = "hmac-sha256",
        _orchestrator: Orchestrator | None = None,
    ) -> bool:
        """Compute MAC and compare against *expected_mac*."""
        result = cls.mac(path, key=key, algorithm=algorithm, _orchestrator=_orchestrator)
        import secrets as _sec
        return _sec.compare_digest(result.mac.lower(), expected_mac.lower())

    @classmethod
    def verify_checksum_value(
        cls,
        path: str | Path,
        expected: str,
        algorithm: str = "crc32",
        _orchestrator: Orchestrator | None = None,
    ) -> bool:
        """Compute checksum and compare against *expected*."""
        result = cls.checksum(path, algorithm, _orchestrator=_orchestrator)
        return result.checksum.lower() == expected.lower()

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def algorithms() -> dict[str, Any]:
        """Return all supported algorithms grouped by category."""
        from filanti.hashing import crypto_hash
        from filanti.crypto import EncryptionAlgorithm
        from filanti.crypto.asymmetric import get_supported_asymmetric_algorithms
        from filanti.integrity.mac import MACAlgorithm
        from filanti.integrity.signature import SignatureAlgorithm
        from filanti.integrity.checksum import ChecksumAlgorithm

        return {
            "hash": crypto_hash.get_supported_algorithms(),
            "encryption": [e.value for e in EncryptionAlgorithm],
            "asymmetric": get_supported_asymmetric_algorithms(),
            "mac": [m.value for m in MACAlgorithm],
            "signature": [s.value for s in SignatureAlgorithm],
            "checksum": [c.value for c in ChecksumAlgorithm],
        }

    @staticmethod
    def resolve_secret(value: str, allow_empty: bool = False) -> str:
        """Resolve an ENV reference (e.g. ``ENV:MY_VAR``) to its value."""
        from filanti.core.secrets import resolve_secret
        return resolve_secret(value, allow_empty)

    @staticmethod
    def is_env_reference(value: str) -> bool:
        """Check if *value* looks like an ENV reference pattern."""
        from filanti.core.secrets import is_env_reference
        return is_env_reference(value)

    @staticmethod
    def load_dotenv(path: str | Path) -> None:
        """Load environment variables from a .env file."""
        from filanti.core.secrets import load_dotenv
        load_dotenv(str(path))
