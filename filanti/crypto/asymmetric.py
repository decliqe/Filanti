"""
Asymmetric encryption module.

Provides hybrid encryption using public-key cryptography for secure file exchange.
Uses ECIES-style hybrid encryption: asymmetric key exchange + symmetric AEAD.

Supported algorithms:
- X25519 (default, modern, fast elliptic curve Diffie-Hellman)
- RSA-OAEP (wide compatibility, larger keys)

Security model:
- Ephemeral key pair generated for each encryption
- Session key derived via ECDH (X25519) or RSA-OAEP key encapsulation
- Data encrypted with AES-256-GCM using the session key
- Supports multi-recipient encryption
"""

import base64
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from filanti.core.errors import EncryptionError, DecryptionError, FileOperationError
from filanti.core.file_manager import FileManager, get_file_manager
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.encryption import EncryptionAlgorithm


class AsymmetricAlgorithm(str, Enum):
    """Supported asymmetric key exchange algorithms."""

    X25519 = "x25519"
    RSA_OAEP = "rsa-oaep"


# Default algorithm for asymmetric operations
DEFAULT_ASYMMETRIC_ALGORITHM = AsymmetricAlgorithm.X25519

# RSA key sizes
RSA_KEY_SIZE_2048 = 2048
RSA_KEY_SIZE_3072 = 3072
RSA_KEY_SIZE_4096 = 4096
DEFAULT_RSA_KEY_SIZE = RSA_KEY_SIZE_4096

# Session key size (256 bits for AES-256)
SESSION_KEY_SIZE = 32

# Nonce size for AES-GCM
NONCE_SIZE = 12

# File format version for asymmetric encryption
ASYMMETRIC_FORMAT_VERSION_V2 = 2  # v2 format (encrypted metadata)

# Product identifier for v2 header
ASYMMETRIC_PRODUCT_NAME = "FLAS"
ASYMMETRIC_HEADER_VERSION = "1.1.0"


@dataclass
class AsymmetricFileHeader:
    """Minimal public header for asymmetric encrypted files - base64 encoded.

    Only exposes product name and version, no cryptographic details.
    """

    product: str = ASYMMETRIC_PRODUCT_NAME
    version: str = ASYMMETRIC_HEADER_VERSION

    def to_base64(self) -> bytes:
        """Encode header as base64 bytes."""
        data = {"p": self.product, "v": self.version}
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(json_bytes)

    @classmethod
    def from_base64(cls, data: bytes) -> "AsymmetricFileHeader":
        """Decode header from base64 bytes."""
        try:
            json_bytes = base64.b64decode(data)
            parsed = json.loads(json_bytes.decode("utf-8"))
            return cls(product=parsed.get("p", "FLAS"), version=parsed.get("v", "1.0.0"))
        except Exception as e:
            raise DecryptionError(f"Invalid file header: {e}") from e

    def validate(self) -> bool:
        """Validate the header is from Filanti asymmetric encryption."""
        return self.product == ASYMMETRIC_PRODUCT_NAME


class AsymmetricKeyPair(NamedTuple):
    """Container for asymmetric key pair."""

    private_key: bytes  # PEM-encoded private key
    public_key: bytes   # PEM-encoded public key
    algorithm: str


@dataclass
class EncryptedSessionKey:
    """Container for encrypted session key data."""

    encrypted_key: bytes
    ephemeral_public_key: bytes | None  # For X25519 (PEM-encoded)
    algorithm: str
    recipient_id: str | None = None  # Optional identifier for multi-recipient

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "encrypted_key": self.encrypted_key.hex(),
            "ephemeral_public_key": self.ephemeral_public_key.decode("utf-8") if self.ephemeral_public_key else None,
            "algorithm": self.algorithm,
            "recipient_id": self.recipient_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedSessionKey":
        """Create from dictionary."""
        return cls(
            encrypted_key=bytes.fromhex(data["encrypted_key"]),
            ephemeral_public_key=data["ephemeral_public_key"].encode("utf-8") if data.get("ephemeral_public_key") else None,
            algorithm=data["algorithm"],
            recipient_id=data.get("recipient_id"),
        )


@dataclass
class HybridEncryptedData:
    """Container for hybrid encrypted data."""

    ciphertext: bytes
    nonce: bytes
    session_keys: list[EncryptedSessionKey]  # One per recipient
    symmetric_algorithm: str
    created_at: str

    def __post_init__(self):
        self._session_key: bytes | None = None
        self._encrypted_meta: bytes | None = None
        self._meta_nonce: bytes | None = None

    def to_bytes(self) -> bytes:
        """Serialize to bytes for storage using v2 format (encrypted metadata).

        V2 Format:
        - Base64 public header (product + version only)
        - Header length (2 bytes)
        - Session keys blob length (4 bytes)
        - Session keys blob (encrypted session keys — needed before decryption)
        - Data nonce (12 bytes) — needed for data decryption
        - Meta nonce (12 bytes) — for encrypting internal metadata
        - Encrypted internal metadata length (4 bytes)
        - Encrypted internal metadata (algorithm, created_at)
        - Ciphertext

        The metadata key is derived from the session key via HKDF,
        ensuring only key holders can read internal metadata.
        """
        if self._session_key is None:
            raise EncryptionError(
                "Cannot serialize without session key — "
                "set _session_key before calling to_bytes()"
            )

        # Create minimal public header
        header = AsymmetricFileHeader()
        header_b64 = header.to_base64()

        # Session keys must be accessible before decryption
        session_keys_data = {
            "version": ASYMMETRIC_FORMAT_VERSION_V2,
            "session_keys": [sk.to_dict() for sk in self.session_keys],
        }
        session_keys_bytes = json.dumps(session_keys_data, separators=(",", ":")).encode("utf-8")

        # Internal metadata to encrypt (algorithm details, timestamp)
        internal_meta = {
            "symmetric_algorithm": self.symmetric_algorithm,
            "created_at": self.created_at,
        }
        internal_meta_bytes = json.dumps(internal_meta, separators=(",", ":")).encode("utf-8")

        # Derive metadata encryption key from the SESSION KEY (not public data)
        meta_nonce = secure_random_bytes(NONCE_SIZE)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_SIZE,
            salt=meta_nonce,
            info=b"filanti-asym-meta-v2",
            backend=default_backend(),
        )
        meta_key = hkdf.derive(self._session_key)

        meta_cipher = AESGCM(meta_key)
        encrypted_meta = meta_cipher.encrypt(meta_nonce, internal_meta_bytes, None)

        parts = [
            header_b64,                                  # Base64 public header
            len(header_b64).to_bytes(2, "big"),          # Header length
            len(session_keys_bytes).to_bytes(4, "big"),  # Session keys length
            session_keys_bytes,                          # Session keys (needed for decryption)
            self.nonce,                                  # Data nonce (12 bytes, plaintext)
            meta_nonce,                                  # Metadata nonce (12 bytes)
            len(encrypted_meta).to_bytes(4, "big"),      # Encrypted metadata length
            encrypted_meta,                              # Encrypted internal metadata
            self.ciphertext,                             # Data ciphertext
        ]
        return b"".join(parts)

    def resolve_metadata(self, session_key: bytes) -> None:
        """Decrypt internal metadata using the recovered session key.

        Called by hybrid_decrypt_bytes() after the session key is recovered.
        Populates symmetric_algorithm and created_at from encrypted metadata.
        """
        if self._encrypted_meta is None or self._meta_nonce is None:
            return  # Already resolved or nothing to resolve

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SESSION_KEY_SIZE,
            salt=self._meta_nonce,
            info=b"filanti-asym-meta-v2",
            backend=default_backend(),
        )
        meta_key = hkdf.derive(session_key)

        meta_cipher = AESGCM(meta_key)
        try:
            internal_meta_bytes = meta_cipher.decrypt(
                self._meta_nonce, self._encrypted_meta, None,
            )
            internal_meta = json.loads(internal_meta_bytes.decode("utf-8"))
            self.symmetric_algorithm = internal_meta["symmetric_algorithm"]
            self.created_at = internal_meta["created_at"]
        except InvalidTag:
            raise DecryptionError(
                "Failed to decrypt internal metadata: wrong session key"
            )
        finally:
            self._encrypted_meta = None
            self._meta_nonce = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridEncryptedData":
        """Deserialize from bytes (v2 format only).

        Internal metadata (symmetric_algorithm, created_at) remains
        encrypted until resolve_metadata() is called with the session key.
        """
        if len(data) < 8:
            raise DecryptionError("Invalid hybrid encrypted data: too short")

        return cls._from_bytes_v2(data)

    @classmethod
    def _from_bytes_v2(cls, data: bytes) -> "HybridEncryptedData":
        """Deserialize from v2 format bytes.

        Defers metadata decryption — stores encrypted meta blob for later
        resolution via resolve_metadata(session_key).
        """
        try:
            offset = 0

            # Find base64 header
            header_found = False
            max_header_len = 50
            for header_len in range(20, max_header_len):
                try:
                    header_b64 = data[:header_len]
                    stored_len = int.from_bytes(data[header_len:header_len+2], "big")
                    if stored_len == header_len:
                        header = AsymmetricFileHeader.from_base64(header_b64)
                        if header.validate():
                            header_found = True
                            offset = header_len + 2
                            break
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue

            if not header_found:
                raise DecryptionError("Invalid v2 format: cannot parse header")

            # Read session keys
            session_keys_len = int.from_bytes(data[offset:offset+4], "big")
            offset += 4

            session_keys_bytes = data[offset:offset+session_keys_len]
            offset += session_keys_len

            try:
                session_keys_data = json.loads(session_keys_bytes.decode("utf-8"))
            except Exception as e:
                raise DecryptionError(f"Invalid session keys data: {e}") from e

            session_keys = [EncryptedSessionKey.from_dict(sk) for sk in session_keys_data["session_keys"]]

            # Read data nonce (12 bytes, plaintext)
            if len(data) < offset + NONCE_SIZE:
                raise DecryptionError("Invalid v2 format: truncated data nonce")
            data_nonce = data[offset:offset + NONCE_SIZE]
            offset += NONCE_SIZE

            # Read metadata nonce (12 bytes)
            if len(data) < offset + NONCE_SIZE:
                raise DecryptionError("Invalid v2 format: truncated metadata nonce")
            meta_nonce = data[offset:offset + NONCE_SIZE]
            offset += NONCE_SIZE

            # Read encrypted metadata length
            if len(data) < offset + 4:
                raise DecryptionError("Invalid v2 format: truncated metadata length")
            encrypted_meta_len = int.from_bytes(data[offset:offset+4], "big")
            offset += 4

            if encrypted_meta_len > 1_048_576:  # 1 MB max
                raise DecryptionError("Invalid v2 format: metadata length too large")

            # Read encrypted metadata
            if len(data) < offset + encrypted_meta_len:
                raise DecryptionError("Invalid v2 format: truncated metadata")
            encrypted_meta = data[offset:offset + encrypted_meta_len]
            offset += encrypted_meta_len

            # Remaining is ciphertext
            ciphertext = data[offset:]

            # Create instance with deferred metadata decryption
            result = cls(
                ciphertext=ciphertext,
                nonce=data_nonce,
                session_keys=session_keys,
                symmetric_algorithm="",  # Deferred — call resolve_metadata()
                created_at="",           # Deferred — call resolve_metadata()
            )
            result._encrypted_meta = encrypted_meta
            result._meta_nonce = meta_nonce
            return result

        except DecryptionError:
            raise
        except Exception as e:
            raise DecryptionError(f"Failed to parse v2 format: {e}") from e


@dataclass
class AsymmetricMetadata:
    """Metadata for asymmetric encrypted files."""

    version: int
    asymmetric_algorithm: str
    symmetric_algorithm: str
    recipient_count: int
    original_size: int | None = None
    created_at: str | None = None

    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return json.dumps(asdict(self), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "AsymmetricMetadata":
        """Deserialize from bytes."""
        parsed = json.loads(data.decode("utf-8"))
        return cls(**parsed)


def _normalize_algorithm(algorithm: AsymmetricAlgorithm | str) -> AsymmetricAlgorithm:
    """Normalize algorithm to enum."""
    if isinstance(algorithm, str):
        try:
            return AsymmetricAlgorithm(algorithm.lower())
        except ValueError:
            raise EncryptionError(
                f"Unsupported asymmetric algorithm: {algorithm}",
                algorithm=algorithm,
                context={"supported": [a.value for a in AsymmetricAlgorithm]},
            )
    return algorithm


def generate_asymmetric_keypair(
    algorithm: AsymmetricAlgorithm | str = DEFAULT_ASYMMETRIC_ALGORITHM,
    password: bytes | None = None,
    rsa_key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> AsymmetricKeyPair:
    """Generate asymmetric key pair for hybrid encryption.

    Args:
        algorithm: Key exchange algorithm (x25519, rsa-oaep).
        password: Optional password to encrypt private key.
        rsa_key_size: RSA key size in bits (only for RSA).

    Returns:
        AsymmetricKeyPair containing PEM-encoded keys.

    Raises:
        EncryptionError: If key generation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    # Determine private key encryption
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    try:
        if algorithm == AsymmetricAlgorithm.X25519:
            private_key = x25519.X25519PrivateKey.generate()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )

            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

        elif algorithm == AsymmetricAlgorithm.RSA_OAEP:
            if rsa_key_size not in (RSA_KEY_SIZE_2048, RSA_KEY_SIZE_3072, RSA_KEY_SIZE_4096):
                raise EncryptionError(
                    f"Invalid RSA key size: {rsa_key_size}",
                    context={"valid_sizes": [RSA_KEY_SIZE_2048, RSA_KEY_SIZE_3072, RSA_KEY_SIZE_4096]},
                )

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=rsa_key_size,
                backend=default_backend(),
            )

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption,
            )

            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise EncryptionError(
                f"Unsupported algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        return AsymmetricKeyPair(
            private_key=private_pem,
            public_key=public_pem,
            algorithm=algorithm.value,
        )

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(
            f"Failed to generate key pair: {e}",
            algorithm=algorithm.value if isinstance(algorithm, AsymmetricAlgorithm) else algorithm,
        ) from e


def save_asymmetric_keypair(
    keypair: AsymmetricKeyPair,
    private_key_path: str | Path,
    public_key_path: str | Path | None = None,
) -> tuple[Path, Path]:
    """Save asymmetric key pair to files.

    Args:
        keypair: Key pair to save.
        private_key_path: Path for private key file.
        public_key_path: Optional path for public key (default: private + '.pub').

    Returns:
        Tuple of (private_key_path, public_key_path).

    Raises:
        FileOperationError: If save fails.
    """
    private_path = Path(private_key_path)
    public_path = Path(public_key_path) if public_key_path else private_path.with_suffix(".pub")

    try:
        private_path.write_bytes(keypair.private_key)
        os.chmod(private_path, 0o600)
        public_path.write_bytes(keypair.public_key)
        return (private_path, public_path)
    except Exception as e:
        raise FileOperationError(
            f"Failed to save key pair: {e}",
            operation="save_asymmetric_keypair",
        ) from e


def load_asymmetric_private_key(
    path: str | Path,
    password: bytes | None = None,
    algorithm: AsymmetricAlgorithm | str = DEFAULT_ASYMMETRIC_ALGORITHM,
):
    """Load asymmetric private key from PEM file.

    Args:
        path: Path to private key file.
        password: Password if key is encrypted.
        algorithm: Expected algorithm.

    Returns:
        Private key object (X25519PrivateKey or RSAPrivateKey).

    Raises:
        DecryptionError: If loading fails.
    """
    path = Path(path)
    algorithm = _normalize_algorithm(algorithm)

    if not path.exists():
        raise DecryptionError(
            f"Private key file not found: {path}",
            algorithm=algorithm.value,
        )

    try:
        pem_data = path.read_bytes()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend(),
        )

        # Validate key type
        if algorithm == AsymmetricAlgorithm.X25519:
            if not isinstance(private_key, x25519.X25519PrivateKey):
                raise DecryptionError(
                    "Key type mismatch: expected X25519",
                    algorithm=algorithm.value,
                )
        elif algorithm == AsymmetricAlgorithm.RSA_OAEP:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise DecryptionError(
                    "Key type mismatch: expected RSA",
                    algorithm=algorithm.value,
                )

        return private_key

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(
            f"Failed to load private key: {e}",
            algorithm=algorithm.value,
        ) from e


def load_asymmetric_public_key(
    path_or_pem: str | Path | bytes,
    algorithm: AsymmetricAlgorithm | str = DEFAULT_ASYMMETRIC_ALGORITHM,
):
    """Load asymmetric public key from PEM file or bytes.

    Args:
        path_or_pem: Path to public key file or PEM bytes.
        algorithm: Expected algorithm.

    Returns:
        Public key object (X25519PublicKey or RSAPublicKey).

    Raises:
        EncryptionError: If loading fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        if isinstance(path_or_pem, bytes):
            pem_data = path_or_pem
        else:
            path = Path(path_or_pem)
            if not path.exists():
                raise EncryptionError(
                    f"Public key file not found: {path}",
                    algorithm=algorithm.value,
                )
            pem_data = path.read_bytes()

        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend(),
        )

        # Validate key type
        if algorithm == AsymmetricAlgorithm.X25519:
            if not isinstance(public_key, x25519.X25519PublicKey):
                raise EncryptionError(
                    "Key type mismatch: expected X25519",
                    algorithm=algorithm.value,
                )
        elif algorithm == AsymmetricAlgorithm.RSA_OAEP:
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise EncryptionError(
                    "Key type mismatch: expected RSA",
                    algorithm=algorithm.value,
                )

        return public_key

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(
            f"Failed to load public key: {e}",
            algorithm=algorithm.value,
        ) from e


def _derive_session_key_x25519(
    shared_secret: bytes,
    ephemeral_public_key_bytes: bytes,
    recipient_public_key_bytes: bytes,
) -> bytes:
    """Derive session key from X25519 shared secret using HKDF."""
    # Combine public keys as context for key derivation
    info = b"filanti-hybrid-x25519" + ephemeral_public_key_bytes + recipient_public_key_bytes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=None,
        info=info,
        backend=default_backend(),
    )

    return hkdf.derive(shared_secret)


def _encrypt_session_key_x25519(
    session_key: bytes,
    recipient_public_key: x25519.X25519PublicKey,
) -> EncryptedSessionKey:
    """Encrypt session key for X25519 recipient using ECDH + HKDF."""
    # Generate ephemeral key pair
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # Perform key exchange
    shared_secret = ephemeral_private.exchange(recipient_public_key)

    # Get raw public key bytes for HKDF context
    ephemeral_public_raw = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recipient_public_raw = recipient_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Derive key encryption key
    kek = _derive_session_key_x25519(shared_secret, ephemeral_public_raw, recipient_public_raw)

    # Encrypt session key with derived KEK using AES-GCM
    nonce = secure_random_bytes(NONCE_SIZE)
    cipher = AESGCM(kek)
    encrypted_session_key = cipher.encrypt(nonce, session_key, None)

    # Combine nonce + encrypted key
    encrypted_key = nonce + encrypted_session_key

    ephemeral_public_pem = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return EncryptedSessionKey(
        encrypted_key=encrypted_key,
        ephemeral_public_key=ephemeral_public_pem,
        algorithm=AsymmetricAlgorithm.X25519.value,
    )


def _decrypt_session_key_x25519(
    encrypted_session_key: EncryptedSessionKey,
    private_key: x25519.X25519PrivateKey,
) -> bytes:
    """Decrypt session key using X25519 private key."""
    if not encrypted_session_key.ephemeral_public_key:
        raise DecryptionError(
            "Missing ephemeral public key for X25519 decryption",
            algorithm=AsymmetricAlgorithm.X25519.value,
        )

    # Load ephemeral public key
    ephemeral_public = serialization.load_pem_public_key(
        encrypted_session_key.ephemeral_public_key,
        backend=default_backend(),
    )

    if not isinstance(ephemeral_public, x25519.X25519PublicKey):
        raise DecryptionError(
            "Invalid ephemeral public key type",
            algorithm=AsymmetricAlgorithm.X25519.value,
        )

    # Perform key exchange
    shared_secret = private_key.exchange(ephemeral_public)

    # Get raw public key bytes
    ephemeral_public_raw = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    recipient_public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # Derive key encryption key
    kek = _derive_session_key_x25519(shared_secret, ephemeral_public_raw, recipient_public_raw)

    # Extract nonce and ciphertext
    encrypted_key = encrypted_session_key.encrypted_key
    nonce = encrypted_key[:NONCE_SIZE]
    ciphertext = encrypted_key[NONCE_SIZE:]

    # Decrypt session key
    try:
        cipher = AESGCM(kek)
        session_key = cipher.decrypt(nonce, ciphertext, None)
        return session_key
    except InvalidTag:
        raise DecryptionError(
            "Session key decryption failed: authentication error",
            algorithm=AsymmetricAlgorithm.X25519.value,
        )


def _encrypt_session_key_rsa(
    session_key: bytes,
    recipient_public_key: rsa.RSAPublicKey,
) -> EncryptedSessionKey:
    """Encrypt session key using RSA-OAEP."""
    encrypted_key = recipient_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return EncryptedSessionKey(
        encrypted_key=encrypted_key,
        ephemeral_public_key=None,  # Not needed for RSA
        algorithm=AsymmetricAlgorithm.RSA_OAEP.value,
    )


def _decrypt_session_key_rsa(
    encrypted_session_key: EncryptedSessionKey,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """Decrypt session key using RSA-OAEP private key."""
    try:
        session_key = private_key.decrypt(
            encrypted_session_key.encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return session_key
    except Exception as e:
        raise DecryptionError(
            f"RSA session key decryption failed: {e}",
            algorithm=AsymmetricAlgorithm.RSA_OAEP.value,
        ) from e


def hybrid_encrypt_bytes(
    plaintext: bytes,
    recipient_public_keys: list[bytes | str | Path],
    algorithm: AsymmetricAlgorithm | str = DEFAULT_ASYMMETRIC_ALGORITHM,
    symmetric_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
    recipient_ids: list[str] | None = None,
) -> HybridEncryptedData:
    """Encrypt bytes using hybrid encryption for multiple recipients.

    Generates a random session key, encrypts data with symmetric AEAD,
    then encrypts the session key for each recipient's public key.

    Args:
        plaintext: Data to encrypt.
        recipient_public_keys: List of recipient public keys (PEM bytes or file paths).
        algorithm: Asymmetric algorithm for key encapsulation.
        symmetric_algorithm: Symmetric algorithm for data encryption.
        recipient_ids: Optional list of recipient identifiers.

    Returns:
        HybridEncryptedData containing encrypted data and session keys.

    Raises:
        EncryptionError: If encryption fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    if not recipient_public_keys:
        raise EncryptionError(
            "At least one recipient public key is required",
            algorithm=algorithm.value,
        )

    if recipient_ids and len(recipient_ids) != len(recipient_public_keys):
        raise EncryptionError(
            "Recipient IDs count must match public keys count",
            algorithm=algorithm.value,
        )

    try:
        # Generate random session key
        session_key = secure_random_bytes(SESSION_KEY_SIZE)

        # Encrypt data with session key using AES-256-GCM
        nonce = secure_random_bytes(NONCE_SIZE)
        cipher = AESGCM(session_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Encrypt session key for each recipient
        encrypted_session_keys = []

        for i, pubkey in enumerate(recipient_public_keys):
            recipient_id = recipient_ids[i] if recipient_ids else None

            # Load public key
            public_key = load_asymmetric_public_key(pubkey, algorithm)

            # Encrypt session key
            if algorithm == AsymmetricAlgorithm.X25519:
                encrypted_sk = _encrypt_session_key_x25519(session_key, public_key)
            elif algorithm == AsymmetricAlgorithm.RSA_OAEP:
                encrypted_sk = _encrypt_session_key_rsa(session_key, public_key)
            else:
                raise EncryptionError(f"Unsupported algorithm: {algorithm}")

            encrypted_sk.recipient_id = recipient_id
            encrypted_session_keys.append(encrypted_sk)

        result = HybridEncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            session_keys=encrypted_session_keys,
            symmetric_algorithm=symmetric_algorithm.value,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        result._session_key = session_key
        return result

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(
            f"Hybrid encryption failed: {e}",
            algorithm=algorithm.value,
        ) from e


def hybrid_decrypt_bytes(
    encrypted: HybridEncryptedData,
    private_key: bytes | str | Path,
    password: bytes | None = None,
    recipient_id: str | None = None,
) -> bytes:
    """Decrypt hybrid encrypted data using private key.

    Args:
        encrypted: Hybrid encrypted data.
        private_key: Private key (PEM bytes or file path).
        password: Password if private key is encrypted.
        recipient_id: Optional recipient ID to select specific session key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        DecryptionError: If decryption fails.
    """
    if not encrypted.session_keys:
        raise DecryptionError("No session keys in encrypted data")

    # Determine algorithm from session keys
    algorithm_str = encrypted.session_keys[0].algorithm
    algorithm = _normalize_algorithm(algorithm_str)

    try:
        # Load private key
        if isinstance(private_key, bytes):
            priv_key = serialization.load_pem_private_key(
                private_key,
                password=password,
                backend=default_backend(),
            )
        else:
            priv_key = load_asymmetric_private_key(private_key, password, algorithm)

        # Find the right session key
        session_key = None
        last_error = None

        for encrypted_sk in encrypted.session_keys:
            # If recipient_id is specified, only try matching keys
            if recipient_id and encrypted_sk.recipient_id != recipient_id:
                continue

            try:
                if algorithm == AsymmetricAlgorithm.X25519:
                    if not isinstance(priv_key, x25519.X25519PrivateKey):
                        continue
                    session_key = _decrypt_session_key_x25519(encrypted_sk, priv_key)
                elif algorithm == AsymmetricAlgorithm.RSA_OAEP:
                    if not isinstance(priv_key, rsa.RSAPrivateKey):
                        continue
                    session_key = _decrypt_session_key_rsa(encrypted_sk, priv_key)
                break
            except DecryptionError as e:
                last_error = e
                continue

        if session_key is None:
            if last_error:
                raise last_error
            raise DecryptionError(
                "Could not decrypt session key with provided private key",
                algorithm=algorithm.value,
            )

        # Resolve deferred internal metadata now that we have the session key
        encrypted.resolve_metadata(session_key)

        # Decrypt data with session key
        try:
            cipher = AESGCM(session_key)
            plaintext = cipher.decrypt(encrypted.nonce, encrypted.ciphertext, None)
            return plaintext
        except InvalidTag:
            raise DecryptionError(
                "Data decryption failed: authentication error",
                algorithm=algorithm.value,
            )

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(
            f"Hybrid decryption failed: {e}",
            algorithm=algorithm.value,
        ) from e


def hybrid_encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    recipient_public_keys: list[bytes | str | Path],
    algorithm: AsymmetricAlgorithm | str = DEFAULT_ASYMMETRIC_ALGORITHM,
    symmetric_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
    recipient_ids: list[str] | None = None,
    file_manager: FileManager | None = None,
    remove_source: bool = False,
    secure_delete: bool = True,
) -> AsymmetricMetadata:
    """Encrypt a file using hybrid encryption.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        recipient_public_keys: List of recipient public keys.
        algorithm: Asymmetric algorithm.
        symmetric_algorithm: Symmetric algorithm.
        recipient_ids: Optional recipient identifiers.
        file_manager: Optional FileManager instance.
        remove_source: If True, delete original file after successful encryption.
        secure_delete: If True and remove_source is True, securely overwrite
            the original file before deletion (defense in depth).

    Returns:
        AsymmetricMetadata for the encrypted file.

    Raises:
        EncryptionError: If encryption fails.
        FileOperationError: If file operations fail.
    """
    algorithm = _normalize_algorithm(algorithm)
    fm = file_manager or get_file_manager()

    try:
        # Read input file
        plaintext = fm.read_bytes(input_path)
        original_size = len(plaintext)

        # Encrypt
        encrypted = hybrid_encrypt_bytes(
            plaintext,
            recipient_public_keys,
            algorithm,
            symmetric_algorithm,
            recipient_ids,
        )

        # Write output
        fm.write_bytes(output_path, encrypted.to_bytes())

        # Remove source file if requested
        if remove_source:
            if secure_delete:
                fm.secure_delete(input_path)
            else:
                fm.delete(input_path)

        return AsymmetricMetadata(
            version=ASYMMETRIC_FORMAT_VERSION_V2,
            asymmetric_algorithm=algorithm.value,
            symmetric_algorithm=symmetric_algorithm.value,
            recipient_count=len(recipient_public_keys),
            original_size=original_size,
            created_at=encrypted.created_at,
        )

    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise EncryptionError(
            f"File encryption failed: {e}",
            algorithm=algorithm.value,
            context={"input": str(input_path)},
        ) from e


def hybrid_decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    private_key: bytes | str | Path,
    password: bytes | None = None,
    recipient_id: str | None = None,
    file_manager: FileManager | None = None,
) -> int:
    """Decrypt a hybrid encrypted file.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        private_key: Private key (PEM bytes or file path).
        password: Password if private key is encrypted.
        recipient_id: Optional recipient ID.
        file_manager: Optional FileManager instance.

    Returns:
        Size of decrypted data in bytes.

    Raises:
        DecryptionError: If decryption fails.
        FileOperationError: If file operations fail.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read encrypted file
        encrypted_data = fm.read_bytes(input_path)

        # Parse encrypted data
        encrypted = HybridEncryptedData.from_bytes(encrypted_data)

        # Decrypt
        plaintext = hybrid_decrypt_bytes(
            encrypted,
            private_key,
            password,
            recipient_id,
        )

        # Write output
        fm.write_bytes(output_path, plaintext)

        return len(plaintext)

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise DecryptionError(
            f"File decryption failed: {e}",
            context={"input": str(input_path)},
        ) from e


def get_hybrid_file_metadata(path: str | Path) -> AsymmetricMetadata:
    """Get metadata from a hybrid encrypted file.

    Args:
        path: Path to encrypted file.

    Returns:
        AsymmetricMetadata extracted from file.

    Raises:
        DecryptionError: If file is not a valid hybrid encrypted file.
    """
    path = Path(path)

    try:
        data = path.read_bytes()
        encrypted = HybridEncryptedData.from_bytes(data)

        # Determine algorithm from first session key
        asymmetric_algo = encrypted.session_keys[0].algorithm if encrypted.session_keys else "unknown"

        return AsymmetricMetadata(
            version=ASYMMETRIC_FORMAT_VERSION_V2,
            asymmetric_algorithm=asymmetric_algo,
            symmetric_algorithm=encrypted.symmetric_algorithm or "encrypted",
            recipient_count=len(encrypted.session_keys),
            created_at=encrypted.created_at or "encrypted",
        )

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(
            f"Failed to read file metadata: {e}",
            context={"path": str(path)},
        ) from e


def get_supported_asymmetric_algorithms() -> list[str]:
    """Get list of supported asymmetric algorithms."""
    return [a.value for a in AsymmetricAlgorithm]

