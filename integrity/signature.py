"""
Digital Signature module.

Provides asymmetric signature operations for file authenticity.
All signature operations use modern, secure algorithms.

Supported algorithms:
- Ed25519 (default, fast, secure, compact signatures)
- ECDSA with P-256/P-384/P-521 curves
"""

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO, NamedTuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

from filanti.core.errors import SignatureError, FileOperationError


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""

    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ECDSA_P521 = "ecdsa-p521"


# Default algorithm for signature operations
DEFAULT_ALGORITHM = SignatureAlgorithm.ED25519

# Chunk size for streaming operations (64 KB)
CHUNK_SIZE = 65536


# Map ECDSA algorithm to curve
_ECDSA_CURVES = {
    SignatureAlgorithm.ECDSA_P256: ec.SECP256R1,
    SignatureAlgorithm.ECDSA_P384: ec.SECP384R1,
    SignatureAlgorithm.ECDSA_P521: ec.SECP521R1,
}


class KeyPair(NamedTuple):
    """Container for asymmetric key pair."""

    private_key: bytes  # PEM-encoded private key
    public_key: bytes   # PEM-encoded public key
    algorithm: str


@dataclass
class SignatureResult:
    """Container for signature computation result."""

    signature: bytes
    algorithm: str
    public_key: bytes  # PEM-encoded
    created_at: str

    def to_hex(self) -> str:
        """Get signature as hex string."""
        return self.signature.hex()

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "signature": self.signature.hex(),
            "algorithm": self.algorithm,
            "public_key": self.public_key.decode("utf-8"),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SignatureResult":
        """Create from dictionary."""
        return cls(
            signature=bytes.fromhex(data["signature"]),
            algorithm=data["algorithm"],
            public_key=data["public_key"].encode("utf-8"),
            created_at=data["created_at"],
        )


@dataclass
class SignatureMetadata:
    """Detached signature metadata for files."""

    version: str = "1.0"
    signature: str | None = None  # hex-encoded
    algorithm: str | None = None
    public_key: str | None = None  # PEM-encoded
    filename: str | None = None
    filesize: int | None = None
    created_at: str | None = None

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, json_str: str) -> "SignatureMetadata":
        """Deserialize from JSON string."""
        data = json.loads(json_str)
        return cls(**data)

    def save(self, path: str | Path) -> None:
        """Save metadata to file."""
        path = Path(path)
        path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "SignatureMetadata":
        """Load metadata from file."""
        path = Path(path)
        return cls.from_json(path.read_text(encoding="utf-8"))


def _normalize_algorithm(algorithm: SignatureAlgorithm | str) -> SignatureAlgorithm:
    """Normalize algorithm to enum."""
    if isinstance(algorithm, str):
        try:
            return SignatureAlgorithm(algorithm.lower())
        except ValueError:
            raise SignatureError(
                f"Unsupported signature algorithm: {algorithm}",
                algorithm=algorithm,
                context={"supported": [a.value for a in SignatureAlgorithm]},
            )
    return algorithm


def generate_keypair(
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    password: bytes | None = None,
) -> KeyPair:
    """Generate a new signing key pair.

    Args:
        algorithm: Signature algorithm to use.
        password: Optional password to encrypt private key.

    Returns:
        KeyPair containing PEM-encoded keys.

    Raises:
        SignatureError: If key generation fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    # Determine encryption for private key
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    try:
        if algorithm == SignatureAlgorithm.ED25519:
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif algorithm in _ECDSA_CURVES:
            curve = _ECDSA_CURVES[algorithm]()
            private_key = ec.generate_private_key(curve, default_backend())
        else:
            raise SignatureError(
                f"Unsupported algorithm for key generation: {algorithm}",
                algorithm=algorithm.value,
            )

        # Serialize keys to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return KeyPair(
            private_key=private_pem,
            public_key=public_pem,
            algorithm=algorithm.value,
        )

    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to generate key pair: {e}",
            algorithm=algorithm.value,
            operation="generate",
        ) from e


def save_keypair(
    keypair: KeyPair,
    private_key_path: str | Path,
    public_key_path: str | Path | None = None,
) -> tuple[Path, Path]:
    """Save key pair to files.

    Args:
        keypair: Key pair to save.
        private_key_path: Path for private key file.
        public_key_path: Optional path for public key (default: private + '.pub')

    Returns:
        Tuple of (private_key_path, public_key_path).

    Raises:
        FileOperationError: If save fails.
    """
    private_key_path = Path(private_key_path)
    public_key_path = Path(public_key_path) if public_key_path else private_key_path.with_suffix(".pub")

    try:
        private_key_path.write_bytes(keypair.private_key)
        public_key_path.write_bytes(keypair.public_key)
        return (private_key_path, public_key_path)
    except Exception as e:
        raise FileOperationError(
            f"Failed to save key pair: {e}",
            operation="save_keypair",
        ) from e


def load_private_key(
    path: str | Path,
    password: bytes | None = None,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
):
    """Load private key from PEM file.

    Args:
        path: Path to private key file.
        password: Password if key is encrypted.
        algorithm: Expected algorithm (for validation).

    Returns:
        Private key object.

    Raises:
        SignatureError: If loading fails.
    """
    path = Path(path)
    algorithm = _normalize_algorithm(algorithm)

    if not path.exists():
        raise SignatureError(
            f"Private key file not found: {path}",
            algorithm=algorithm.value,
            operation="load",
        )

    try:
        pem_data = path.read_bytes()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend(),
        )

        # Validate key type matches algorithm
        if algorithm == SignatureAlgorithm.ED25519:
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise SignatureError(
                    "Key type does not match algorithm: expected Ed25519",
                    algorithm=algorithm.value,
                )
        elif algorithm in _ECDSA_CURVES:
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise SignatureError(
                    f"Key type does not match algorithm: expected ECDSA",
                    algorithm=algorithm.value,
                )

        return private_key

    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to load private key: {e}",
            algorithm=algorithm.value,
            operation="load",
        ) from e


def load_public_key(
    path: str | Path,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
):
    """Load public key from PEM file.

    Args:
        path: Path to public key file.
        algorithm: Expected algorithm (for validation).

    Returns:
        Public key object.

    Raises:
        SignatureError: If loading fails.
    """
    path = Path(path)
    algorithm = _normalize_algorithm(algorithm)

    if not path.exists():
        raise SignatureError(
            f"Public key file not found: {path}",
            algorithm=algorithm.value,
            operation="load",
        )

    try:
        pem_data = path.read_bytes()
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend(),
        )

        return public_key

    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to load public key: {e}",
            algorithm=algorithm.value,
            operation="load",
        ) from e


def _load_key_from_bytes(key_data: bytes, is_private: bool, password: bytes | None = None):
    """Load key from PEM bytes."""
    if is_private:
        return serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend(),
        )
    else:
        return serialization.load_pem_public_key(
            key_data,
            backend=default_backend(),
        )


def sign_bytes(
    data: bytes,
    private_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    password: bytes | None = None,
) -> SignatureResult:
    """Sign bytes with private key.

    Args:
        data: Data to sign.
        private_key: PEM-encoded private key.
        algorithm: Signature algorithm.
        password: Password if key is encrypted.

    Returns:
        SignatureResult containing the signature.

    Raises:
        SignatureError: If signing fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        key = _load_key_from_bytes(private_key, is_private=True, password=password)

        if algorithm == SignatureAlgorithm.ED25519:
            signature = key.sign(data)
        elif algorithm in _ECDSA_CURVES:
            signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
        else:
            raise SignatureError(
                f"Unsupported signing algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        # Get public key for verification
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return SignatureResult(
            signature=signature,
            algorithm=algorithm.value,
            public_key=public_pem,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to sign data: {e}",
            algorithm=algorithm.value,
            operation="sign",
        ) from e


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify signature with public key.

    Args:
        data: Original data that was signed.
        signature: Signature to verify.
        public_key: PEM-encoded public key.
        algorithm: Signature algorithm used.

    Returns:
        True if signature is valid.

    Raises:
        SignatureError: If verification fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        key = _load_key_from_bytes(public_key, is_private=False)

        if algorithm == SignatureAlgorithm.ED25519:
            key.verify(signature, data)
        elif algorithm in _ECDSA_CURVES:
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            raise SignatureError(
                f"Unsupported verification algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        return True

    except InvalidSignature:
        raise SignatureError(
            "Signature verification failed: invalid signature",
            algorithm=algorithm.value,
            operation="verify",
        )
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to verify signature: {e}",
            algorithm=algorithm.value,
            operation="verify",
        ) from e


def sign_stream(
    stream: BinaryIO,
    private_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    password: bytes | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> SignatureResult:
    """Sign a stream with private key.

    For non-Ed25519 algorithms, uses a digest-based approach.
    For Ed25519, reads the entire stream (Ed25519 doesn't support streaming).

    Args:
        stream: Binary stream to sign.
        private_key: PEM-encoded private key.
        algorithm: Signature algorithm.
        password: Password if key is encrypted.
        chunk_size: Size of chunks to read.

    Returns:
        SignatureResult containing the signature.

    Raises:
        SignatureError: If signing fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        key = _load_key_from_bytes(private_key, is_private=True, password=password)

        if algorithm == SignatureAlgorithm.ED25519:
            # Ed25519 doesn't support streaming, read all data
            data = stream.read()
            signature = key.sign(data)
        elif algorithm in _ECDSA_CURVES:
            # Use prehashed signature for ECDSA
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

            # Hash the stream
            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)

            digest = hasher.finalize()
            signature = key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        else:
            raise SignatureError(
                f"Unsupported streaming sign algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return SignatureResult(
            signature=signature,
            algorithm=algorithm.value,
            public_key=public_pem,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to sign stream: {e}",
            algorithm=algorithm.value,
            operation="sign",
        ) from e


def verify_stream_signature(
    stream: BinaryIO,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    chunk_size: int = CHUNK_SIZE,
) -> bool:
    """Verify signature of a stream.

    Args:
        stream: Binary stream to verify.
        signature: Signature to verify.
        public_key: PEM-encoded public key.
        algorithm: Signature algorithm used.
        chunk_size: Size of chunks to read.

    Returns:
        True if signature is valid.

    Raises:
        SignatureError: If verification fails.
    """
    algorithm = _normalize_algorithm(algorithm)

    try:
        key = _load_key_from_bytes(public_key, is_private=False)

        if algorithm == SignatureAlgorithm.ED25519:
            data = stream.read()
            key.verify(signature, data)
        elif algorithm in _ECDSA_CURVES:
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

            hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)

            digest = hasher.finalize()
            key.verify(signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        else:
            raise SignatureError(
                f"Unsupported streaming verify algorithm: {algorithm}",
                algorithm=algorithm.value,
            )

        return True

    except InvalidSignature:
        raise SignatureError(
            "Signature verification failed: invalid signature",
            algorithm=algorithm.value,
            operation="verify",
        )
    except SignatureError:
        raise
    except Exception as e:
        raise SignatureError(
            f"Failed to verify stream signature: {e}",
            algorithm=algorithm.value,
            operation="verify",
        ) from e


def sign_file(
    file_path: str | Path,
    private_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    password: bytes | None = None,
) -> SignatureResult:
    """Sign a file with private key.

    Args:
        file_path: Path to file to sign.
        private_key: PEM-encoded private key.
        algorithm: Signature algorithm.
        password: Password if key is encrypted.

    Returns:
        SignatureResult containing the signature.

    Raises:
        SignatureError: If signing fails.
        FileOperationError: If file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileOperationError(
            f"File not found: {file_path}",
            path=str(file_path),
            operation="sign",
        )

    try:
        with open(file_path, "rb") as f:
            return sign_stream(f, private_key, algorithm, password)
    except SignatureError:
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to read file for signing: {e}",
            path=str(file_path),
            operation="sign",
        ) from e


def verify_file_signature(
    file_path: str | Path,
    signature: bytes,
    public_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
) -> bool:
    """Verify file signature.

    Args:
        file_path: Path to file to verify.
        signature: Signature to verify.
        public_key: PEM-encoded public key.
        algorithm: Signature algorithm used.

    Returns:
        True if signature is valid.

    Raises:
        SignatureError: If verification fails.
        FileOperationError: If file cannot be read.
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileOperationError(
            f"File not found: {file_path}",
            path=str(file_path),
            operation="verify",
        )

    try:
        with open(file_path, "rb") as f:
            return verify_stream_signature(f, signature, public_key, algorithm)
    except SignatureError:
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to read file for verification: {e}",
            path=str(file_path),
            operation="verify",
        ) from e


def create_signature_file(
    file_path: str | Path,
    private_key: bytes,
    algorithm: SignatureAlgorithm | str = DEFAULT_ALGORITHM,
    password: bytes | None = None,
    output_path: str | Path | None = None,
    include_public_key: bool = True,
) -> Path:
    """Create detached signature file.

    Args:
        file_path: Path to file to sign.
        private_key: PEM-encoded private key.
        algorithm: Signature algorithm.
        password: Password if key is encrypted.
        output_path: Optional output path (default: file_path + '.sig')
        include_public_key: Whether to include public key in metadata.

    Returns:
        Path to the created signature file.

    Raises:
        SignatureError: If signing fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    output_path = Path(output_path) if output_path else file_path.with_suffix(file_path.suffix + ".sig")

    result = sign_file(file_path, private_key, algorithm, password)

    metadata = SignatureMetadata(
        signature=result.to_hex(),
        algorithm=result.algorithm,
        public_key=result.public_key.decode("utf-8") if include_public_key else None,
        filename=file_path.name,
        filesize=file_path.stat().st_size,
        created_at=result.created_at,
    )

    try:
        metadata.save(output_path)
        return output_path
    except Exception as e:
        raise FileOperationError(
            f"Failed to save signature metadata: {e}",
            path=str(output_path),
            operation="create_signature_file",
        ) from e


def verify_signature_file(
    file_path: str | Path,
    metadata_path: str | Path | None = None,
    public_key: bytes | None = None,
) -> bool:
    """Verify file using detached signature metadata.

    Args:
        file_path: Path to file to verify.
        metadata_path: Optional metadata path (default: file_path + '.sig')
        public_key: Optional public key (uses embedded key if not provided).

    Returns:
        True if signature verification passes.

    Raises:
        SignatureError: If verification fails.
        FileOperationError: If file operations fail.
    """
    file_path = Path(file_path)
    metadata_path = Path(metadata_path) if metadata_path else file_path.with_suffix(file_path.suffix + ".sig")

    if not metadata_path.exists():
        raise FileOperationError(
            f"Signature metadata not found: {metadata_path}",
            path=str(metadata_path),
            operation="verify_signature_file",
        )

    try:
        metadata = SignatureMetadata.load(metadata_path)
    except Exception as e:
        raise SignatureError(
            f"Failed to load signature metadata: {e}",
            context={"metadata_path": str(metadata_path)},
            operation="verify",
        ) from e

    if not metadata.signature or not metadata.algorithm:
        raise SignatureError(
            "Invalid signature metadata: missing signature or algorithm",
            context={"metadata_path": str(metadata_path)},
            operation="verify",
        )

    # Use provided public key or embedded key
    if public_key is None:
        if not metadata.public_key:
            raise SignatureError(
                "No public key provided and none embedded in metadata",
                context={"metadata_path": str(metadata_path)},
                operation="verify",
            )
        public_key = metadata.public_key.encode("utf-8")

    signature = bytes.fromhex(metadata.signature)
    return verify_file_signature(file_path, signature, public_key, metadata.algorithm)

