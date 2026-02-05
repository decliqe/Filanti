"""
Filanti SDK - High-level Python API.

Provides a unified, easy-to-use interface for all Filanti operations.
This is the recommended way to integrate Filanti into Python applications.

Example:
    from filanti.api import Filanti

    # Hash a file
    result = Filanti.hash_file("document.pdf")

    # Encrypt with password
    Filanti.encrypt("secret.txt", password="my-password")

    # Sign a file
    keypair = Filanti.generate_keypair()
    Filanti.sign("document.pdf", private_key=keypair.private_key)
"""

from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Hashing
from filanti.hashing.crypto_hash import (
    HashAlgorithm,
    hash_bytes,
    hash_file,
    hash_stream,
    verify_hash,
    verify_file_hash,
    get_supported_algorithms as get_hash_algorithms,
)

# Encryption
from filanti.crypto import (
    EncryptionAlgorithm,
    EncryptedData,
)
from filanti.crypto import encrypt_bytes as _encrypt_bytes
from filanti.crypto import decrypt_bytes as _decrypt_bytes
from filanti.crypto import encrypt_bytes_with_password as _encrypt_bytes_with_password
from filanti.crypto import decrypt_bytes_with_password as _decrypt_bytes_with_password
from filanti.crypto import (
    encrypt_file,
    decrypt_file,
    encrypt_file_with_password,
    decrypt_file_with_password,
    get_file_metadata,
)

# Asymmetric / Hybrid Encryption
from filanti.crypto.asymmetric import (
    AsymmetricAlgorithm,
    AsymmetricKeyPair,
    HybridEncryptedData,
    AsymmetricMetadata,
    generate_asymmetric_keypair as _generate_asymmetric_keypair,
    save_asymmetric_keypair as _save_asymmetric_keypair,
    load_asymmetric_private_key,
    load_asymmetric_public_key,
    hybrid_encrypt_bytes as _hybrid_encrypt_bytes,
    hybrid_decrypt_bytes as _hybrid_decrypt_bytes,
    hybrid_encrypt_file as _hybrid_encrypt_file,
    hybrid_decrypt_file as _hybrid_decrypt_file,
    get_hybrid_file_metadata,
    get_supported_asymmetric_algorithms,
)

from filanti.crypto.key_management import (
    generate_key,
    generate_nonce,
    split_key,
    derive_subkey,
    KEY_SIZE_128,
    KEY_SIZE_256,
    KEY_SIZE_512,
)

from filanti.crypto.kdf import (
    KDFAlgorithm,
    derive_key,
    derive_key_with_salt,
    generate_salt,
)

# Integrity
from filanti.integrity.mac import (
    MACAlgorithm,
    MACResult,
    IntegrityMetadata,
    compute_mac,
    verify_mac,
    compute_file_mac,
    verify_file_mac,
    create_integrity_file,
    verify_integrity_file,
)

from filanti.integrity.signature import (
    SignatureAlgorithm,
    KeyPair,
    SignatureResult,
    SignatureMetadata,
    generate_keypair,
    save_keypair,
    load_private_key,
    load_public_key,
    sign_bytes,
    verify_signature,
    sign_file,
    verify_file_signature,
    create_signature_file,
    verify_signature_file,
)

from filanti.integrity.checksum import (
    ChecksumAlgorithm,
    ChecksumResult,
    ChecksumMetadata,
    compute_checksum,
    verify_checksum,
    compute_file_checksum,
    verify_file_checksum,
    create_checksum_file,
    verify_checksum_file,
)

# Errors
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

# Secrets
from filanti.core.secrets import (
    resolve_secret,
    resolve_secret_optional,
    is_env_reference,
    get_env_var_name,
    load_dotenv,
    get_supported_patterns,
    redact_secret,
    redact_secrets,
    create_safe_json_output,
    REDACTED_PLACEHOLDER,
)


@dataclass
class HashResult:
    """Result of a hash operation."""
    hash: str
    algorithm: str
    file: str | None = None


@dataclass
class EncryptResult:
    """Result of an encryption operation."""
    output_path: Path
    algorithm: str
    kdf_algorithm: str | None = None


@dataclass
class DecryptResult:
    """Result of a decryption operation."""
    output_path: Path
    size: int


@dataclass
class HybridEncryptResult:
    """Result of a hybrid encryption operation."""
    output_path: Path
    asymmetric_algorithm: str
    symmetric_algorithm: str
    recipient_count: int


@dataclass
class HybridDecryptResult:
    """Result of a hybrid decryption operation."""
    output_path: Path
    size: int


@dataclass
class SignResult:
    """Result of a signing operation."""
    signature: bytes
    signature_hex: str
    algorithm: str
    signature_file: Path | None = None


@dataclass
class VerifyResult:
    """Result of a verification operation."""
    valid: bool
    algorithm: str
    file: str


class Filanti:
    """High-level API for Filanti operations.

    All methods are static for convenience. For more control,
    use the underlying modules directly.
    """

    # =========================================================================
    # HASHING
    # =========================================================================

    @staticmethod
    def hash(
        data: bytes,
        algorithm: str = "sha256",
    ) -> HashResult:
        """Hash bytes data.

        Args:
            data: Bytes to hash.
            algorithm: Hash algorithm (sha256, sha512, blake2b, etc.)

        Returns:
            HashResult with the computed hash.
        """
        digest = hash_bytes(data, algorithm)
        return HashResult(hash=digest, algorithm=algorithm)

    @staticmethod
    def hash_file(
        path: str | Path,
        algorithm: str = "sha256",
    ) -> HashResult:
        """Hash a file.

        Args:
            path: Path to file.
            algorithm: Hash algorithm.

        Returns:
            HashResult with the computed hash.
        """
        digest = hash_file(str(path), algorithm)
        return HashResult(hash=digest, algorithm=algorithm, file=str(path))

    @staticmethod
    def verify_hash(
        data: bytes,
        expected: str,
        algorithm: str = "sha256",
    ) -> VerifyResult:
        """Verify hash of bytes.

        Args:
            data: Data to verify.
            expected: Expected hash (hex).
            algorithm: Hash algorithm.

        Returns:
            VerifyResult indicating if hash matches.
        """
        try:
            valid = verify_hash(data, expected, algorithm)
            return VerifyResult(valid=valid, algorithm=algorithm, file="<bytes>")
        except ValidationError:
            return VerifyResult(valid=False, algorithm=algorithm, file="<bytes>")

    @staticmethod
    def verify_file_hash(
        path: str | Path,
        expected: str,
        algorithm: str = "sha256",
    ) -> VerifyResult:
        """Verify hash of a file.

        Args:
            path: Path to file.
            expected: Expected hash (hex).
            algorithm: Hash algorithm.

        Returns:
            VerifyResult indicating if hash matches.
        """
        try:
            valid = verify_file_hash(str(path), expected, algorithm)
            return VerifyResult(valid=valid, algorithm=algorithm, file=str(path))
        except ValidationError:
            return VerifyResult(valid=False, algorithm=algorithm, file=str(path))

    # =========================================================================
    # ENCRYPTION
    # =========================================================================

    @staticmethod
    def encrypt(
        path: str | Path,
        password: str | None = None,
        key: bytes | None = None,
        output: str | Path | None = None,
        algorithm: str = "aes-256-gcm",
    ) -> EncryptResult:
        """Encrypt a file.

        Provide either password OR key, not both.

        Supports ENV-based secret resolution for password:
            Filanti.encrypt("file.txt", password="ENV:MY_PASSWORD")

        Args:
            path: Path to file to encrypt.
            password: Password for key derivation. Supports ENV:VAR_NAME syntax.
            key: Raw encryption key (32 bytes for AES-256).
            output: Output path (default: path + .enc).
            algorithm: Encryption algorithm.

        Returns:
            EncryptResult with output path and metadata.

        Raises:
            SecretError: If ENV variable is not set or empty.
        """
        path = Path(path)
        out_path = Path(output) if output else path.with_suffix(path.suffix + ".enc")
        alg = EncryptionAlgorithm(algorithm.lower())

        if password:
            # Resolve password from ENV if needed
            resolved_password = resolve_secret(password)
            metadata = encrypt_file_with_password(path, out_path, resolved_password, alg)
            return EncryptResult(
                output_path=out_path,
                algorithm=metadata.algorithm,
                kdf_algorithm=metadata.kdf_algorithm,
            )
        elif key:
            encrypt_file(path, out_path, key, alg)
            return EncryptResult(output_path=out_path, algorithm=algorithm)
        else:
            raise ValueError("Must provide either password or key")

    @staticmethod
    def decrypt(
        path: str | Path,
        password: str | None = None,
        key: bytes | None = None,
        output: str | Path | None = None,
    ) -> DecryptResult:
        """Decrypt a file.

        Provide either password OR key, not both.

        Supports ENV-based secret resolution for password:
            Filanti.decrypt("file.enc", password="ENV:MY_PASSWORD")

        Args:
            path: Path to encrypted file.
            password: Password used for encryption. Supports ENV:VAR_NAME syntax.
            key: Raw encryption key.
            output: Output path (default: removes .enc extension).

        Returns:
            DecryptResult with output path and size.

        Raises:
            SecretError: If ENV variable is not set or empty.
        """
        path = Path(path)
        if output:
            out_path = Path(output)
        elif str(path).endswith(".enc"):
            out_path = Path(str(path)[:-4])
        else:
            out_path = path.with_suffix(".dec")

        if password:
            # Resolve password from ENV if needed
            resolved_password = resolve_secret(password)
            size = decrypt_file_with_password(path, out_path, resolved_password)
        elif key:
            size = decrypt_file(path, out_path, key)
        else:
            raise ValueError("Must provide either password or key")

        return DecryptResult(output_path=out_path, size=size)

    @staticmethod
    def encrypt_bytes(
        data: bytes,
        password: str | None = None,
        key: bytes | None = None,
        algorithm: str = "aes-256-gcm",
    ) -> bytes:
        """Encrypt bytes data.

        Supports ENV-based secret resolution for password:
            Filanti.encrypt_bytes(data, password="ENV:MY_PASSWORD")

        Args:
            data: Data to encrypt.
            password: Password for key derivation. Supports ENV:VAR_NAME syntax.
            key: Raw encryption key.
            algorithm: Encryption algorithm.

        Returns:
            Encrypted bytes (includes nonce and auth tag).

        Raises:
            SecretError: If ENV variable is not set or empty.
        """
        alg = EncryptionAlgorithm(algorithm.lower())

        if password is not None:
            # Resolve password from ENV if needed
            resolved_password = resolve_secret(password)
            result = _encrypt_bytes_with_password(data, resolved_password, alg)
            return result.to_bytes()
        elif key is not None:
            result = _encrypt_bytes(data, key, alg)
            # Return nonce + ciphertext for raw key encryption
            return result.nonce + result.ciphertext
        else:
            raise ValueError("Must provide either password or key")

    @staticmethod
    def decrypt_bytes(
        data: bytes,
        password: str | None = None,
        key: bytes | None = None,
    ) -> bytes:
        """Decrypt bytes data.

        Supports ENV-based secret resolution for password:
            Filanti.decrypt_bytes(data, password="ENV:MY_PASSWORD")

        Args:
            data: Encrypted data.
            password: Password used for encryption. Supports ENV:VAR_NAME syntax.
            key: Raw encryption key.

        Returns:
            Decrypted bytes.

        Raises:
            SecretError: If ENV variable is not set or empty.
        """
        if password is not None:
            # Resolve password from ENV if needed
            resolved_password = resolve_secret(password)
            # Parse the encrypted data from bytes
            encrypted = EncryptedData.from_bytes(data)
            return _decrypt_bytes_with_password(encrypted, resolved_password)
        elif key is not None:
            # For raw key, data is nonce (12 bytes) + ciphertext
            nonce = data[:12]
            ciphertext = data[12:]
            encrypted = EncryptedData(
                ciphertext=ciphertext,
                nonce=nonce,
                algorithm="aes-256-gcm"
            )
            return _decrypt_bytes(encrypted, key)
        else:
            raise ValueError("Must provide either password or key")

    # =========================================================================
    # INTEGRITY (MAC)
    # =========================================================================

    @staticmethod
    def mac(
        data: bytes,
        key: bytes,
        algorithm: str = "hmac-sha256",
    ) -> MACResult:
        """Compute HMAC of bytes.

        Args:
            data: Data to authenticate.
            key: Secret key.
            algorithm: MAC algorithm.

        Returns:
            MACResult with the computed MAC.
        """
        return compute_mac(data, key, algorithm)

    @staticmethod
    def mac_file(
        path: str | Path,
        key: bytes,
        algorithm: str = "hmac-sha256",
        create_file: bool = False,
    ) -> MACResult | Path:
        """Compute HMAC of a file.

        Args:
            path: Path to file.
            key: Secret key.
            algorithm: MAC algorithm.
            create_file: If True, create detached .mac file.

        Returns:
            MACResult or Path to .mac file if create_file=True.
        """
        if create_file:
            return create_integrity_file(path, key, algorithm)
        return compute_file_mac(path, key, algorithm)

    @staticmethod
    def verify_mac(
        data: bytes,
        mac_value: bytes,
        key: bytes,
        algorithm: str = "hmac-sha256",
    ) -> bool:
        """Verify HMAC of bytes.

        Args:
            data: Data to verify.
            mac_value: Expected MAC.
            key: Secret key.
            algorithm: MAC algorithm.

        Returns:
            True if MAC is valid.

        Raises:
            IntegrityError: If MAC is invalid.
        """
        return verify_mac(data, mac_value, key, algorithm)

    @staticmethod
    def verify_mac_file(
        path: str | Path,
        key: bytes,
        mac_value: bytes | None = None,
        mac_file: str | Path | None = None,
    ) -> bool:
        """Verify HMAC of a file.

        Args:
            path: Path to file.
            key: Secret key.
            mac_value: Expected MAC (if not using mac_file).
            mac_file: Path to .mac metadata file.

        Returns:
            True if MAC is valid.
        """
        if mac_file is not None or mac_value is None:
            return verify_integrity_file(path, key, mac_file)
        return verify_file_mac(path, mac_value, key)

    # =========================================================================
    # SIGNATURES
    # =========================================================================

    @staticmethod
    def generate_keypair(
        algorithm: str = "ed25519",
        password: str | bytes | None = None,
    ) -> KeyPair:
        """Generate a new signing key pair.

        Args:
            algorithm: Signature algorithm (ed25519, ecdsa-p256, etc.)
            password: Optional password to protect private key.

        Returns:
            KeyPair with PEM-encoded private and public keys.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        return generate_keypair(algorithm, password)

    @staticmethod
    def sign(
        data: bytes,
        private_key: bytes,
        algorithm: str = "ed25519",
        password: str | bytes | None = None,
    ) -> SignatureResult:
        """Sign bytes data.

        Args:
            data: Data to sign.
            private_key: PEM-encoded private key.
            algorithm: Signature algorithm.
            password: Password if private key is encrypted.

        Returns:
            SignatureResult with the signature.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        return sign_bytes(data, private_key, algorithm, password)

    @staticmethod
    def sign_file(
        path: str | Path,
        private_key: bytes,
        algorithm: str = "ed25519",
        password: str | bytes | None = None,
        create_file: bool = False,
        embed_public_key: bool = True,
    ) -> SignatureResult | Path:
        """Sign a file.

        Args:
            path: Path to file.
            private_key: PEM-encoded private key.
            algorithm: Signature algorithm.
            password: Password if private key is encrypted.
            create_file: If True, create detached .sig file.
            embed_public_key: Include public key in signature file.

        Returns:
            SignatureResult or Path to .sig file if create_file=True.
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        if create_file:
            return create_signature_file(
                path, private_key, algorithm, password,
                include_public_key=embed_public_key,
            )
        return sign_file(path, private_key, algorithm, password)

    @staticmethod
    def verify_signature(
        data: bytes,
        signature: bytes,
        public_key: bytes,
        algorithm: str = "ed25519",
    ) -> bool:
        """Verify signature of bytes.

        Args:
            data: Original data.
            signature: Signature to verify.
            public_key: PEM-encoded public key.
            algorithm: Signature algorithm.

        Returns:
            True if signature is valid.

        Raises:
            SignatureError: If signature is invalid.
        """
        return verify_signature(data, signature, public_key, algorithm)

    @staticmethod
    def verify_signature_file(
        path: str | Path,
        signature_file: str | Path | None = None,
        public_key: bytes | None = None,
    ) -> bool:
        """Verify signature of a file.

        Args:
            path: Path to file.
            signature_file: Path to .sig file (default: path + .sig).
            public_key: PEM-encoded public key (uses embedded if not provided).

        Returns:
            True if signature is valid.
        """
        return verify_signature_file(path, signature_file, public_key)

    # =========================================================================
    # CHECKSUM
    # =========================================================================

    @staticmethod
    def checksum(
        data: bytes,
        algorithm: str = "crc32",
    ) -> ChecksumResult:
        """Compute checksum of bytes.

        Note: Checksums are NOT cryptographically secure.
        Use for detecting accidental corruption only.

        Args:
            data: Data to checksum.
            algorithm: Checksum algorithm (crc32, adler32, xxhash64).

        Returns:
            ChecksumResult with the computed checksum.
        """
        return compute_checksum(data, algorithm)

    @staticmethod
    def checksum_file(
        path: str | Path,
        algorithm: str = "crc32",
        create_file: bool = False,
    ) -> ChecksumResult | Path:
        """Compute checksum of a file.

        Args:
            path: Path to file.
            algorithm: Checksum algorithm.
            create_file: If True, create detached .checksum file.

        Returns:
            ChecksumResult or Path to .checksum file if create_file=True.
        """
        if create_file:
            return create_checksum_file(path, algorithm)
        return compute_file_checksum(path, algorithm)

    @staticmethod
    def verify_checksum(
        data: bytes,
        expected: int,
        algorithm: str = "crc32",
    ) -> bool:
        """Verify checksum of bytes.

        Args:
            data: Data to verify.
            expected: Expected checksum value.
            algorithm: Checksum algorithm.

        Returns:
            True if checksum matches.

        Raises:
            IntegrityError: If checksum doesn't match.
        """
        return verify_checksum(data, expected, algorithm)

    @staticmethod
    def verify_checksum_file(
        path: str | Path,
        expected: int | None = None,
        checksum_file: str | Path | None = None,
        algorithm: str = "crc32",
    ) -> bool:
        """Verify checksum of a file.

        Args:
            path: Path to file.
            expected: Expected checksum (if not using checksum_file).
            checksum_file: Path to .checksum metadata file.
            algorithm: Checksum algorithm.

        Returns:
            True if checksum matches.
        """
        if checksum_file is not None or expected is None:
            return verify_checksum_file(path, checksum_file)
        return verify_file_checksum(path, expected, algorithm)

    # =========================================================================
    # KEY MANAGEMENT
    # =========================================================================

    @staticmethod
    def generate_key(size: int = 32) -> bytes:
        """Generate a random encryption key.

        Args:
            size: Key size in bytes (16, 32, or 64).

        Returns:
            Random key bytes.
        """
        return generate_key(size)

    @staticmethod
    def derive_key(
        password: str,
        salt: bytes | None = None,
        algorithm: str = "argon2id",
    ) -> tuple[bytes, bytes]:
        """Derive encryption key from password.

        Args:
            password: Password to derive key from.
            salt: Salt bytes (generated if not provided).
            algorithm: KDF algorithm (argon2id, scrypt).

        Returns:
            Tuple of (derived_key, salt).
        """
        from filanti.crypto.kdf import KDFParams, derive_key as kdf_derive_key

        params = KDFParams(algorithm=KDFAlgorithm(algorithm))
        result = kdf_derive_key(password, salt=salt, params=params)
        return result.key, result.salt

    # =========================================================================
    # ASYMMETRIC / HYBRID ENCRYPTION
    # =========================================================================

    @staticmethod
    def generate_asymmetric_keypair(
        algorithm: str = "x25519",
        password: str | bytes | None = None,
        rsa_key_size: int = 4096,
    ) -> AsymmetricKeyPair:
        """Generate asymmetric key pair for hybrid encryption.

        Args:
            algorithm: Key exchange algorithm (x25519, rsa-oaep).
            password: Optional password to protect private key.
            rsa_key_size: RSA key size in bits (only for RSA).

        Returns:
            AsymmetricKeyPair with PEM-encoded private and public keys.

        Example:
            # Generate X25519 key pair
            keypair = Filanti.generate_asymmetric_keypair()

            # Generate RSA key pair with password protection
            keypair = Filanti.generate_asymmetric_keypair(
                algorithm="rsa-oaep",
                password="my-password"
            )
        """
        if isinstance(password, str):
            password = password.encode("utf-8")
        return _generate_asymmetric_keypair(algorithm, password, rsa_key_size)

    @staticmethod
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

        Example:
            keypair = Filanti.generate_asymmetric_keypair()
            Filanti.save_asymmetric_keypair(keypair, "my-key.pem")
            # Creates my-key.pem (private) and my-key.pub (public)
        """
        return _save_asymmetric_keypair(keypair, private_key_path, public_key_path)

    @staticmethod
    def hybrid_encrypt(
        path: str | Path,
        recipient_public_keys: list[bytes | str | Path],
        output: str | Path | None = None,
        algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
        recipient_ids: list[str] | None = None,
    ) -> HybridEncryptResult:
        """Encrypt a file using hybrid encryption for multiple recipients.

        Uses asymmetric key exchange to establish a shared session key,
        then encrypts data with fast symmetric AEAD.

        Args:
            path: Path to file to encrypt.
            recipient_public_keys: List of recipient public keys (PEM files or bytes).
            output: Output path (default: path + .henc).
            algorithm: Asymmetric algorithm (x25519, rsa-oaep).
            symmetric_algorithm: Symmetric algorithm (aes-256-gcm).
            recipient_ids: Optional list of recipient identifiers.

        Returns:
            HybridEncryptResult with output path and metadata.

        Example:
            # Encrypt for single recipient
            Filanti.hybrid_encrypt("secret.txt", ["recipient.pub"])

            # Encrypt for multiple recipients
            Filanti.hybrid_encrypt(
                "secret.txt",
                ["alice.pub", "bob.pub"],
                recipient_ids=["alice", "bob"]
            )
        """
        path = Path(path)
        out_path = Path(output) if output else path.with_suffix(path.suffix + ".henc")

        alg = AsymmetricAlgorithm(algorithm.lower())
        sym_alg = EncryptionAlgorithm(symmetric_algorithm.lower())

        metadata = _hybrid_encrypt_file(
            path, out_path, recipient_public_keys,
            alg, sym_alg, recipient_ids
        )

        return HybridEncryptResult(
            output_path=out_path,
            asymmetric_algorithm=metadata.asymmetric_algorithm,
            symmetric_algorithm=metadata.symmetric_algorithm,
            recipient_count=metadata.recipient_count,
        )

    @staticmethod
    def hybrid_decrypt(
        path: str | Path,
        private_key: bytes | str | Path,
        output: str | Path | None = None,
        password: str | bytes | None = None,
        recipient_id: str | None = None,
    ) -> HybridDecryptResult:
        """Decrypt a hybrid encrypted file.

        Args:
            path: Path to encrypted file.
            private_key: Private key (PEM file path or bytes).
            output: Output path (default: removes .henc extension).
            password: Password if private key is encrypted.
            recipient_id: Optional recipient ID to select specific session key.

        Returns:
            HybridDecryptResult with output path and size.

        Example:
            # Decrypt with private key file
            Filanti.hybrid_decrypt("secret.txt.henc", "my-key.pem")

            # Decrypt with password-protected key
            Filanti.hybrid_decrypt(
                "secret.txt.henc",
                "my-key.pem",
                password="my-password"
            )
        """
        path = Path(path)
        if output:
            out_path = Path(output)
        elif str(path).endswith(".henc"):
            out_path = Path(str(path)[:-5])
        else:
            out_path = path.with_suffix(".dec")

        if isinstance(password, str):
            password = password.encode("utf-8")

        size = _hybrid_decrypt_file(path, out_path, private_key, password, recipient_id)

        return HybridDecryptResult(output_path=out_path, size=size)

    @staticmethod
    def hybrid_encrypt_bytes(
        data: bytes,
        recipient_public_keys: list[bytes | str | Path],
        algorithm: str = "x25519",
        symmetric_algorithm: str = "aes-256-gcm",
        recipient_ids: list[str] | None = None,
    ) -> bytes:
        """Encrypt bytes using hybrid encryption.

        Args:
            data: Data to encrypt.
            recipient_public_keys: List of recipient public keys.
            algorithm: Asymmetric algorithm.
            symmetric_algorithm: Symmetric algorithm.
            recipient_ids: Optional recipient identifiers.

        Returns:
            Encrypted bytes (serialized hybrid format).

        Example:
            encrypted = Filanti.hybrid_encrypt_bytes(
                b"secret data",
                ["recipient.pub"]
            )
        """
        alg = AsymmetricAlgorithm(algorithm.lower())
        sym_alg = EncryptionAlgorithm(symmetric_algorithm.lower())

        result = _hybrid_encrypt_bytes(
            data, recipient_public_keys, alg, sym_alg, recipient_ids
        )
        return result.to_bytes()

    @staticmethod
    def hybrid_decrypt_bytes(
        data: bytes,
        private_key: bytes | str | Path,
        password: str | bytes | None = None,
        recipient_id: str | None = None,
    ) -> bytes:
        """Decrypt hybrid encrypted bytes.

        Args:
            data: Encrypted data (serialized hybrid format).
            private_key: Private key (PEM bytes or file path).
            password: Password if private key is encrypted.
            recipient_id: Optional recipient ID.

        Returns:
            Decrypted bytes.

        Example:
            decrypted = Filanti.hybrid_decrypt_bytes(encrypted, "my-key.pem")
        """
        if isinstance(password, str):
            password = password.encode("utf-8")

        encrypted = HybridEncryptedData.from_bytes(data)
        return _hybrid_decrypt_bytes(encrypted, private_key, password, recipient_id)

    @staticmethod
    def get_hybrid_file_info(path: str | Path) -> AsymmetricMetadata:
        """Get metadata from a hybrid encrypted file.

        Args:
            path: Path to hybrid encrypted file.

        Returns:
            AsymmetricMetadata with file information.

        Example:
            info = Filanti.get_hybrid_file_info("secret.txt.henc")
            print(f"Recipients: {info.recipient_count}")
        """
        return get_hybrid_file_metadata(path)

    # =========================================================================
    # UTILITY
    # =========================================================================

    @staticmethod
    def algorithms() -> dict:
        """Get all supported algorithms.

        Returns:
            Dictionary of algorithm categories and their supported values.
        """
        return {
            "hash": get_hash_algorithms(),
            "encryption": [e.value for e in EncryptionAlgorithm],
            "asymmetric": get_supported_asymmetric_algorithms(),
            "mac": [m.value for m in MACAlgorithm],
            "signature": [s.value for s in SignatureAlgorithm],
            "checksum": [c.value for c in ChecksumAlgorithm],
            "kdf": [k.value for k in KDFAlgorithm],
        }

    # =========================================================================
    # SECRETS
    # =========================================================================

    @staticmethod
    def resolve_secret(value: str, allow_empty: bool = False) -> str:
        """Resolve a secret value from ENV variable.

        Supports ENV:VAR_NAME syntax for environment-based secret resolution.
        Literal strings are returned unchanged.

        Args:
            value: Secret value or ENV reference (e.g., "ENV:MY_PASSWORD").
            allow_empty: If False (default), raise error for empty values.

        Returns:
            The resolved secret value.

        Raises:
            SecretError: If environment variable is not set or empty.

        Example:
            # Set environment variable
            os.environ["MY_PASSWORD"] = "secret123"

            # Resolve it
            password = Filanti.resolve_secret("ENV:MY_PASSWORD")
            # Returns: "secret123"

            # Literal values pass through
            literal = Filanti.resolve_secret("direct-password")
            # Returns: "direct-password"
        """
        return resolve_secret(value, allow_empty)

    @staticmethod
    def is_env_reference(value: str) -> bool:
        """Check if a value is an ENV reference.

        Args:
            value: String to check.

        Returns:
            True if value matches ENV:VAR_NAME pattern.

        Example:
            Filanti.is_env_reference("ENV:MY_SECRET")  # True
            Filanti.is_env_reference("my-password")    # False
        """
        return is_env_reference(value)

    @staticmethod
    def redact_secret(text: str, secret: str) -> str:
        """Redact a secret from text output.

        Args:
            text: Text that may contain the secret.
            secret: Secret value to redact.

        Returns:
            Text with secret replaced by [REDACTED].

        Example:
            output = "Password is secret123"
            safe = Filanti.redact_secret(output, "secret123")
            # Returns: "Password is [REDACTED]"
        """
        return redact_secret(text, secret)

    @staticmethod
    def redact_secrets(text: str, secrets: list[str]) -> str:
        """Redact multiple secrets from text output.

        Args:
            text: Text that may contain secrets.
            secrets: List of secret values to redact.

        Returns:
            Text with all secrets replaced by [REDACTED].
        """
        return redact_secrets(text, secrets)

    @staticmethod
    def safe_json_output(
        data: dict,
        secrets: list[str] | None = None,
        secret_keys: list[str] | None = None,
    ) -> dict:
        """Create JSON-safe output with secrets redacted.

        Args:
            data: Dictionary to sanitize.
            secrets: Secret values to redact from string fields.
            secret_keys: Dictionary keys whose values should be redacted.

        Returns:
            Sanitized dictionary safe for logging/output.

        Example:
            data = {"password": "secret123", "message": "Using secret123"}
            safe = Filanti.safe_json_output(
                data,
                secrets=["secret123"],
                secret_keys=["password"]
            )
            # Returns: {"password": "[REDACTED]", "message": "Using [REDACTED]"}
        """
        return create_safe_json_output(data, secrets, secret_keys)

