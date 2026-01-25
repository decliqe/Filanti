"""
Plugin architecture for extensible algorithm support.

Allows registration of custom algorithms for hashing, encryption,
MAC, signatures, and checksums without modifying core code.

Example:
    from filanti.core.plugins import PluginRegistry, HashPlugin

    class MyHashPlugin(HashPlugin):
        name = "my-hash"

        def hash(self, data: bytes) -> bytes:
            # Custom implementation
            return my_hash_function(data)

    PluginRegistry.register_hash(MyHashPlugin())
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Type


class Plugin(ABC):
    """Base class for all plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this plugin."""
        pass

    @property
    def description(self) -> str:
        """Human-readable description."""
        return f"{self.name} plugin"

    @property
    def version(self) -> str:
        """Plugin version."""
        return "1.0.0"


class HashPlugin(Plugin):
    """Plugin interface for hash algorithms."""

    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Size of hash output in bytes."""
        pass

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """Compute hash of data.

        Args:
            data: Data to hash.

        Returns:
            Hash digest as bytes.
        """
        pass

    def hash_hex(self, data: bytes) -> str:
        """Compute hash and return as hex string."""
        return self.hash(data).hex()

    def create_hasher(self) -> "StreamingHasher":
        """Create a streaming hasher for incremental hashing.

        Override this for streaming support.
        """
        raise NotImplementedError(f"{self.name} does not support streaming")


class StreamingHasher(ABC):
    """Interface for incremental/streaming hash computation."""

    @abstractmethod
    def update(self, data: bytes) -> None:
        """Add data to the hash."""
        pass

    @abstractmethod
    def finalize(self) -> bytes:
        """Finalize and return the hash digest."""
        pass

    def hexdigest(self) -> str:
        """Finalize and return hex-encoded digest."""
        return self.finalize().hex()


class EncryptionPlugin(Plugin):
    """Plugin interface for encryption algorithms."""

    @property
    @abstractmethod
    def key_size(self) -> int:
        """Required key size in bytes."""
        pass

    @property
    @abstractmethod
    def nonce_size(self) -> int:
        """Required nonce/IV size in bytes."""
        pass

    @property
    @abstractmethod
    def tag_size(self) -> int:
        """Authentication tag size in bytes (0 for non-AEAD)."""
        pass

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Encrypt data.

        Args:
            plaintext: Data to encrypt.
            key: Encryption key.
            nonce: Nonce/IV.
            associated_data: Optional AAD for AEAD ciphers.

        Returns:
            Ciphertext (may include auth tag for AEAD).
        """
        pass

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt data.

        Args:
            ciphertext: Data to decrypt.
            key: Decryption key.
            nonce: Nonce/IV.
            associated_data: Optional AAD for AEAD ciphers.

        Returns:
            Plaintext.

        Raises:
            Exception: If decryption or authentication fails.
        """
        pass


class MACPlugin(Plugin):
    """Plugin interface for MAC algorithms."""

    @property
    @abstractmethod
    def tag_size(self) -> int:
        """MAC tag size in bytes."""
        pass

    @abstractmethod
    def compute(self, data: bytes, key: bytes) -> bytes:
        """Compute MAC of data.

        Args:
            data: Data to authenticate.
            key: Secret key.

        Returns:
            MAC tag as bytes.
        """
        pass

    @abstractmethod
    def verify(self, data: bytes, tag: bytes, key: bytes) -> bool:
        """Verify MAC of data.

        Args:
            data: Data to verify.
            tag: Expected MAC tag.
            key: Secret key.

        Returns:
            True if MAC is valid.
        """
        pass


class SignaturePlugin(Plugin):
    """Plugin interface for signature algorithms."""

    @abstractmethod
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a new key pair.

        Returns:
            Tuple of (private_key, public_key) as bytes.
        """
        pass

    @abstractmethod
    def sign(self, data: bytes, private_key: bytes) -> bytes:
        """Sign data.

        Args:
            data: Data to sign.
            private_key: Private key bytes.

        Returns:
            Signature bytes.
        """
        pass

    @abstractmethod
    def verify(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature.

        Args:
            data: Original data.
            signature: Signature to verify.
            public_key: Public key bytes.

        Returns:
            True if signature is valid.
        """
        pass


class ChecksumPlugin(Plugin):
    """Plugin interface for checksum algorithms."""

    @property
    @abstractmethod
    def size(self) -> int:
        """Checksum size in bits."""
        pass

    @abstractmethod
    def compute(self, data: bytes) -> int:
        """Compute checksum of data.

        Args:
            data: Data to checksum.

        Returns:
            Checksum as integer.
        """
        pass

    def compute_hex(self, data: bytes) -> str:
        """Compute checksum and return as hex string."""
        size_bytes = (self.size + 7) // 8
        return f"{self.compute(data):0{size_bytes * 2}x}"


class KDFPlugin(Plugin):
    """Plugin interface for key derivation functions."""

    @abstractmethod
    def derive(
        self,
        password: bytes,
        salt: bytes,
        key_length: int,
        **params,
    ) -> bytes:
        """Derive key from password.

        Args:
            password: Password bytes.
            salt: Salt bytes.
            key_length: Desired key length.
            **params: Algorithm-specific parameters.

        Returns:
            Derived key bytes.
        """
        pass

    @property
    def default_params(self) -> dict:
        """Default parameters for this KDF."""
        return {}


@dataclass
class PluginRegistry:
    """Central registry for all plugins.

    Thread-safe singleton pattern for global plugin access.
    """

    _instance: "PluginRegistry | None" = field(default=None, init=False, repr=False)

    hash_plugins: dict[str, HashPlugin] = field(default_factory=dict)
    encryption_plugins: dict[str, EncryptionPlugin] = field(default_factory=dict)
    mac_plugins: dict[str, MACPlugin] = field(default_factory=dict)
    signature_plugins: dict[str, SignaturePlugin] = field(default_factory=dict)
    checksum_plugins: dict[str, ChecksumPlugin] = field(default_factory=dict)
    kdf_plugins: dict[str, KDFPlugin] = field(default_factory=dict)

    @classmethod
    def get_instance(cls) -> "PluginRegistry":
        """Get the singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def register_hash(cls, plugin: HashPlugin) -> None:
        """Register a hash plugin."""
        cls.get_instance().hash_plugins[plugin.name] = plugin

    @classmethod
    def register_encryption(cls, plugin: EncryptionPlugin) -> None:
        """Register an encryption plugin."""
        cls.get_instance().encryption_plugins[plugin.name] = plugin

    @classmethod
    def register_mac(cls, plugin: MACPlugin) -> None:
        """Register a MAC plugin."""
        cls.get_instance().mac_plugins[plugin.name] = plugin

    @classmethod
    def register_signature(cls, plugin: SignaturePlugin) -> None:
        """Register a signature plugin."""
        cls.get_instance().signature_plugins[plugin.name] = plugin

    @classmethod
    def register_checksum(cls, plugin: ChecksumPlugin) -> None:
        """Register a checksum plugin."""
        cls.get_instance().checksum_plugins[plugin.name] = plugin

    @classmethod
    def register_kdf(cls, plugin: KDFPlugin) -> None:
        """Register a KDF plugin."""
        cls.get_instance().kdf_plugins[plugin.name] = plugin

    @classmethod
    def get_hash(cls, name: str) -> HashPlugin | None:
        """Get a hash plugin by name."""
        return cls.get_instance().hash_plugins.get(name)

    @classmethod
    def get_encryption(cls, name: str) -> EncryptionPlugin | None:
        """Get an encryption plugin by name."""
        return cls.get_instance().encryption_plugins.get(name)

    @classmethod
    def get_mac(cls, name: str) -> MACPlugin | None:
        """Get a MAC plugin by name."""
        return cls.get_instance().mac_plugins.get(name)

    @classmethod
    def get_signature(cls, name: str) -> SignaturePlugin | None:
        """Get a signature plugin by name."""
        return cls.get_instance().signature_plugins.get(name)

    @classmethod
    def get_checksum(cls, name: str) -> ChecksumPlugin | None:
        """Get a checksum plugin by name."""
        return cls.get_instance().checksum_plugins.get(name)

    @classmethod
    def get_kdf(cls, name: str) -> KDFPlugin | None:
        """Get a KDF plugin by name."""
        return cls.get_instance().kdf_plugins.get(name)

    @classmethod
    def list_plugins(cls) -> dict[str, list[str]]:
        """List all registered plugins."""
        instance = cls.get_instance()
        return {
            "hash": list(instance.hash_plugins.keys()),
            "encryption": list(instance.encryption_plugins.keys()),
            "mac": list(instance.mac_plugins.keys()),
            "signature": list(instance.signature_plugins.keys()),
            "checksum": list(instance.checksum_plugins.keys()),
            "kdf": list(instance.kdf_plugins.keys()),
        }

    @classmethod
    def reset(cls) -> None:
        """Reset the registry (mainly for testing)."""
        cls._instance = None


def plugin(category: str) -> Callable[[Type[Plugin]], Type[Plugin]]:
    """Decorator for automatic plugin registration.

    Example:
        @plugin("hash")
        class MyHashPlugin(HashPlugin):
            name = "my-hash"
            ...

    Args:
        category: Plugin category (hash, encryption, mac, signature, checksum, kdf).

    Returns:
        Decorator function.
    """
    def decorator(cls: Type[Plugin]) -> Type[Plugin]:
        instance = cls()

        if category == "hash":
            PluginRegistry.register_hash(instance)
        elif category == "encryption":
            PluginRegistry.register_encryption(instance)
        elif category == "mac":
            PluginRegistry.register_mac(instance)
        elif category == "signature":
            PluginRegistry.register_signature(instance)
        elif category == "checksum":
            PluginRegistry.register_checksum(instance)
        elif category == "kdf":
            PluginRegistry.register_kdf(instance)
        else:
            raise ValueError(f"Unknown plugin category: {category}")

        return cls

    return decorator

