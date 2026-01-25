"""Crypto module - Encryption, decryption, and key management."""

from filanti.crypto.encryption import (
    EncryptionAlgorithm,
    EncryptedData,
    EncryptionMetadata,
    encrypt_bytes,
    encrypt_bytes_with_password,
    encrypt_file,
    encrypt_file_with_password,
)
from filanti.crypto.decryption import (
    decrypt_bytes,
    decrypt_bytes_with_password,
    decrypt_file,
    decrypt_file_with_password,
    get_file_metadata,
)
from filanti.crypto.kdf import (
    KDFAlgorithm,
    KDFParams,
    DerivedKey,
    derive_key,
    generate_salt,
)
from filanti.crypto.key_management import (
    generate_key,
    generate_nonce,
    split_key,
    derive_subkey,
)
from filanti.crypto.streaming import (
    encrypt_stream,
    decrypt_stream,
    encrypt_file_streaming,
    decrypt_file_streaming,
    encrypt_file_streaming_with_password,
    decrypt_file_streaming_with_password,
)
from filanti.crypto.asymmetric import (
    AsymmetricAlgorithm,
    AsymmetricKeyPair,
    HybridEncryptedData,
    AsymmetricMetadata,
    EncryptedSessionKey,
    generate_asymmetric_keypair,
    save_asymmetric_keypair,
    load_asymmetric_private_key,
    load_asymmetric_public_key,
    hybrid_encrypt_bytes,
    hybrid_decrypt_bytes,
    hybrid_encrypt_file,
    hybrid_decrypt_file,
    get_hybrid_file_metadata,
    get_supported_asymmetric_algorithms,
)

__all__ = [
    # Encryption
    "EncryptionAlgorithm",
    "EncryptedData",
    "EncryptionMetadata",
    "encrypt_bytes",
    "encrypt_bytes_with_password",
    "encrypt_file",
    "encrypt_file_with_password",
    # Decryption
    "decrypt_bytes",
    "decrypt_bytes_with_password",
    "decrypt_file",
    "decrypt_file_with_password",
    "get_file_metadata",
    # Streaming
    "encrypt_stream",
    "decrypt_stream",
    "encrypt_file_streaming",
    "decrypt_file_streaming",
    "encrypt_file_streaming_with_password",
    "decrypt_file_streaming_with_password",
    # KDF
    "KDFAlgorithm",
    "KDFParams",
    "DerivedKey",
    "derive_key",
    "generate_salt",
    # Key Management
    "generate_key",
    "generate_nonce",
    "split_key",
    "derive_subkey",
    # Asymmetric / Hybrid Encryption
    "AsymmetricAlgorithm",
    "AsymmetricKeyPair",
    "HybridEncryptedData",
    "AsymmetricMetadata",
    "EncryptedSessionKey",
    "generate_asymmetric_keypair",
    "save_asymmetric_keypair",
    "load_asymmetric_private_key",
    "load_asymmetric_public_key",
    "hybrid_encrypt_bytes",
    "hybrid_decrypt_bytes",
    "hybrid_encrypt_file",
    "hybrid_decrypt_file",
    "get_hybrid_file_metadata",
    "get_supported_asymmetric_algorithms",
]
