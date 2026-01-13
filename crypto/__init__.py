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
]
