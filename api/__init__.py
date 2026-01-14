"""
Filanti API/SDK module.

Provides a high-level, unified interface for all Filanti operations.

Example:
    from filanti.api import Filanti

    # Hash a file
    result = Filanti.hash_file("document.pdf")
    print(result.hash)

    # Encrypt with password
    Filanti.encrypt("secret.txt", password="my-password")

    # Sign a file
    keypair = Filanti.generate_keypair()
    Filanti.sign_file("document.pdf", keypair.private_key, create_file=True)
"""

from filanti.api.sdk import (
    Filanti,
    HashResult,
    EncryptResult,
    DecryptResult,
    SignResult,
    VerifyResult,
)

__all__ = [
    "Filanti",
    "HashResult",
    "EncryptResult",
    "DecryptResult",
    "SignResult",
    "VerifyResult",
]

