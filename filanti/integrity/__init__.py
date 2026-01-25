"""
Integrity module.

Provides integrity verification and authenticity validation:
- MAC (HMAC-based message authentication)
- Digital signatures (Ed25519, ECDSA)
- Checksums (CRC32, Adler32, XXHash64)
- Detached metadata support for all operations
"""

from filanti.integrity.checksum import (
    ChecksumAlgorithm,
    ChecksumResult,
    ChecksumMetadata,
    compute_checksum,
    verify_checksum,
    compute_checksum_stream,
    compute_file_checksum,
    verify_file_checksum,
    create_checksum_file,
    verify_checksum_file,
    generate_checksum_line,
    parse_checksum_line,
)

from filanti.integrity.mac import (
    MACAlgorithm,
    MACResult,
    IntegrityMetadata,
    compute_mac,
    verify_mac,
    compute_mac_stream,
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
    sign_stream,
    verify_stream_signature,
    sign_file,
    verify_file_signature,
    create_signature_file,
    verify_signature_file,
)

__all__ = [
    # Checksum
    "ChecksumAlgorithm",
    "ChecksumResult",
    "ChecksumMetadata",
    "compute_checksum",
    "verify_checksum",
    "compute_checksum_stream",
    "compute_file_checksum",
    "verify_file_checksum",
    "create_checksum_file",
    "verify_checksum_file",
    "generate_checksum_line",
    "parse_checksum_line",
    # MAC
    "MACAlgorithm",
    "MACResult",
    "IntegrityMetadata",
    "compute_mac",
    "verify_mac",
    "compute_mac_stream",
    "compute_file_mac",
    "verify_file_mac",
    "create_integrity_file",
    "verify_integrity_file",
    # Signature
    "SignatureAlgorithm",
    "KeyPair",
    "SignatureResult",
    "SignatureMetadata",
    "generate_keypair",
    "save_keypair",
    "load_private_key",
    "load_public_key",
    "sign_bytes",
    "verify_signature",
    "sign_stream",
    "verify_stream_signature",
    "sign_file",
    "verify_file_signature",
    "create_signature_file",
    "verify_signature_file",
]

