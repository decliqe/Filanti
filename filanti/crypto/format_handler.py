"""
Format Handler — Serialize / deserialize the Filanti v2 encrypted file format.

V2 format layout
================
::

    [base64-header][2-byte header-len][12-byte meta-nonce]
    [4-byte enc-meta-len][encrypted-metadata][ciphertext-payload]

The metadata block is AES-GCM encrypted with a key derived (HKDF) from
the user's encryption key, so only key holders can inspect metadata.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from filanti.core.errors import DecryptionError
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.cipher_engine import NONCE_SIZE_GCM
from filanti.crypto.encryption import (
    EncryptionMetadata,
    FileHeader,
    PRODUCT_NAME,
)

# We only produce v2 format in Filanti v2.
FORMAT_VERSION: int = 2

# HKDF info label used to derive the metadata-encryption key.
_META_HKDF_INFO: bytes = b"filanti-meta-v2"


@dataclass(frozen=True)
class SerializedFile:
    """Result of ``FormatHandler.serialize``."""

    data: bytes
    metadata: EncryptionMetadata


class FormatHandler:
    """Stateless v2 format serializer / deserializer."""

    # ------------------------------------------------------------------
    # Serialize
    # ------------------------------------------------------------------

    @staticmethod
    def serialize(
        metadata: EncryptionMetadata,
        ciphertext: bytes,
        encryption_key: bytes,
    ) -> bytes:
        """Wrap *ciphertext* + *metadata* into the v2 on-disk format.

        Args:
            metadata: The ``EncryptionMetadata`` describing the payload.
            ciphertext: The AEAD-encrypted payload bytes.
            encryption_key: The user's encryption key (used via HKDF to
                protect metadata).

        Returns:
            The complete v2 file as ``bytes``.
        """
        # 1. Build minimal public header
        header = FileHeader(product=PRODUCT_NAME)
        header_b64: bytes = header.to_base64()

        # 2. Derive metadata-encryption key via HKDF
        meta_nonce = secure_random_bytes(NONCE_SIZE_GCM)
        meta_key = _derive_meta_key(encryption_key, meta_nonce)

        # 3. Encrypt metadata
        meta_plaintext = metadata.to_bytes()
        meta_cipher = AESGCM(meta_key)
        meta_ciphertext: bytes = meta_cipher.encrypt(meta_nonce, meta_plaintext, None)

        # 4. Assemble
        parts: list[bytes] = [
            header_b64,
            len(header_b64).to_bytes(2, "big"),
            meta_nonce,
            len(meta_ciphertext).to_bytes(4, "big"),
            meta_ciphertext,
            ciphertext,
        ]
        return b"".join(parts)

    # ------------------------------------------------------------------
    # Deserialize
    # ------------------------------------------------------------------

    @staticmethod
    def deserialize(
        data: bytes,
        encryption_key: bytes | None = None,
    ) -> tuple[EncryptionMetadata, bytes]:
        """Parse *data* in v2 format → (metadata, ciphertext).

        Args:
            data: Raw file bytes.
            encryption_key: Must be provided in order to decrypt metadata.

        Returns:
            Tuple of ``(EncryptionMetadata, ciphertext_bytes)``.

        Raises:
            DecryptionError: If the format is invalid or metadata
                cannot be decrypted.
        """
        if len(data) < 8:
            raise DecryptionError("Invalid v2 file: too short")

        # --- locate header ---
        header_b64: bytes | None = None
        header_end: int = 0

        for try_len in range(20, 64):
            if try_len + 2 > len(data):
                break
            potential = data[:try_len]
            stored_len = int.from_bytes(data[try_len : try_len + 2], "big")
            if stored_len == try_len:
                try:
                    hdr = FileHeader.from_base64(potential)
                    if hdr.validate():
                        header_b64 = potential
                        header_end = try_len + 2
                        break
                except Exception:
                    continue

        if header_b64 is None:
            raise DecryptionError("Invalid v2 file: cannot locate header")

        offset = header_end

        # --- metadata nonce (12 bytes) ---
        if len(data) < offset + NONCE_SIZE_GCM:
            raise DecryptionError("Invalid v2 file: truncated meta nonce")
        meta_nonce = data[offset : offset + NONCE_SIZE_GCM]
        offset += NONCE_SIZE_GCM

        # --- encrypted metadata length (4 bytes) ---
        if len(data) < offset + 4:
            raise DecryptionError("Invalid v2 file: truncated meta length")
        meta_ct_len = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4

        # Sanity cap — metadata should never be huge
        if meta_ct_len > 1_048_576:
            raise DecryptionError("Invalid v2 file: metadata too large")

        # --- encrypted metadata ---
        if len(data) < offset + meta_ct_len:
            raise DecryptionError("Invalid v2 file: truncated metadata")
        meta_ciphertext = data[offset : offset + meta_ct_len]
        offset += meta_ct_len

        # --- ciphertext payload ---
        ciphertext = data[offset:]

        # --- decrypt metadata ---
        if encryption_key is None:
            raise DecryptionError(
                "Encryption key required to decrypt v2 metadata"
            )

        meta_key = _derive_meta_key(encryption_key, meta_nonce)
        meta_cipher = AESGCM(meta_key)
        try:
            meta_plain = meta_cipher.decrypt(meta_nonce, meta_ciphertext, None)
        except Exception as exc:
            raise DecryptionError(
                f"Failed to decrypt file metadata (wrong key?): {exc}"
            ) from exc

        try:
            metadata = EncryptionMetadata.from_bytes(meta_plain)
        except Exception as exc:
            raise DecryptionError(
                f"Corrupt metadata after decryption: {exc}"
            ) from exc

        return metadata, ciphertext


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _derive_meta_key(encryption_key: bytes, meta_nonce: bytes) -> bytes:
    """HKDF-SHA256 derivation of the metadata-encryption key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=meta_nonce,
        info=_META_HKDF_INFO,
    )
    return hkdf.derive(encryption_key)
