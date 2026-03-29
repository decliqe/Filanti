"""
Cipher Engine — Pure cryptographic operations.

No file I/O, no metadata, no format logic.  Just encrypt / decrypt
raw bytes with a given AEAD cipher, key, nonce and optional AAD.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from filanti.core.errors import DecryptionError, EncryptionError
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.encryption import EncryptionAlgorithm

# Nonce sizes (in bytes)
NONCE_SIZE_GCM: int = 12
NONCE_SIZE_CHACHA: int = 12


def _make_cipher(
    algorithm: EncryptionAlgorithm,
    key: bytes,
) -> AESGCM | ChaCha20Poly1305:
    """Instantiate the correct AEAD cipher."""
    if algorithm is EncryptionAlgorithm.AES_256_GCM:
        return AESGCM(key)
    if algorithm is EncryptionAlgorithm.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    raise EncryptionError(
        f"Unsupported algorithm: {algorithm}",
        algorithm=str(algorithm),
    )


def nonce_size_for(algorithm: EncryptionAlgorithm) -> int:
    """Return the nonce byte-length for *algorithm*."""
    if algorithm is EncryptionAlgorithm.CHACHA20_POLY1305:
        return NONCE_SIZE_CHACHA
    return NONCE_SIZE_GCM


class CipherEngine:
    """Stateless, pure-crypto AEAD engine.

    >>> engine = CipherEngine(EncryptionAlgorithm.AES_256_GCM)
    >>> ct, nonce = engine.encrypt(key, plaintext)
    >>> pt = engine.decrypt(key, ct, nonce)
    """

    __slots__ = ("_algorithm",)

    def __init__(self, algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM) -> None:
        self._algorithm = algorithm

    @property
    def algorithm(self) -> EncryptionAlgorithm:
        return self._algorithm

    @property
    def nonce_size(self) -> int:
        return nonce_size_for(self._algorithm)

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def encrypt(
        self,
        key: bytes,
        data: bytes,
        aad: bytes | None = None,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt *data* → (ciphertext, nonce).

        If *nonce* is ``None`` a fresh random nonce is generated.

        Raises:
            EncryptionError: on any crypto failure.
        """
        try:
            if nonce is None:
                nonce = secure_random_bytes(self.nonce_size)
            cipher = _make_cipher(self._algorithm, key)
            ciphertext: bytes = cipher.encrypt(nonce, data, aad)
            return ciphertext, nonce
        except EncryptionError:
            raise
        except Exception as exc:
            raise EncryptionError(
                f"Encryption failed: {exc}",
                algorithm=self._algorithm.value,
            ) from exc

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def decrypt(
        self,
        key: bytes,
        data: bytes,
        nonce: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        """Decrypt *data* and verify its authentication tag.

        Raises:
            DecryptionError: on authentication failure or crypto error.
        """
        try:
            cipher = _make_cipher(self._algorithm, key)
            plaintext: bytes = cipher.decrypt(nonce, data, aad)
            return plaintext
        except InvalidTag:
            raise DecryptionError(
                "Authentication failed: data may be tampered or wrong key",
                algorithm=self._algorithm.value,
            )
        except Exception as exc:
            if isinstance(exc, DecryptionError):
                raise
            raise DecryptionError(
                f"Decryption failed: {exc}",
                algorithm=self._algorithm.value,
            ) from exc
