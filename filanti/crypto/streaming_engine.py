"""
Streaming Engine — Memory-efficient chunked AEAD encryption / decryption.

ALL file encryption/decryption in Filanti v2 MUST go through this engine
so that no file is ever fully loaded into memory.

Each chunk is independently authenticated (nonce = base⊕counter, AAD
includes chunk index + last-flag) to prevent reordering and truncation.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO, Callable


from filanti.core.errors import DecryptionError, EncryptionError, FileOperationError
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.cipher_engine import CipherEngine, nonce_size_for
from filanti.crypto.encryption import EncryptionAlgorithm, EncryptionMetadata

# Defaults
DEFAULT_CHUNK_SIZE: int = 64 * 1024       # 64 KiB
MAX_CHUNK_SIZE: int = 16 * 1024 * 1024    # 16 MiB

# Magic for the streaming sub-format header
_MAGIC: bytes = b"FLNT"
_STREAM_VERSION: int = 2

ProgressCallback = Callable[[int, int], None] | None


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


class StreamingEngine:
    """Process binary streams in fixed-size AEAD-encrypted chunks.

    >>> engine = StreamingEngine(cipher)
    >>> engine.process_encrypt(in_stream, out_stream, key)
    """

    __slots__ = ("_cipher",)

    def __init__(self, cipher: CipherEngine) -> None:
        self._cipher = cipher

    @property
    def algorithm(self) -> EncryptionAlgorithm:
        return self._cipher.algorithm

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def process_encrypt(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        key: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        progress: ProgressCallback = None,
    ) -> EncryptionMetadata:
        """Encrypt *input_stream* → *output_stream* in chunks.

        Returns:
            EncryptionMetadata describing the encrypted content.
        """
        if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
            raise EncryptionError(
                f"chunk_size must be 1..{MAX_CHUNK_SIZE}, got {chunk_size}",
                algorithm=self.algorithm.value,
            )

        nonce_len = nonce_size_for(self.algorithm)
        base_nonce = secure_random_bytes(nonce_len)

        # Write stream header
        output_stream.write(
            _build_header(self.algorithm, base_nonce, chunk_size),
        )

        total: int = 0
        idx: int = 0

        while True:
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break

            # Detect last chunk
            is_last = len(chunk) < chunk_size
            if not is_last:
                peek = input_stream.read(1)
                if not peek:
                    is_last = True
                else:
                    input_stream.seek(-1, 1)

            nonce = _derive_chunk_nonce(base_nonce, idx)
            aad = _chunk_aad(idx, is_last)
            ct, _ = self._cipher.encrypt(key, chunk, aad=aad, nonce=nonce)

            output_stream.write(struct.pack(">I", len(ct)))
            output_stream.write(ct)

            total += len(chunk)
            idx += 1

            if progress is not None:
                progress(total, -1)

        # End-of-stream marker
        output_stream.write(struct.pack(">I", 0))

        return EncryptionMetadata(
            version=_STREAM_VERSION,
            algorithm=self.algorithm.value,
            nonce=base_nonce.hex(),
            original_size=total,
        )

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def process_decrypt(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        key: bytes,
        progress: ProgressCallback = None,
    ) -> int:
        """Decrypt *input_stream* → *output_stream*.

        Returns the total plaintext byte count.
        """
        hdr = _parse_header(input_stream)
        algorithm = EncryptionAlgorithm(hdr["algorithm"])

        # We trust the header's algorithm — it was written by us
        cipher = CipherEngine(algorithm)
        base_nonce = bytes(hdr["nonce"])  # type: ignore[arg-type]

        total: int = 0
        idx: int = 0

        while True:
            raw_len = input_stream.read(4)
            if len(raw_len) < 4:
                raise DecryptionError(
                    "Truncated chunk length", algorithm=algorithm.value,
                )
            ct_len = struct.unpack(">I", raw_len)[0]
            if ct_len == 0:
                break

            ct = input_stream.read(ct_len)
            if len(ct) < ct_len:
                raise DecryptionError(
                    "Truncated chunk data", algorithm=algorithm.value,
                )

            # Peek to determine is_last
            peek = input_stream.read(4)
            if len(peek) == 4:
                is_last = struct.unpack(">I", peek)[0] == 0
                input_stream.seek(-4, 1)
            else:
                is_last = True
                if peek:
                    input_stream.seek(-len(peek), 1)

            nonce = _derive_chunk_nonce(base_nonce, idx)
            aad = _chunk_aad(idx, is_last)

            try:
                pt = cipher.decrypt(key, ct, nonce, aad=aad)
            except DecryptionError:
                raise DecryptionError(
                    f"Authentication failed at chunk {idx}",
                    algorithm=algorithm.value,
                )

            output_stream.write(pt)
            total += len(pt)
            idx += 1

            if progress is not None:
                progress(total, -1)

        return total


# ------------------------------------------------------------------
# File convenience wrappers
# ------------------------------------------------------------------


def streaming_encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: ProgressCallback = None,
) -> EncryptionMetadata:
    """Encrypt a file with streaming — the v2 default."""
    inp = Path(input_path)
    if not inp.exists():
        raise FileOperationError(f"Not found: {inp}", path=str(inp), operation="encrypt")

    engine = StreamingEngine(CipherEngine(algorithm))
    with open(inp, "rb") as fin, open(Path(output_path), "wb") as fout:
        return engine.process_encrypt(fin, fout, key, chunk_size, progress)


def streaming_decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    progress: ProgressCallback = None,
) -> int:
    """Decrypt a streaming-format file."""
    inp = Path(input_path)
    if not inp.exists():
        raise FileOperationError(f"Not found: {inp}", path=str(inp), operation="decrypt")

    # Algorithm is discovered from the stream header
    engine = StreamingEngine(CipherEngine())  # dummy; overridden inside
    with open(inp, "rb") as fin, open(Path(output_path), "wb") as fout:
        return engine.process_decrypt(fin, fout, key, progress)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _derive_chunk_nonce(base: bytes, index: int) -> bytes:
    """XOR chunk counter into the tail of the base nonce."""
    idx_bytes = index.to_bytes(8, "big")
    buf = bytearray(base)
    for i in range(min(8, len(buf))):
        buf[-(i + 1)] ^= idx_bytes[-(i + 1)]
    return bytes(buf)


def _chunk_aad(index: int, is_last: bool) -> bytes:
    """AAD = 8-byte big-endian chunk index ‖ 2-byte last flag."""
    return struct.pack(">QH", index, 1 if is_last else 0)


def _build_header(
    algorithm: EncryptionAlgorithm,
    base_nonce: bytes,
    chunk_size: int,
) -> bytes:
    hdr = bytearray(_MAGIC)
    hdr.append(_STREAM_VERSION)
    hdr.append(0 if algorithm is EncryptionAlgorithm.AES_256_GCM else 1)
    hdr.extend(struct.pack(">I", chunk_size))
    hdr.append(len(base_nonce))
    hdr.extend(base_nonce)
    return bytes(hdr)


def _parse_header(stream: BinaryIO) -> dict[str, object]:
    magic = stream.read(4)
    if magic != _MAGIC:
        raise DecryptionError("Bad stream magic bytes")
    version = stream.read(1)[0]
    if version != _STREAM_VERSION:
        raise DecryptionError(f"Unsupported stream version: {version}")
    alg_id = stream.read(1)[0]
    alg = "aes-256-gcm" if alg_id == 0 else "chacha20-poly1305"
    chunk_size = struct.unpack(">I", stream.read(4))[0]
    nonce_len = stream.read(1)[0]
    nonce = stream.read(nonce_len)
    return {
        "version": version,
        "algorithm": alg,
        "chunk_size": chunk_size,
        "nonce": nonce,
    }
