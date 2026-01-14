"""
Streaming encryption and decryption module.

Provides memory-efficient processing of large files using chunked
encryption with AEAD ciphers. Each chunk is independently authenticated
to allow streaming decryption with early failure detection.

Format:
- Each chunk: 4-byte length prefix + nonce + ciphertext (includes auth tag)
- Chunk counter is included in AAD to prevent reordering attacks
"""

import struct
from pathlib import Path
from typing import BinaryIO, Generator, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from filanti.core.errors import EncryptionError, DecryptionError, FileOperationError
from filanti.core.secure_memory import secure_random_bytes
from filanti.crypto.encryption import (
    EncryptionAlgorithm,
    EncryptionMetadata,
    DEFAULT_ALGORITHM,
    FILANTI_MAGIC,
    FORMAT_VERSION,
    _get_cipher,
    _get_nonce_size,
)
from filanti.crypto.kdf import derive_key, KDFParams


# Default chunk size: 64 KB (good balance between memory and performance)
DEFAULT_CHUNK_SIZE = 64 * 1024

# Maximum chunk size: 16 MB (to prevent memory issues)
MAX_CHUNK_SIZE = 16 * 1024 * 1024

# Streaming format version
STREAM_FORMAT_VERSION = 2


def _generate_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """Generate a unique nonce for each chunk.

    Uses XOR of base nonce with chunk index to ensure uniqueness.
    """
    # Convert chunk index to bytes (8 bytes, big-endian)
    index_bytes = chunk_index.to_bytes(8, 'big')

    # XOR with the last 8 bytes of the base nonce
    nonce = bytearray(base_nonce)
    for i in range(min(8, len(nonce))):
        nonce[-(i+1)] ^= index_bytes[-(i+1)]

    return bytes(nonce)


def _chunk_aad(chunk_index: int, is_last: bool) -> bytes:
    """Generate additional authenticated data for a chunk.

    Includes chunk index and last-chunk flag to prevent reordering
    and truncation attacks.
    """
    flags = 1 if is_last else 0
    return struct.pack('>QH', chunk_index, flags)


def encrypt_stream(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    key: bytes,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int], None] | None = None,
) -> EncryptionMetadata:
    """Encrypt a stream using chunked AEAD encryption.

    Each chunk is independently encrypted and authenticated, allowing
    streaming decryption with early failure on tampering.

    Args:
        input_stream: Binary stream to read plaintext from.
        output_stream: Binary stream to write ciphertext to.
        key: Encryption key (32 bytes for AES-256).
        algorithm: Encryption algorithm to use.
        chunk_size: Size of plaintext chunks (default 64KB).
        progress_callback: Optional callback(bytes_processed, total_bytes).

    Returns:
        EncryptionMetadata for the encrypted stream.

    Raises:
        EncryptionError: If encryption fails.
    """
    if chunk_size > MAX_CHUNK_SIZE:
        raise EncryptionError(
            f"Chunk size {chunk_size} exceeds maximum {MAX_CHUNK_SIZE}",
            algorithm=algorithm.value,
        )

    try:
        cipher = _get_cipher(algorithm, key)
        nonce_size = _get_nonce_size(algorithm)

        # Generate base nonce for this encryption
        base_nonce = secure_random_bytes(nonce_size)

        # Write header
        header = _build_stream_header(algorithm, base_nonce, chunk_size)
        output_stream.write(header)

        # Track bytes for progress
        total_bytes = 0
        chunk_index = 0

        while True:
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break

            is_last = len(chunk) < chunk_size

            # Check if this is truly the last chunk
            if not is_last:
                peek = input_stream.read(1)
                if not peek:
                    is_last = True
                else:
                    # Put the byte back by seeking
                    input_stream.seek(-1, 1)

            # Generate unique nonce for this chunk
            chunk_nonce = _generate_chunk_nonce(base_nonce, chunk_index)

            # Create AAD with chunk metadata
            aad = _chunk_aad(chunk_index, is_last)

            # Encrypt chunk
            ciphertext = cipher.encrypt(chunk_nonce, chunk, aad)

            # Write chunk: length (4 bytes) + ciphertext
            chunk_len = len(ciphertext)
            output_stream.write(struct.pack('>I', chunk_len))
            output_stream.write(ciphertext)

            total_bytes += len(chunk)
            chunk_index += 1

            if progress_callback:
                progress_callback(total_bytes, -1)  # -1 = unknown total

        # Write end marker (zero-length chunk)
        output_stream.write(struct.pack('>I', 0))

        return EncryptionMetadata(
            version=STREAM_FORMAT_VERSION,
            algorithm=algorithm.value,
            nonce=base_nonce.hex(),
            original_size=total_bytes,
        )

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(
            f"Stream encryption failed: {e}",
            algorithm=algorithm.value,
        ) from e


def decrypt_stream(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    key: bytes,
    progress_callback: Callable[[int, int], None] | None = None,
) -> int:
    """Decrypt a stream encrypted with encrypt_stream.

    Verifies each chunk's authentication tag, failing early if
    any chunk has been tampered with.

    Args:
        input_stream: Binary stream to read ciphertext from.
        output_stream: Binary stream to write plaintext to.
        key: Decryption key.
        progress_callback: Optional callback(bytes_processed, total_bytes).

    Returns:
        Size of decrypted data in bytes.

    Raises:
        DecryptionError: If decryption or authentication fails.
    """
    try:
        # Read and parse header
        header_info = _parse_stream_header(input_stream)
        algorithm = EncryptionAlgorithm(header_info['algorithm'])
        base_nonce = header_info['nonce']

        cipher = _get_cipher(algorithm, key)

        total_bytes = 0
        chunk_index = 0

        while True:
            # Read chunk length
            len_bytes = input_stream.read(4)
            if len(len_bytes) < 4:
                raise DecryptionError(
                    "Unexpected end of stream: truncated chunk length",
                    algorithm=algorithm.value,
                )

            chunk_len = struct.unpack('>I', len_bytes)[0]

            # Zero length = end marker
            if chunk_len == 0:
                break

            # Read ciphertext
            ciphertext = input_stream.read(chunk_len)
            if len(ciphertext) < chunk_len:
                raise DecryptionError(
                    "Unexpected end of stream: truncated chunk",
                    algorithm=algorithm.value,
                )

            # Check if this is the last chunk (peek ahead)
            peek_len = input_stream.read(4)
            if len(peek_len) == 4:
                next_len = struct.unpack('>I', peek_len)[0]
                is_last = (next_len == 0)
                # Seek back
                input_stream.seek(-4, 1)
            else:
                is_last = True
                input_stream.seek(-len(peek_len), 1)

            # Generate nonce and AAD
            chunk_nonce = _generate_chunk_nonce(base_nonce, chunk_index)
            aad = _chunk_aad(chunk_index, is_last)

            # Decrypt and verify
            try:
                plaintext = cipher.decrypt(chunk_nonce, ciphertext, aad)
            except InvalidTag:
                raise DecryptionError(
                    f"Authentication failed at chunk {chunk_index}: data may be tampered",
                    algorithm=algorithm.value,
                    context={"chunk_index": chunk_index},
                )

            output_stream.write(plaintext)
            total_bytes += len(plaintext)
            chunk_index += 1

            if progress_callback:
                progress_callback(total_bytes, -1)

        return total_bytes

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(
            f"Stream decryption failed: {e}",
        ) from e


def _build_stream_header(
    algorithm: EncryptionAlgorithm,
    base_nonce: bytes,
    chunk_size: int,
) -> bytes:
    """Build streaming encryption header.

    Format:
    - 4 bytes: Magic ("FLNT")
    - 1 byte: Format version
    - 1 byte: Algorithm ID (0=AES-GCM, 1=ChaCha20)
    - 4 bytes: Chunk size
    - 1 byte: Nonce length
    - N bytes: Base nonce
    """
    alg_id = 0 if algorithm == EncryptionAlgorithm.AES_256_GCM else 1

    header = bytearray()
    header.extend(FILANTI_MAGIC)
    header.append(STREAM_FORMAT_VERSION)
    header.append(alg_id)
    header.extend(struct.pack('>I', chunk_size))
    header.append(len(base_nonce))
    header.extend(base_nonce)

    return bytes(header)


def _parse_stream_header(stream: BinaryIO) -> dict:
    """Parse streaming encryption header."""
    magic = stream.read(4)
    if magic != FILANTI_MAGIC:
        raise DecryptionError("Invalid stream header: bad magic bytes")

    version = stream.read(1)[0]
    if version != STREAM_FORMAT_VERSION:
        raise DecryptionError(
            f"Unsupported stream format version: {version}",
            context={"expected": STREAM_FORMAT_VERSION, "actual": version},
        )

    alg_id = stream.read(1)[0]
    algorithm = "aes-256-gcm" if alg_id == 0 else "chacha20-poly1305"

    chunk_size = struct.unpack('>I', stream.read(4))[0]
    nonce_len = stream.read(1)[0]
    nonce = stream.read(nonce_len)

    return {
        'version': version,
        'algorithm': algorithm,
        'chunk_size': chunk_size,
        'nonce': nonce,
    }


def encrypt_file_streaming(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Callable[[int, int], None] | None = None,
) -> EncryptionMetadata:
    """Encrypt a file using streaming chunked encryption.

    Memory-efficient for large files - only one chunk is held in memory.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        key: Encryption key.
        algorithm: Encryption algorithm.
        chunk_size: Size of plaintext chunks.
        progress_callback: Optional progress callback.

    Returns:
        EncryptionMetadata for the encrypted file.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileOperationError(
            f"Input file not found: {input_path}",
            path=str(input_path),
            operation="encrypt_streaming",
        )

    total_size = input_path.stat().st_size

    def progress_wrapper(processed: int, _: int) -> None:
        if progress_callback:
            progress_callback(processed, total_size)

    try:
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            return encrypt_stream(
                infile, outfile, key, algorithm, chunk_size, progress_wrapper
            )
    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to encrypt file: {e}",
            path=str(input_path),
            operation="encrypt_streaming",
        ) from e


def decrypt_file_streaming(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    progress_callback: Callable[[int, int], None] | None = None,
) -> int:
    """Decrypt a file encrypted with streaming encryption.

    Memory-efficient - processes one chunk at a time.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        key: Decryption key.
        progress_callback: Optional progress callback.

    Returns:
        Size of decrypted data in bytes.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileOperationError(
            f"Input file not found: {input_path}",
            path=str(input_path),
            operation="decrypt_streaming",
        )

    try:
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            return decrypt_stream(infile, outfile, key, progress_callback)
    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to decrypt file: {e}",
            path=str(input_path),
            operation="decrypt_streaming",
        ) from e


def encrypt_file_streaming_with_password(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
    algorithm: EncryptionAlgorithm = DEFAULT_ALGORITHM,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    kdf_params: KDFParams | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> EncryptionMetadata:
    """Encrypt a file with password using streaming encryption.

    Combines password-based key derivation with streaming encryption
    for memory-efficient processing of large files.

    Args:
        input_path: Path to file to encrypt.
        output_path: Path for encrypted output.
        password: Encryption password.
        algorithm: Encryption algorithm.
        chunk_size: Size of plaintext chunks.
        kdf_params: Optional KDF parameters.
        progress_callback: Optional progress callback.

    Returns:
        EncryptionMetadata including KDF parameters.
    """
    # Derive key from password
    derived = derive_key(password, params=kdf_params)

    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileOperationError(
            f"Input file not found: {input_path}",
            path=str(input_path),
            operation="encrypt_streaming",
        )

    total_size = input_path.stat().st_size

    def progress_wrapper(processed: int, _: int) -> None:
        if progress_callback:
            progress_callback(processed, total_size)

    try:
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Write KDF metadata first
            kdf_header = _build_kdf_header(derived)
            outfile.write(kdf_header)

            # Then encrypt stream
            metadata = encrypt_stream(
                infile, outfile, derived.key, algorithm, chunk_size, progress_wrapper
            )

            # Update metadata with KDF info
            metadata.salt = derived.salt.hex()
            metadata.kdf_algorithm = derived.algorithm
            metadata.kdf_params = derived.params

            return metadata

    except (EncryptionError, FileOperationError):
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to encrypt file: {e}",
            path=str(input_path),
            operation="encrypt_streaming",
        ) from e


def decrypt_file_streaming_with_password(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> int:
    """Decrypt a file encrypted with password and streaming encryption.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        password: Decryption password.
        progress_callback: Optional progress callback.

    Returns:
        Size of decrypted data in bytes.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileOperationError(
            f"Input file not found: {input_path}",
            path=str(input_path),
            operation="decrypt_streaming",
        )

    try:
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            # Read and parse KDF header
            kdf_info = _parse_kdf_header(infile)

            # Derive key
            from filanti.crypto.kdf import derive_key_with_salt
            key = derive_key_with_salt(
                password,
                kdf_info['salt'],
                kdf_info['algorithm'],
                kdf_info['params'],
            )

            # Decrypt stream
            return decrypt_stream(infile, outfile, key, progress_callback)

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise FileOperationError(
            f"Failed to decrypt file: {e}",
            path=str(input_path),
            operation="decrypt_streaming",
        ) from e


def _build_kdf_header(derived) -> bytes:
    """Build KDF metadata header for password-based streaming encryption."""
    import json

    kdf_data = {
        'algorithm': derived.algorithm,
        'params': derived.params,
        'salt': derived.salt.hex(),
    }
    kdf_json = json.dumps(kdf_data, separators=(',', ':')).encode('utf-8')

    # Header: 4 bytes length + JSON
    return struct.pack('>I', len(kdf_json)) + kdf_json


def _parse_kdf_header(stream: BinaryIO) -> dict:
    """Parse KDF metadata header."""
    import json

    len_bytes = stream.read(4)
    if len(len_bytes) < 4:
        raise DecryptionError("Invalid KDF header: truncated length")

    kdf_len = struct.unpack('>I', len_bytes)[0]
    kdf_json = stream.read(kdf_len)

    if len(kdf_json) < kdf_len:
        raise DecryptionError("Invalid KDF header: truncated data")

    try:
        kdf_data = json.loads(kdf_json.decode('utf-8'))
        kdf_data['salt'] = bytes.fromhex(kdf_data['salt'])
        return kdf_data
    except Exception as e:
        raise DecryptionError(f"Invalid KDF header: {e}") from e

