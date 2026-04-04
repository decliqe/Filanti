"""
Decryption module.

Provides authenticated decryption for data encrypted with Filanti.
All decryption operations verify the authentication tag to ensure integrity.
"""

from pathlib import Path

from cryptography.exceptions import InvalidTag

from filanti.core.errors import DecryptionError, FileOperationError
from filanti.core.file_manager import FileManager, get_file_manager
from filanti.crypto.encryption import (
    EncryptionAlgorithm,
    EncryptedData,
    EncryptionMetadata,
    parse_encrypted_file,
    extract_kdf_block,
    _get_cipher,
)
from filanti.crypto.kdf import derive_key_with_salt


def decrypt_bytes(
    encrypted: EncryptedData,
    key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt bytes using authenticated decryption.

    Args:
        encrypted: EncryptedData containing ciphertext and metadata.
        key: Decryption key.
        associated_data: Optional additional authenticated data (AAD).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        DecryptionError: If decryption fails or authentication fails.
    """
    try:
        algorithm = EncryptionAlgorithm(encrypted.algorithm)
        cipher = _get_cipher(algorithm, key)

        plaintext = cipher.decrypt(
            encrypted.nonce,
            encrypted.ciphertext,
            associated_data,
        )

        return plaintext

    except InvalidTag:
        raise DecryptionError(
            "Authentication failed: data may be tampered or wrong key",
            algorithm=encrypted.algorithm,
        )
    except ValueError as e:
        raise DecryptionError(
            f"Decryption failed: {e}",
            algorithm=encrypted.algorithm,
        ) from e
    except Exception as e:
        if isinstance(e, DecryptionError):
            raise
        raise DecryptionError(
            f"Decryption failed: {e}",
            algorithm=encrypted.algorithm,
        ) from e


def decrypt_bytes_with_password(
    encrypted: EncryptedData,
    password: str,
    associated_data: bytes | None = None,
) -> bytes:
    """Decrypt bytes using a password.

    Derives the decryption key from the password using stored KDF parameters.

    Args:
        encrypted: EncryptedData containing ciphertext and KDF parameters.
        password: Password for decryption.
        associated_data: Optional additional authenticated data.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        DecryptionError: If decryption fails.
    """
    if encrypted.salt is None or encrypted.kdf_algorithm is None:
        raise DecryptionError(
            "Missing KDF parameters for password decryption",
            algorithm=encrypted.algorithm,
        )

    if encrypted.kdf_params is None:
        raise DecryptionError(
            "Missing KDF parameters for password decryption",
            algorithm=encrypted.algorithm,
        )

    try:
        # Derive key using stored parameters
        key = derive_key_with_salt(
            password=password,
            salt=encrypted.salt,
            algorithm=encrypted.kdf_algorithm,
            params=encrypted.kdf_params,
        )

        return decrypt_bytes(encrypted, key, associated_data)

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(
            f"Password decryption failed: {e}",
            algorithm=encrypted.algorithm,
        ) from e


def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    file_manager: FileManager | None = None,
) -> int:
    """Decrypt a file.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        key: Decryption key.
        file_manager: Optional FileManager instance.

    Returns:
        Size of decrypted data in bytes.

    Raises:
        DecryptionError: If decryption fails.
        FileOperationError: If file operations fail.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read encrypted file
        encrypted_data = fm.read_bytes(input_path)

        # Parse header (pass key for v2 metadata decryption)
        metadata, ciphertext = parse_encrypted_file(encrypted_data, encryption_key=key)

        # Create EncryptedData from parsed file
        encrypted = EncryptedData(
            ciphertext=ciphertext,
            nonce=bytes.fromhex(metadata.nonce),
            algorithm=metadata.algorithm,
        )

        # Reconstruct AAD from stable metadata fields (MED-05 binding)
        from filanti.crypto.encryption import _build_file_aad
        metadata_aad = _build_file_aad(
            metadata.version, metadata.algorithm, metadata.original_size,
        )

        # Decrypt with AAD
        plaintext = decrypt_bytes(encrypted, key, associated_data=metadata_aad)

        # Write output
        fm.write_bytes(output_path, plaintext)

        return len(plaintext)

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise DecryptionError(
            f"File decryption failed: {e}",
            context={"input": str(input_path)},
        ) from e


def decrypt_file_with_password(
    input_path: str | Path,
    output_path: str | Path,
    password: str,
    file_manager: FileManager | None = None,
) -> int:
    """Decrypt a file using a password.

    Supports v2.1 format only (KDF block + encrypted metadata).
    Legacy v1 format is no longer supported.

    Args:
        input_path: Path to encrypted file.
        output_path: Path for decrypted output.
        password: Password for decryption.
        file_manager: Optional FileManager instance.

    Returns:
        Size of decrypted data in bytes.

    Raises:
        DecryptionError: If decryption fails.
        FileOperationError: If file operations fail.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read encrypted file
        encrypted_data = fm.read_bytes(input_path)

        # Extract v2.1 KDF block (lightweight, no metadata decryption)
        kdf_info = extract_kdf_block(encrypted_data)

        if kdf_info is None:
            raise DecryptionError(
                "Unsupported file format: missing KDF block. "
                "This file may be in a legacy v1 format that is no longer supported.",
            )

        # Derive key from KDF block parameters
        salt = kdf_info.get("s")
        kdf_algorithm = kdf_info.get("a")
        kdf_params = kdf_info.get("p")

        if salt is None or kdf_algorithm is None:
            raise DecryptionError(
                "Invalid v2.1 KDF block: missing salt or algorithm",
            )

        # Salt is raw bytes from binary KDF block
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)

        key = derive_key_with_salt(
            password=password,
            salt=salt,
            algorithm=kdf_algorithm,
            params=kdf_params,
        )

        # Parse with key to decrypt metadata
        metadata, ciphertext = parse_encrypted_file(encrypted_data, encryption_key=key)

        # Reconstruct AAD (v2.1 uses AAD binding)
        from filanti.crypto.encryption import _build_file_aad
        metadata_aad = _build_file_aad(
            metadata.version, metadata.algorithm, metadata.original_size,
        )

        # Create EncryptedData and decrypt with AAD
        encrypted = EncryptedData(
            ciphertext=ciphertext,
            nonce=bytes.fromhex(metadata.nonce),
            algorithm=metadata.algorithm,
        )

        plaintext = decrypt_bytes(encrypted, key, associated_data=metadata_aad)

        # Write output
        fm.write_bytes(output_path, plaintext)

        return len(plaintext)

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise DecryptionError(
            f"File decryption failed: {e}",
            context={"input": str(input_path)},
        ) from e


def get_file_metadata(
    input_path: str | Path,
    encryption_key: bytes | None = None,
    file_manager: FileManager | None = None,
) -> EncryptionMetadata:
    """Get metadata from an encrypted file without decrypting content.

    An encryption key is required to decrypt the metadata.

    Args:
        input_path: Path to encrypted file.
        encryption_key: Key for decrypting metadata (required).
        file_manager: Optional FileManager instance.

    Returns:
        EncryptionMetadata from the file.

    Raises:
        DecryptionError: If file format is invalid or key is missing.
        FileOperationError: If file cannot be read.
    """
    fm = file_manager or get_file_manager()

    try:
        data = fm.read_bytes(input_path)
        metadata, _ = parse_encrypted_file(data, encryption_key=encryption_key)
        return metadata

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise DecryptionError(
            f"Failed to read file metadata: {e}",
            context={"input": str(input_path)},
        ) from e

