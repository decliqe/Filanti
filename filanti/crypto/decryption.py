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

        # Parse header
        metadata, ciphertext = parse_encrypted_file(encrypted_data)

        # Create EncryptedData from parsed file
        encrypted = EncryptedData(
            ciphertext=ciphertext,
            nonce=bytes.fromhex(metadata.nonce),
            algorithm=metadata.algorithm,
        )

        # Decrypt
        plaintext = decrypt_bytes(encrypted, key)

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

        # Parse header
        metadata, ciphertext = parse_encrypted_file(encrypted_data)

        # Validate password-based encryption metadata
        if metadata.salt is None or metadata.kdf_algorithm is None:
            raise DecryptionError(
                "File was not encrypted with a password",
                algorithm=metadata.algorithm,
            )

        # Create EncryptedData from parsed file
        encrypted = EncryptedData(
            ciphertext=ciphertext,
            nonce=bytes.fromhex(metadata.nonce),
            algorithm=metadata.algorithm,
            salt=bytes.fromhex(metadata.salt),
            kdf_algorithm=metadata.kdf_algorithm,
            kdf_params=metadata.kdf_params,
        )

        # Decrypt with password
        plaintext = decrypt_bytes_with_password(encrypted, password)

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
    file_manager: FileManager | None = None,
) -> EncryptionMetadata:
    """Get metadata from an encrypted file without decrypting.

    Args:
        input_path: Path to encrypted file.
        file_manager: Optional FileManager instance.

    Returns:
        EncryptionMetadata from the file.

    Raises:
        DecryptionError: If file format is invalid.
        FileOperationError: If file cannot be read.
    """
    fm = file_manager or get_file_manager()

    try:
        # Read enough for header (magic + length + reasonable metadata)
        data = fm.read_bytes(input_path)
        metadata, _ = parse_encrypted_file(data)
        return metadata

    except (DecryptionError, FileOperationError):
        raise
    except Exception as e:
        raise DecryptionError(
            f"Failed to read file metadata: {e}",
            context={"input": str(input_path)},
        ) from e

