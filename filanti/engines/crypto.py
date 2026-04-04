"""
Crypto Engine — High-level encrypt/decrypt operations via the engine interface.

Wraps the existing CipherEngine, StreamingEngine, and FormatHandler,
routing through the BaseEngine.execute() API.

Password-based encryption/decryption uses the v2.1 file format
(``encrypt_file_with_password`` / ``decrypt_file_with_password``)
which embeds KDF parameters and encrypted metadata in the file for portability.

Raw-key operations use the streaming FLNT format.
"""

from __future__ import annotations

from pathlib import Path

from filanti.core.context import ExecutionContext, Operation
from filanti.core.errors import DecryptionError, EncryptionError
from filanti.core.orchestrator import ExecutionResult
from filanti.crypto.cipher_engine import CipherEngine
from filanti.crypto.decryption import decrypt_file_with_password, decrypt_bytes_with_password
from filanti.crypto.encryption import (
    EncryptionAlgorithm,
    EncryptionMetadata,
    encrypt_file_with_password,
)
from filanti.crypto.format_handler import FormatHandler
from filanti.crypto.streaming_engine import (
    streaming_decrypt_file,
    streaming_encrypt_file,
)
from filanti.engines.base import BaseEngine


class CryptoEngine(BaseEngine):
    """Orchestrator-facing engine for symmetric encrypt/decrypt.

    Delegates to :class:`CipherEngine` (bytes) or
    :func:`streaming_encrypt_file` / :func:`streaming_decrypt_file`
    (files).
    """

    @property
    def name(self) -> str:
        return "crypto"

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if ctx.operation is Operation.ENCRYPT:
            return self._encrypt(ctx)
        if ctx.operation is Operation.DECRYPT:
            return self._decrypt(ctx)
        raise EncryptionError(
            f"CryptoEngine does not handle operation: {ctx.operation}"
        )

    # ------------------------------------------------------------------
    # Encrypt
    # ------------------------------------------------------------------

    def _encrypt(self, ctx: ExecutionContext) -> ExecutionResult:
        algorithm = EncryptionAlgorithm(ctx.algorithm or "aes-256-gcm")

        # --- password-based file encryption (v1 format with embedded KDF) ---
        if ctx.password is not None and ctx.key is None and ctx.input_path is not None:
            output = ctx.output_path
            if output is None:
                output = str(ctx.input_path) + ".enc"

            meta = encrypt_file_with_password(
                input_path=ctx.input_path,
                output_path=output,
                password=ctx.password,
                algorithm=algorithm,
                remove_source=ctx.remove_source,
                secure_delete=ctx.secure_delete,
            )
            return ExecutionResult(
                output_path=str(output),
                metadata=meta,
                algorithm=meta.algorithm,
                kdf=meta.kdf_algorithm,
                source_removed=ctx.remove_source,
            )

        # --- password-based bytes encryption (derive key, then encrypt) ---
        if ctx.password is not None and ctx.key is None and ctx.input_bytes is not None:
            from filanti.crypto.kdf import derive_key
            derived = derive_key(ctx.password)
            ctx.key = derived.key
            ctx.metadata["kdf_salt"] = derived.salt
            ctx.metadata["kdf_algorithm"] = derived.algorithm
            ctx.metadata["kdf_params"] = derived.params

        key = ctx.require_key()

        # --- bytes mode ---
        if ctx.input_bytes is not None:
            cipher = CipherEngine(algorithm)
            ct, nonce = cipher.encrypt(key, ctx.input_bytes, aad=ctx.associated_data)
            meta = EncryptionMetadata(
                version=2,
                algorithm=algorithm.value,
                nonce=nonce.hex(),
                original_size=len(ctx.input_bytes),
            )
            packed = FormatHandler.serialize(meta, ct, key)
            return ExecutionResult(
                ciphertext=packed,
                metadata=meta,
                algorithm=algorithm.value,
            )

        # --- file streaming mode (raw key, no password) ---
        if ctx.input_path is not None:
            output = ctx.output_path
            if output is None:
                output = str(ctx.input_path) + ".enc"

            chunk = ctx.chunk_size or 65536
            meta = streaming_encrypt_file(
                ctx.input_path, output, key, algorithm, chunk,
            )
            # Attach KDF info if password-based
            if "kdf_salt" in ctx.metadata:
                meta.salt = ctx.metadata["kdf_salt"].hex()
                meta.kdf_algorithm = ctx.metadata.get("kdf_algorithm")
                meta.kdf_params = ctx.metadata.get("kdf_params")

            return ExecutionResult(
                output_path=str(output),
                metadata=meta,
                algorithm=algorithm.value,
                streaming=True,
            )

        raise EncryptionError("No input provided (input_bytes or input_path)")

    # ------------------------------------------------------------------
    # Decrypt
    # ------------------------------------------------------------------

    def _decrypt(self, ctx: ExecutionContext) -> ExecutionResult:
        # --- password-based file decryption (reads KDF params from file) ---
        if ctx.password is not None and ctx.key is None and ctx.input_path is not None:
            output = ctx.output_path
            if output is None:
                inp = str(ctx.input_path)
                output = inp.removesuffix(".enc") if inp.endswith(".enc") else inp + ".dec"

            size = decrypt_file_with_password(
                input_path=ctx.input_path,
                output_path=output,
                password=ctx.password,
            )

            # Remove source if requested
            if ctx.remove_source:
                from filanti.core.file_manager import get_file_manager
                fm = get_file_manager()
                if ctx.secure_delete:
                    fm.secure_delete(ctx.input_path)
                else:
                    fm.delete(ctx.input_path)

            return ExecutionResult(
                output_path=str(output),
                size=size,
                source_removed=ctx.remove_source,
            )

        # --- password-based bytes decryption ---
        if ctx.password is not None and ctx.key is None and ctx.input_bytes is not None:
            from filanti.crypto.encryption import extract_kdf_block, EncryptedData
            from filanti.crypto.decryption import parse_encrypted_file
            from filanti.crypto.kdf import derive_key

            kdf_info = extract_kdf_block(ctx.input_bytes)
            if kdf_info is None:
                raise DecryptionError(
                    "Data was not encrypted with a password "
                    "(missing KDF block — unsupported legacy format)"
                )
            kdf_algo = kdf_info.get("a", "argon2id")
            kdf_params = kdf_info.get("p", {})
            salt_hex = kdf_info.get("s")
            if salt_hex is None:
                raise DecryptionError("KDF block is missing salt")
            salt = bytes.fromhex(salt_hex)

            derived = derive_key(
                ctx.password, salt=salt, algorithm=kdf_algo, **kdf_params,
            )
            metadata, ciphertext = parse_encrypted_file(
                ctx.input_bytes, encryption_key=derived.key,
            )
            encrypted = EncryptedData(
                ciphertext=ciphertext,
                nonce=bytes.fromhex(metadata.nonce),
                algorithm=metadata.algorithm,
                salt=salt,
                kdf_algorithm=kdf_algo,
                kdf_params=kdf_params,
            )
            plaintext = decrypt_bytes_with_password(encrypted, ctx.password)
            return ExecutionResult(
                plaintext=plaintext,
                metadata=metadata,
                algorithm=metadata.algorithm,
            )

        # --- raw-key bytes mode (v2 packed) ---
        if ctx.input_bytes is not None:
            key = ctx.require_key()
            meta, ct = FormatHandler.deserialize(ctx.input_bytes, key)
            algorithm = EncryptionAlgorithm(meta.algorithm)
            cipher = CipherEngine(algorithm)

            aad = ctx.associated_data
            nonce = bytes.fromhex(meta.nonce)
            plaintext = cipher.decrypt(key, ct, nonce, aad=aad)
            return ExecutionResult(
                plaintext=plaintext,
                metadata=meta,
                algorithm=algorithm.value,
            )

        # --- raw-key file streaming mode ---
        if ctx.input_path is not None:
            key = ctx.require_key()
            output = ctx.output_path
            if output is None:
                inp = str(ctx.input_path)
                output = inp.removesuffix(".enc") if inp.endswith(".enc") else inp + ".dec"

            size = streaming_decrypt_file(ctx.input_path, output, key)
            return ExecutionResult(
                output_path=str(output),
                size=size,
                streaming=True,
            )

        raise DecryptionError("No input provided (input_bytes or input_path)")
