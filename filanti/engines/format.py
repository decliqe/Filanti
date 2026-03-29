"""
Format Engine — Unified serialization/deserialization for all domains.

Handles:
    * Encryption metadata (v2 encrypted format via FormatHandler)
    * Signature metadata (detached .sig JSON)
    * MAC metadata (detached .mac JSON)
    * Checksum metadata (detached .chk JSON)
"""

from __future__ import annotations

import json
from typing import Any

from filanti.core.errors import DecryptionError, FilantiError
from filanti.core.orchestrator import ExecutionResult
from filanti.crypto.encryption import EncryptionMetadata
from filanti.crypto.format_handler import FormatHandler


class FormatEngine:
    """Centralized format handler for all Filanti output types.

    Encryption serializes via the binary v2 format.
    Other domains serialize to JSON sidecar files.
    """

    @property
    def name(self) -> str:
        return "format"

    # ------------------------------------------------------------------
    # Encryption format (v2 binary)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize_encrypted(
        metadata: EncryptionMetadata,
        ciphertext: bytes,
        encryption_key: bytes,
    ) -> bytes:
        """Wrap ciphertext + metadata into the v2 on-disk format."""
        return FormatHandler.serialize(metadata, ciphertext, encryption_key)

    @staticmethod
    def deserialize_encrypted(
        data: bytes,
        encryption_key: bytes | None = None,
    ) -> tuple[EncryptionMetadata, bytes]:
        """Parse v2 format → (metadata, ciphertext)."""
        return FormatHandler.deserialize(data, encryption_key)

    # ------------------------------------------------------------------
    # Signature format (JSON sidecar)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize_signature(
        signature_hex: str,
        algorithm: str,
        public_key: str | bytes | None = None,
        filename: str | None = None,
        filesize: int | None = None,
    ) -> str:
        """Build a detached signature sidecar as JSON."""
        from datetime import datetime, timezone

        payload: dict[str, Any] = {
            "version": "2.0",
            "type": "signature",
            "signature": signature_hex,
            "algorithm": algorithm,
        }
        if public_key is not None:
            if isinstance(public_key, bytes):
                public_key = public_key.decode("utf-8")
            payload["public_key"] = public_key
        if filename is not None:
            payload["filename"] = filename
        if filesize is not None:
            payload["filesize"] = filesize
        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(payload, indent=2)

    @staticmethod
    def deserialize_signature(data: str) -> dict[str, Any]:
        """Parse a signature sidecar JSON."""
        try:
            return json.loads(data)  # type: ignore[no-any-return]
        except json.JSONDecodeError as exc:
            raise FilantiError(f"Invalid signature sidecar: {exc}") from exc

    # ------------------------------------------------------------------
    # MAC format (JSON sidecar)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize_mac(
        mac_hex: str,
        algorithm: str,
        filename: str | None = None,
        filesize: int | None = None,
    ) -> str:
        """Build a detached MAC sidecar as JSON."""
        from datetime import datetime, timezone

        payload: dict[str, Any] = {
            "version": "2.0",
            "type": "mac",
            "mac": mac_hex,
            "algorithm": algorithm,
        }
        if filename is not None:
            payload["filename"] = filename
        if filesize is not None:
            payload["filesize"] = filesize
        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(payload, indent=2)

    @staticmethod
    def deserialize_mac(data: str) -> dict[str, Any]:
        """Parse a MAC sidecar JSON."""
        try:
            return json.loads(data)  # type: ignore[no-any-return]
        except json.JSONDecodeError as exc:
            raise FilantiError(f"Invalid MAC sidecar: {exc}") from exc

    # ------------------------------------------------------------------
    # Checksum format (JSON sidecar)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize_checksum(
        checksum_hex: str,
        algorithm: str,
        filename: str | None = None,
        filesize: int | None = None,
    ) -> str:
        """Build a detached checksum sidecar as JSON."""
        from datetime import datetime, timezone

        payload: dict[str, Any] = {
            "version": "2.0",
            "type": "checksum",
            "checksum": checksum_hex,
            "algorithm": algorithm,
        }
        if filename is not None:
            payload["filename"] = filename
        if filesize is not None:
            payload["filesize"] = filesize
        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(payload, indent=2)

    @staticmethod
    def deserialize_checksum(data: str) -> dict[str, Any]:
        """Parse a checksum sidecar JSON."""
        try:
            return json.loads(data)  # type: ignore[no-any-return]
        except json.JSONDecodeError as exc:
            raise FilantiError(f"Invalid checksum sidecar: {exc}") from exc

    # ------------------------------------------------------------------
    # Hash format (JSON sidecar)
    # ------------------------------------------------------------------

    @staticmethod
    def serialize_hash(
        hash_hex: str,
        algorithm: str,
        filename: str | None = None,
        filesize: int | None = None,
    ) -> str:
        """Build a detached hash sidecar as JSON."""
        from datetime import datetime, timezone

        payload: dict[str, Any] = {
            "version": "2.0",
            "type": "hash",
            "hash": hash_hex,
            "algorithm": algorithm,
        }
        if filename is not None:
            payload["filename"] = filename
        if filesize is not None:
            payload["filesize"] = filesize
        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        return json.dumps(payload, indent=2)

    @staticmethod
    def deserialize_hash(data: str) -> dict[str, Any]:
        """Parse a hash sidecar JSON."""
        try:
            return json.loads(data)  # type: ignore[no-any-return]
        except json.JSONDecodeError as exc:
            raise FilantiError(f"Invalid hash sidecar: {exc}") from exc
