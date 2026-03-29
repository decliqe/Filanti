"""
Integrity Engine — Digital signatures, MACs, and checksums.

Wraps ``filanti.integrity.signature``, ``filanti.integrity.mac``,
and ``filanti.integrity.checksum`` behind the unified engine interface.
"""

from __future__ import annotations

from filanti.core.context import ExecutionContext, Operation
from filanti.core.errors import FilantiError
from filanti.core.orchestrator import ExecutionResult
from filanti.engines.base import BaseEngine


class IntegrityEngine(BaseEngine):
    """Orchestrator-facing engine for integrity operations."""

    @property
    def name(self) -> str:
        return "integrity"

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        handlers = {
            Operation.SIGN: self._sign,
            Operation.VERIFY: self._verify,
            Operation.MAC: self._mac,
            Operation.CHECKSUM: self._checksum,
        }
        handler = handlers.get(ctx.operation)
        if handler is None:
            raise FilantiError(
                f"IntegrityEngine does not handle operation: {ctx.operation}"
            )
        return handler(ctx)

    # ------------------------------------------------------------------
    # Sign
    # ------------------------------------------------------------------

    def _sign(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.integrity.signature import sign_bytes, sign_file

        pk = ctx.metadata.get("private_key")
        if pk is None:
            raise FilantiError(
                "No private_key in context metadata for signing"
            )

        if ctx.input_bytes is not None:
            result = sign_bytes(ctx.input_bytes, pk)
            return ExecutionResult(
                signature=result.signature.hex(),
                algorithm=result.algorithm,
            )

        if ctx.input_path is not None:
            result = sign_file(str(ctx.input_path), pk)
            return ExecutionResult(
                signature=result.signature.hex(),
                algorithm=result.algorithm,
            )

        raise FilantiError("No input provided for sign")

    # ------------------------------------------------------------------
    # Verify
    # ------------------------------------------------------------------

    def _verify(self, ctx: ExecutionContext) -> ExecutionResult:
        # Check whether this is MAC verification or signature verification
        if "expected_mac" in ctx.metadata:
            return self._verify_mac(ctx)

        from filanti.integrity.signature import (
            verify_signature,
            verify_file_signature,
        )

        pub = ctx.metadata.get("public_key")
        sig = ctx.metadata.get("signature")
        if pub is None or sig is None:
            raise FilantiError(
                "public_key and signature required in metadata"
            )

        sig_bytes = bytes.fromhex(sig) if isinstance(sig, str) else sig

        if ctx.input_bytes is not None:
            ok = verify_signature(ctx.input_bytes, sig_bytes, pub)
            return ExecutionResult(valid=ok)

        if ctx.input_path is not None:
            ok = verify_file_signature(str(ctx.input_path), sig_bytes, pub)
            return ExecutionResult(valid=ok)

        raise FilantiError("No input provided for verify")

    # ------------------------------------------------------------------
    # MAC
    # ------------------------------------------------------------------

    def _mac(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.integrity.mac import (
            MACAlgorithm,
            compute_file_mac,
            compute_mac,
        )

        key = ctx.require_key()
        alg = MACAlgorithm(ctx.algorithm or "hmac-sha256")

        if ctx.input_bytes is not None:
            result = compute_mac(ctx.input_bytes, key, alg)
            return ExecutionResult(mac=result.to_hex(), algorithm=alg.value)

        if ctx.input_path is not None:
            result = compute_file_mac(str(ctx.input_path), key, alg)
            return ExecutionResult(mac=result.to_hex(), algorithm=alg.value)

        raise FilantiError("No input provided for MAC")

    def _verify_mac(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.integrity.mac import MACAlgorithm, verify_mac, verify_file_mac

        key = ctx.require_key()
        alg = MACAlgorithm(ctx.algorithm or "hmac-sha256")
        expected = ctx.metadata["expected_mac"]
        # verify_mac expects raw bytes for the mac parameter
        if isinstance(expected, str):
            expected = bytes.fromhex(expected)

        if ctx.input_bytes is not None:
            ok = verify_mac(ctx.input_bytes, expected, key, alg)
            return ExecutionResult(valid=ok, algorithm=alg.value)

        if ctx.input_path is not None:
            ok = verify_file_mac(str(ctx.input_path), expected, key, alg)
            return ExecutionResult(valid=ok, algorithm=alg.value)

        raise FilantiError("No input provided for verify_mac")

    # ------------------------------------------------------------------
    # Checksum
    # ------------------------------------------------------------------

    def _checksum(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.integrity.checksum import (
            ChecksumAlgorithm,
            compute_checksum,
            compute_file_checksum,
        )

        alg = ChecksumAlgorithm(ctx.algorithm or "crc32")

        if ctx.input_bytes is not None:
            result = compute_checksum(ctx.input_bytes, alg)
            return ExecutionResult(
                checksum=result.to_hex(), algorithm=alg.value,
            )

        if ctx.input_path is not None:
            result = compute_file_checksum(str(ctx.input_path), alg)
            return ExecutionResult(
                checksum=result.to_hex(), algorithm=alg.value,
            )

        raise FilantiError("No input provided for checksum")
