"""
Hashing Engine — Cryptographic hash operations via engine interface.

Wraps ``filanti.hashing.crypto_hash`` for orchestrator routing.
"""

from __future__ import annotations

from filanti.core.context import ExecutionContext, Operation
from filanti.core.errors import FilantiError
from filanti.core.orchestrator import ExecutionResult
from filanti.engines.base import BaseEngine


class HashingEngine(BaseEngine):
    """Orchestrator-facing engine for hashing operations."""

    @property
    def name(self) -> str:
        return "hashing"

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if ctx.operation is Operation.HASH:
            # If expected_hash is provided, this is a verify operation
            if "expected_hash" in ctx.metadata:
                return self._verify(ctx)
            return self._hash(ctx)
        raise FilantiError(
            f"HashingEngine does not handle operation: {ctx.operation}"
        )

    # ------------------------------------------------------------------
    # Hash
    # ------------------------------------------------------------------

    def _hash(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.hashing.crypto_hash import HashAlgorithm, hash_bytes, hash_file

        alg = HashAlgorithm(ctx.algorithm or "sha256")

        if ctx.input_bytes is not None:
            digest = hash_bytes(ctx.input_bytes, alg)
            return ExecutionResult(hash=digest, algorithm=alg.value)

        if ctx.input_path is not None:
            digest = hash_file(str(ctx.input_path), alg)
            return ExecutionResult(hash=digest, algorithm=alg.value)

        raise FilantiError("No input provided for hash")

    # ------------------------------------------------------------------
    # Verify hash
    # ------------------------------------------------------------------

    def _verify(self, ctx: ExecutionContext) -> ExecutionResult:
        from filanti.hashing.crypto_hash import HashAlgorithm, hash_bytes, hash_file
        from filanti.core.secure_memory import secure_compare

        alg = HashAlgorithm(ctx.algorithm or "sha256")
        expected: str = ctx.metadata["expected_hash"]

        if ctx.input_bytes is not None:
            digest = hash_bytes(ctx.input_bytes, alg)
        elif ctx.input_path is not None:
            digest = hash_file(str(ctx.input_path), alg)
        else:
            raise FilantiError("No input provided for hash verify")

        valid = secure_compare(
            digest.encode("utf-8"), expected.encode("utf-8"),
        )
        return ExecutionResult(
            valid=valid, hash=digest, algorithm=alg.value,
        )
