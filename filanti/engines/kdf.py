"""
KDF Engine — Key derivation via the engine interface.

Wraps ``filanti.crypto.kdf`` so that ALL password-based key
derivation goes through the orchestrator pipeline.
"""

from __future__ import annotations

from filanti.core.context import ExecutionContext, Operation
from filanti.core.errors import FilantiError
from filanti.core.orchestrator import ExecutionResult
from filanti.crypto.kdf import KDFAlgorithm, KDFParams, derive_key
from filanti.engines.base import BaseEngine


class KDFEngine(BaseEngine):
    """Orchestrator-facing engine for key derivation."""

    @property
    def name(self) -> str:
        return "kdf"

    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        if ctx.operation is Operation.DERIVE:
            return self._derive(ctx)
        raise FilantiError(
            f"KDFEngine does not handle operation: {ctx.operation}"
        )

    # ------------------------------------------------------------------
    # Derive
    # ------------------------------------------------------------------

    def _derive(self, ctx: ExecutionContext) -> ExecutionResult:
        if ctx.password is None:
            raise FilantiError(
                "KDFEngine.derive requires a password in context"
            )

        params = self._build_params(ctx)
        salt = ctx.metadata.get("salt")
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)

        derived = derive_key(ctx.password, salt=salt, params=params)

        return ExecutionResult(
            key=derived.key,
            salt=derived.salt.hex(),
            algorithm=derived.algorithm,
            params=derived.params,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_params(ctx: ExecutionContext) -> KDFParams:
        """Build ``KDFParams`` from context overrides."""
        params = KDFParams()
        ov = ctx.kdf_overrides
        if not ov:
            return params

        if "algorithm" in ov:
            params.algorithm = KDFAlgorithm(ov["algorithm"])
        if "memory_cost" in ov:
            params.argon2_memory_cost = ov["memory_cost"]
        if "time_cost" in ov:
            params.argon2_time_cost = ov["time_cost"]
        if "parallelism" in ov:
            params.argon2_parallelism = ov["parallelism"]
        if "key_length" in ov:
            params.key_length = ov["key_length"]
        return params

    # ------------------------------------------------------------------
    # Public helper for orchestrator key resolution
    # ------------------------------------------------------------------

    def derive_for_context(self, ctx: ExecutionContext) -> None:
        """Derive a key from ``ctx.password`` and store it in ``ctx.key``.

        Used by the Orchestrator during key resolution for
        password-based encryption — NOT as a standalone operation.
        """
        if ctx.password is None:
            raise FilantiError("No password in context for KDF")

        params = self._build_params(ctx)
        derived = derive_key(ctx.password, params=params)

        ctx.key = derived.key
        ctx.metadata["kdf_salt"] = derived.salt
        ctx.metadata["kdf_algorithm"] = derived.algorithm
        ctx.metadata["kdf_params"] = derived.params
