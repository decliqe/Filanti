"""
Orchestrator — Central execution engine for Filanti v2.1.

Every public operation flows through::

    Orchestrator.execute(operation, context)
        → Threat Engine  (apply mode overrides)
        → Policy Engine  (validate rules)
        → KMS            (resolve / generate keys)
        → Engine Router  (dispatch to correct engine)
        → Engine.execute(context)
"""

from __future__ import annotations

from typing import Any

from filanti.core.context import ExecutionContext, Operation
from filanti.core.errors import (
    EncryptionError,
    FilantiError,
)
from filanti.kms.manager import KeyManager
from filanti.policy.engine import PolicyEngine
from filanti.threat.engine import ThreatEngine, ThreatMode


# ------------------------------------------------------------------
# Result container
# ------------------------------------------------------------------

class ExecutionResult:
    """Immutable result wrapper returned by the Orchestrator."""

    __slots__ = ("_data",)

    def __init__(self, **kwargs: Any) -> None:
        self._data: dict[str, Any] = dict(kwargs)

    def __getattr__(self, name: str) -> Any:
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name) from None

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        items = ", ".join(f"{k}={v!r}" for k, v in self._data.items())
        return f"ExecutionResult({items})"

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------

class Orchestrator:
    """Central v2.1 execution engine.

    Routes all operations through the pipeline::

        Threat Engine → Policy Engine → KMS → Engine Router → Engine

    Args:
        key_manager: Optional ``KeyManager`` instance. A default
            ``LocalProvider``-backed manager is used when omitted.
    """

    def __init__(self, key_manager: KeyManager | None = None) -> None:
        self._km = key_manager or KeyManager()
        # Lazy import to avoid circular deps at module load time
        from filanti.engines.router import EngineRouter
        self._router = EngineRouter()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        operation: str | Operation,
        context: dict[str, Any] | ExecutionContext | None = None,
        **overrides: Any,
    ) -> ExecutionResult:
        """Run *operation* through the full v2 pipeline.

        Args:
            operation: ``"encrypt"``, ``"decrypt"``, etc.
            context: An ``ExecutionContext`` or a plain dict that will be
                converted into one.
            **overrides: Extra fields merged into the context.

        Returns:
            ``ExecutionResult`` with operation-specific attributes.
        """
        # --- normalise input ---
        if isinstance(operation, str):
            operation = Operation(operation)

        ctx = self._build_context(operation, context, overrides)

        # --- 1. Threat mode ---
        mode = self._apply_threat_mode(ctx)

        # --- 2. Policy validation ---
        self._apply_policy(ctx, mode)

        # --- 3. KMS key resolution ---
        self._resolve_keys(ctx)

        # --- 4. Dispatch ---
        return self._dispatch(ctx)

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------

    def _build_context(
        self,
        operation: Operation,
        raw: dict[str, Any] | ExecutionContext | None,
        overrides: dict[str, Any],
    ) -> ExecutionContext:
        if isinstance(raw, ExecutionContext):
            ctx = raw.copy(operation=operation, **overrides)
        else:
            merged = dict(raw or {})
            merged.update(overrides)
            merged["operation"] = operation
            # Pop anything that isn't a Context field
            ctx = ExecutionContext(**{
                k: v
                for k, v in merged.items()
                if k in ExecutionContext.__dataclass_fields__
            })
        return ctx

    def _apply_threat_mode(self, ctx: ExecutionContext) -> ThreatMode | None:
        mode_name = ctx.threat_mode or "production"
        try:
            mode = ThreatEngine.load(mode_name)
        except ValueError:
            mode = ThreatEngine.load("production")

        # Override encryption algorithm if not explicitly set
        if ctx.algorithm is None and ctx.operation in (
            Operation.ENCRYPT, Operation.DECRYPT,
        ):
            alg = mode.get("encryption", "algorithm")
            if alg:
                ctx.algorithm = alg

        # Apply hashing overrides
        if ctx.operation is Operation.HASH and mode.hashing:
            if ctx.algorithm is None:
                alg = mode.hashing.get("algorithm")
                if alg:
                    ctx.algorithm = alg
            # force_strong_hash: override weak hash choices
            if mode.hashing.get("force_strong_hash") and ctx.algorithm:
                weak = {"md5", "sha1"}
                if ctx.algorithm.lower() in weak:
                    ctx.algorithm = mode.hashing.get("algorithm", "sha256")

        # Apply integrity overrides
        if mode.integrity:
            ctx.metadata["_threat_integrity"] = dict(mode.integrity)

        # Merge KDF overrides: threat mode provides defaults, user overrides win
        if mode.kdf:
            merged_kdf = dict(mode.kdf)
            merged_kdf.update(ctx.kdf_overrides)  # User overrides take priority
            ctx.kdf_overrides = merged_kdf

        # Push chunk_size
        if ctx.chunk_size is None:
            cs = mode.get("streaming", "chunk_size")
            if isinstance(cs, int):
                ctx.chunk_size = cs

        # Carry the policy min-password from threat mode into context
        # (only if context has no explicit policy)
        if ctx.policy_name is None:
            min_pw = mode.get("policy", "min_password_length")
            if min_pw is not None:
                ctx.metadata["_threat_min_pw"] = min_pw

        return mode

    def _apply_policy(
        self, ctx: ExecutionContext, mode: ThreatMode | None,
    ) -> None:
        policy_name = ctx.policy_name or "default"
        try:
            policy = PolicyEngine.load(policy_name)
        except ValueError:
            policy = PolicyEngine.load("default")

        # Merge threat-mode policy overrides
        if mode and mode.policy:
            if mode.policy.get("min_password_length") is not None:
                policy.min_password_length = max(
                    policy.min_password_length,
                    mode.policy["min_password_length"],
                )
            if mode.policy.get("disallow_raw_keys") is True:
                policy.disallow_raw_keys = True
            if mode.policy.get("require_encrypted_metadata") is True:
                policy.require_encrypted_metadata = True

        PolicyEngine.validate(ctx, policy)
        ctx.validated = True

    def _resolve_keys(self, ctx: ExecutionContext) -> None:
        """Resolve key material from password, key_ref, or raw key."""
        if ctx.key is not None:
            ctx.resolved = True
            return

        if ctx.password is not None:
            # Password-based operations: the CryptoEngine handles KDF
            # derivation internally (reads stored salt for decrypt,
            # generates fresh salt for encrypt).
            ctx.resolved = True
            return

        if ctx.key_ref is not None:
            ctx.key = self._km.resolve(ctx.key_ref)
            ctx.resolved = True
            return

        # Operations that don't need a symmetric key
        keyless = {Operation.HASH, Operation.CHECKSUM, Operation.VERIFY, Operation.DERIVE, Operation.SIGN}
        if ctx.operation not in keyless:
            raise EncryptionError(
                "No key material provided — supply key, password, or key_ref"
            )

    # ------------------------------------------------------------------
    # Dispatch to engines via router
    # ------------------------------------------------------------------

    def _dispatch(self, ctx: ExecutionContext) -> ExecutionResult:
        engine = self._router.route(ctx.operation)
        return engine.execute(ctx)


