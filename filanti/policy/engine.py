"""
Policy Engine — Enforce allowed operations and parameter constraints.

Policies are declarative rule-sets that the Orchestrator validates
against the ``ExecutionContext`` **before** any crypto work begins.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from filanti.core.context import ExecutionContext
from filanti.core.errors import ValidationError


# ------------------------------------------------------------------
# Policy dataclass
# ------------------------------------------------------------------

@dataclass
class Policy:
    """A resolved, immutable policy configuration.

    Attributes:
        name: Human-readable identifier.
        allowed_algorithms: Whitelist of permitted encryption algorithms.
            ``None`` means "all algorithms are allowed".
        allowed_operations: Whitelist of permitted operations.
            ``None`` means "all operations are allowed".
        min_password_length: Minimum acceptable password length.
        disallow_raw_keys: If ``True``, raw-key operations are blocked
            (users MUST use password-based or KMS key refs).
        require_encrypted_metadata: Enforce v2 encrypted-metadata format.
        max_chunk_size: Upper bound on streaming chunk size.
        allowed_signatures: Whitelist of permitted signature algorithms
            (e.g. ``["ed25519", "ecdsa-p256"]``). ``None`` = all allowed.
        allowed_mac: Whitelist of permitted MAC algorithms
            (e.g. ``["hmac-sha256"]``). ``None`` = all allowed.
        allowed_hashes: Whitelist of permitted hash algorithms
            (e.g. ``["sha256", "blake2b"]``). ``None`` = all allowed.
        kdf_min_memory_cost: Minimum memory cost (KiB) for KDF
            derivations. ``None`` = no enforcement.
        custom_rules: Arbitrary key/value rules for extensions.
    """

    name: str = "default"
    allowed_algorithms: list[str] | None = None
    allowed_operations: list[str] | None = None
    min_password_length: int = 8
    disallow_raw_keys: bool = False
    require_encrypted_metadata: bool = True
    max_chunk_size: int = 16 * 1024 * 1024
    allowed_signatures: list[str] | None = None
    allowed_mac: list[str] | None = None
    allowed_hashes: list[str] | None = None
    kdf_min_memory_cost: int | None = None
    custom_rules: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------
# Built-in policies
# ------------------------------------------------------------------

_BUILTIN: dict[str, dict[str, Any]] = {
    "default": {
        "name": "default",
        "min_password_length": 8,
        "disallow_raw_keys": False,
        "require_encrypted_metadata": True,
    },
    "enterprise": {
        "name": "enterprise",
        "allowed_algorithms": ["aes-256-gcm"],
        "allowed_signatures": ["ed25519"],
        "allowed_mac": ["hmac-sha256"],
        "allowed_hashes": ["sha256", "sha384", "sha512", "blake2b"],
        "kdf_min_memory_cost": 65536,
        "min_password_length": 14,
        "disallow_raw_keys": True,
        "require_encrypted_metadata": True,
    },
    "relaxed": {
        "name": "relaxed",
        "min_password_length": 4,
        "disallow_raw_keys": False,
        "require_encrypted_metadata": False,
    },
}


# ------------------------------------------------------------------
# PolicyEngine
# ------------------------------------------------------------------

class PolicyEngine:
    """Load policies and validate execution contexts against them.

    Usage::

        policy = PolicyEngine.load("enterprise")
        PolicyEngine.validate(context, policy)   # raises on violation
    """

    _custom: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, name: str) -> Policy:
        """Load a built-in or registered policy by name.

        Raises:
            ValueError: If *name* is unknown.
        """
        raw = cls._custom.get(name) or _BUILTIN.get(name)
        if raw is None:
            valid = sorted(set(list(_BUILTIN) + list(cls._custom)))
            raise ValueError(f"Unknown policy '{name}'. Available: {valid}")
        return cls._to_policy(raw)

    @classmethod
    def load_from_dict(cls, data: dict[str, Any]) -> Policy:
        """Build a ``Policy`` from an arbitrary mapping."""
        return cls._to_policy(data)

    @classmethod
    def load_from_file(cls, path: str | Path) -> Policy:
        """Load a YAML or JSON policy file.

        Raises:
            FileNotFoundError: If *path* doesn't exist.
            ValueError: On parse error.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {p}")
        text = p.read_text(encoding="utf-8")

        data: dict[str, Any] | None = None
        try:
            import yaml  # type: ignore[import-untyped]
            data = yaml.safe_load(text)
        except ImportError:
            pass
        except Exception:
            pass

        if data is None:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Cannot parse policy file: {exc}"
                ) from exc

        if not isinstance(data, dict):
            raise ValueError("Policy file must contain a mapping")
        return cls.load_from_dict(data)

    @classmethod
    def register(cls, name: str, raw: dict[str, Any]) -> None:
        """Register a custom policy for later ``load()``."""
        cls._custom[name] = copy.deepcopy(raw)

    @classmethod
    def available(cls) -> list[str]:
        """Return all available policy names."""
        return sorted(set(list(_BUILTIN) + list(cls._custom)))

    @classmethod
    def reset(cls) -> None:
        """Clear custom registrations."""
        cls._custom.clear()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @classmethod
    def validate(cls, ctx: ExecutionContext, policy: Policy) -> None:
        """Validate *ctx* against *policy*.

        Raises:
            ValidationError: On any policy violation.
        """
        from filanti.core.context import Operation

        violations: list[str] = []

        # 1. Operation whitelist
        if policy.allowed_operations is not None:
            if ctx.operation.value not in policy.allowed_operations:
                violations.append(
                    f"Operation '{ctx.operation.value}' is not allowed "
                    f"by policy '{policy.name}'"
                )

        # 2. Algorithm whitelist (encryption-specific)
        if policy.allowed_algorithms is not None and ctx.algorithm is not None:
            if ctx.operation in (Operation.ENCRYPT, Operation.DECRYPT):
                if ctx.algorithm not in policy.allowed_algorithms:
                    violations.append(
                        f"Algorithm '{ctx.algorithm}' is not allowed "
                        f"by policy '{policy.name}'. "
                        f"Permitted: {policy.allowed_algorithms}"
                    )

        # 3. Signature algorithm whitelist
        if (
            policy.allowed_signatures is not None
            and ctx.operation in (Operation.SIGN, Operation.VERIFY)
            and ctx.algorithm is not None
        ):
            if ctx.algorithm not in policy.allowed_signatures:
                violations.append(
                    f"Signature algorithm '{ctx.algorithm}' is not allowed "
                    f"by policy '{policy.name}'. "
                    f"Permitted: {policy.allowed_signatures}"
                )

        # 4. MAC algorithm whitelist
        if (
            policy.allowed_mac is not None
            and ctx.operation is Operation.MAC
            and ctx.algorithm is not None
        ):
            if ctx.algorithm not in policy.allowed_mac:
                violations.append(
                    f"MAC algorithm '{ctx.algorithm}' is not allowed "
                    f"by policy '{policy.name}'. "
                    f"Permitted: {policy.allowed_mac}"
                )

        # 5. Hash algorithm whitelist
        if (
            policy.allowed_hashes is not None
            and ctx.operation is Operation.HASH
            and ctx.algorithm is not None
        ):
            if ctx.algorithm not in policy.allowed_hashes:
                violations.append(
                    f"Hash algorithm '{ctx.algorithm}' is not allowed "
                    f"by policy '{policy.name}'. "
                    f"Permitted: {policy.allowed_hashes}"
                )

        # 6. Password length
        if ctx.password is not None:
            if len(ctx.password) < policy.min_password_length:
                violations.append(
                    f"Password too short ({len(ctx.password)} chars). "
                    f"Policy '{policy.name}' requires >= {policy.min_password_length}"
                )

        # 7. Raw key restriction
        if policy.disallow_raw_keys and ctx.key is not None and ctx.key_ref is None:
            violations.append(
                f"Policy '{policy.name}' disallows raw keys — "
                f"use a password or KMS key reference instead"
            )

        # 8. Chunk size cap
        if ctx.chunk_size is not None and ctx.chunk_size > policy.max_chunk_size:
            violations.append(
                f"Chunk size {ctx.chunk_size} exceeds policy max "
                f"{policy.max_chunk_size}"
            )

        # 9. KDF memory-cost floor
        if policy.kdf_min_memory_cost is not None and ctx.kdf_overrides:
            mem = ctx.kdf_overrides.get("memory_cost")
            if mem is not None and mem < policy.kdf_min_memory_cost:
                violations.append(
                    f"KDF memory_cost {mem} is below policy minimum "
                    f"{policy.kdf_min_memory_cost}"
                )

        if violations:
            raise ValidationError(
                "; ".join(violations),
                context={"policy": policy.name, "violations": violations},
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @classmethod
    def _to_policy(cls, raw: dict[str, Any]) -> Policy:
        known = {f.name for f in Policy.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        kwargs = {k: v for k, v in raw.items() if k in known}
        return Policy(**kwargs)
