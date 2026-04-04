"""
Threat Engine — Runtime security-posture profiles.

Built-in modes:
    * ``dev``       – relaxed settings for local development
    * ``production`` – balanced security/performance
    * ``paranoid``   – maximum security, higher resource cost

Custom modes can be loaded from YAML files or created programmatically.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class ThreatLevel(str, Enum):
    """Predefined threat-mode names."""

    DEV = "dev"
    PRODUCTION = "production"
    PARANOID = "paranoid"


# ------------------------------------------------------------------
# Default profile definitions
# ------------------------------------------------------------------

_PROFILES: dict[str, dict[str, Any]] = {
    "dev": {
        "encryption": {
            "algorithm": "aes-256-gcm",
        },
        "kdf": {
            "algorithm": "argon2id",
            "memory_cost": 16384,      # 16 MiB — fast iteration
            "time_cost": 1,
            "parallelism": 4,
        },
        "streaming": {
            "chunk_size": 65536,
        },
        "policy": {
            "min_password_length": 8,
            "disallow_raw_keys": False,
            "require_encrypted_metadata": True,
        },
    },
    "production": {
        "encryption": {
            "algorithm": "aes-256-gcm",
        },
        "kdf": {
            "algorithm": "argon2id",
            "memory_cost": 65536,      # 64 MiB — OWASP recommended
            "time_cost": 3,
            "parallelism": 4,
        },
        "streaming": {
            "chunk_size": 65536,
        },
        "policy": {
            "min_password_length": 8,
            "disallow_raw_keys": False,
            "require_encrypted_metadata": True,
        },
    },
    "paranoid": {
        "encryption": {
            "algorithm": "chacha20-poly1305",
        },
        "kdf": {
            "algorithm": "argon2id",
            "memory_cost": 131072,     # 128 MiB
            "time_cost": 5,
            "parallelism": 4,
        },
        "streaming": {
            "chunk_size": 32768,       # smaller chunks = less exposure
        },
        "policy": {
            "min_password_length": 14,
            "disallow_raw_keys": True,
            "require_encrypted_metadata": True,
        },
        "hashing": {
            "force_strong_hash": True,
            "algorithm": "sha512",
        },
        "integrity": {
            "enforce_signature_only": True,
        },
    },
}


# ------------------------------------------------------------------
# ThreatMode dataclass
# ------------------------------------------------------------------

@dataclass
class ThreatMode:
    """Concrete, resolved threat-mode configuration.

    Attributes:
        name: Human-friendly identifier.
        base: Optional base mode this was derived from.
        encryption: Encryption-related overrides.
        kdf: KDF-parameter overrides.
        streaming: Streaming-engine overrides.
        policy: Policy-enforcement overrides.
        hashing: Hashing-engine overrides.
        integrity: Integrity-engine overrides.
    """

    name: str
    base: str | None = None
    encryption: dict[str, Any] = field(default_factory=dict)
    kdf: dict[str, Any] = field(default_factory=dict)
    streaming: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    hashing: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Convenience accessor for nested values.

        >>> mode.get("kdf", "memory_cost", 65536)
        """
        section_dict: dict[str, Any] = getattr(self, section, {})
        return section_dict.get(key, default)


# ------------------------------------------------------------------
# ThreatEngine singleton-like loader
# ------------------------------------------------------------------

class ThreatEngine:
    """Load and resolve threat-mode profiles.

    Usage::

        mode = ThreatEngine.load("production")
        mode = ThreatEngine.load_from_dict({...})
        mode = ThreatEngine.load_from_file("modes/custom.yaml")
    """

    _custom_profiles: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, name: str) -> ThreatMode:
        """Load a built-in or previously registered profile by *name*.

        Raises:
            ValueError: If *name* is unknown.
        """
        profile = cls._custom_profiles.get(name) or _PROFILES.get(name)
        if profile is None:
            valid = sorted(set(list(_PROFILES) + list(cls._custom_profiles)))
            raise ValueError(
                f"Unknown threat mode '{name}'. Available: {valid}"
            )
        return cls._resolve(name, profile)

    @classmethod
    def load_from_dict(cls, data: dict[str, Any]) -> ThreatMode:
        """Build a ``ThreatMode`` from an arbitrary dict.

        The dict MAY contain a ``"base"`` key that references a built-in
        profile; overrides are deep-merged on top.
        """
        name: str = data.get("name", "custom")
        base_name: str | None = data.get("base")
        if base_name:
            base = copy.deepcopy(
                cls._custom_profiles.get(base_name)
                or _PROFILES.get(base_name)
                or {},
            )
            overrides: dict[str, Any] = data.get("overrides", {})
            merged = _deep_merge(base, overrides)
        else:
            merged = {
                k: v
                for k, v in data.items()
                if k not in ("name", "base", "overrides")
            }
        return cls._resolve(name, merged, base=base_name)

    @classmethod
    def load_from_file(cls, path: str | Path) -> ThreatMode:
        """Load a YAML (or JSON) threat-mode file.

        Raises:
            FileNotFoundError: If *path* doesn't exist.
            ValueError: On parse error.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Threat-mode file not found: {p}")

        text = p.read_text(encoding="utf-8")

        # Try YAML first, then JSON
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
                    f"Cannot parse threat-mode file as YAML or JSON: {exc}"
                ) from exc

        if not isinstance(data, dict):
            raise ValueError("Threat-mode file must contain a mapping")

        return cls.load_from_dict(data)

    @classmethod
    def register(cls, name: str, profile: dict[str, Any]) -> None:
        """Register a custom profile for later ``load()`` calls."""
        cls._custom_profiles[name] = copy.deepcopy(profile)

    @classmethod
    def available(cls) -> list[str]:
        """Return names of all available (built-in + custom) profiles."""
        return sorted(set(list(_PROFILES) + list(cls._custom_profiles)))

    @classmethod
    def reset(cls) -> None:
        """Remove all custom registrations (useful in tests)."""
        cls._custom_profiles.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @classmethod
    def _resolve(
        cls,
        name: str,
        profile: dict[str, Any],
        base: str | None = None,
    ) -> ThreatMode:
        return ThreatMode(
            name=name,
            base=base,
            encryption=profile.get("encryption", {}),
            kdf=profile.get("kdf", {}),
            streaming=profile.get("streaming", {}),
            policy=profile.get("policy", {}),
            hashing=profile.get("hashing", {}),
            integrity=profile.get("integrity", {}),
        )


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* (non-destructive)."""
    result = copy.deepcopy(base)
    for key, val in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(val, dict)
        ):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result
