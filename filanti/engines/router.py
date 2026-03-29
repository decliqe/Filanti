"""
Engine Router — Maps operations to the correct engine.

Used by the Orchestrator to dispatch ``ExecutionContext`` to the
appropriate engine after threat/policy/KMS stages complete.
"""

from __future__ import annotations

from filanti.core.context import Operation
from filanti.core.errors import FilantiError
from filanti.engines.base import BaseEngine
from filanti.engines.crypto import CryptoEngine
from filanti.engines.hashing import HashingEngine
from filanti.engines.integrity import IntegrityEngine
from filanti.engines.kdf import KDFEngine


class EngineRouter:
    """Route operations to the correct engine instance.

    The router lazily instantiates engines on first use and
    caches them for the lifetime of the router.
    """

    def __init__(self) -> None:
        self._crypto = CryptoEngine()
        self._integrity = IntegrityEngine()
        self._hashing = HashingEngine()
        self._kdf = KDFEngine()

        self._routing: dict[Operation, BaseEngine] = {
            Operation.ENCRYPT: self._crypto,
            Operation.DECRYPT: self._crypto,
            Operation.SIGN: self._integrity,
            Operation.VERIFY: self._integrity,
            Operation.MAC: self._integrity,
            Operation.CHECKSUM: self._integrity,
            Operation.HASH: self._hashing,
            Operation.DERIVE: self._kdf,
        }

    def route(self, operation: Operation) -> BaseEngine:
        """Return the engine responsible for *operation*.

        Raises:
            FilantiError: If no engine handles the operation.
        """
        engine = self._routing.get(operation)
        if engine is None:
            raise FilantiError(
                f"No engine registered for operation: {operation}"
            )
        return engine

    @property
    def crypto(self) -> CryptoEngine:
        """Direct access to the CryptoEngine (for orchestrator internals)."""
        return self._crypto

    @property
    def integrity(self) -> IntegrityEngine:
        return self._integrity

    @property
    def hashing(self) -> HashingEngine:
        return self._hashing

    @property
    def kdf(self) -> KDFEngine:
        return self._kdf

    @property
    def available_operations(self) -> list[str]:
        """All operation names this router can handle."""
        return [op.value for op in self._routing]
