"""
Base Engine — Abstract base class for all Filanti v2.1 engines.

Every engine accepts an ``ExecutionContext`` and returns an
``ExecutionResult`` through the single ``execute`` entry point.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from filanti.core.context import ExecutionContext
from filanti.core.orchestrator import ExecutionResult


class BaseEngine(ABC):
    """Abstract engine that the Orchestrator dispatches to."""

    @abstractmethod
    def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """Run the operation described by *ctx*.

        Subclasses MUST implement this method.

        Args:
            ctx: Fully-resolved execution context (keys resolved,
                 policy validated, threat mode applied).

        Returns:
            ``ExecutionResult`` with operation-specific attributes.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable engine name used for logging and routing."""
        ...
