"""
Metadata handling for Filanti operations.

Provides a structured way to store and retrieve metadata about
files, operations, and cryptographic parameters.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from filanti.core.errors import FileOperationError, ValidationError


class MetadataVersion(str, Enum):
    """Metadata format versions for compatibility tracking."""

    V1 = "1.0"


@dataclass
class FileMetadata:
    """Metadata container for Filanti operations.

    Stores information about file operations including:
    - Version for format compatibility
    - Algorithm information
    - Hash values
    - Timestamps
    - Custom attributes
    """

    version: str = MetadataVersion.V1.value
    algorithm: str | None = None
    hash_value: str | None = None
    original_filename: str | None = None
    original_size: int | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary.

        Returns:
            Dictionary representation of metadata.
        """
        return asdict(self)

    def to_json(self, indent: int | None = 2) -> str:
        """Serialize metadata to JSON string.

        Args:
            indent: Indentation level for pretty printing.

        Returns:
            JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileMetadata":
        """Create metadata from dictionary.

        Args:
            data: Dictionary containing metadata fields.

        Returns:
            FileMetadata instance.

        Raises:
            ValidationError: If required fields are missing or invalid.
        """
        try:
            # Extract known fields, put rest in attributes
            known_fields = {
                "version", "algorithm", "hash_value", "original_filename",
                "original_size", "created_at", "attributes"
            }

            kwargs = {k: v for k, v in data.items() if k in known_fields}
            extra = {k: v for k, v in data.items() if k not in known_fields}

            # Merge extra fields into attributes
            if extra:
                attrs = kwargs.get("attributes", {})
                attrs.update(extra)
                kwargs["attributes"] = attrs

            return cls(**kwargs)
        except (TypeError, ValueError) as e:
            raise ValidationError(f"Invalid metadata format: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> "FileMetadata":
        """Deserialize metadata from JSON string.

        Args:
            json_str: JSON string to parse.

        Returns:
            FileMetadata instance.

        Raises:
            ValidationError: If JSON is invalid or missing required fields.
        """
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON: {e}") from e

    def save(self, path: str | Path) -> None:
        """Save metadata to a JSON file.

        Args:
            path: Path to save metadata to.

        Raises:
            FileOperationError: If file cannot be written.
        """
        try:
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.to_json(), encoding="utf-8")
        except OSError as e:
            raise FileOperationError(
                f"Failed to save metadata: {e}",
                path=str(path),
                operation="save_metadata",
            ) from e

    @classmethod
    def load(cls, path: str | Path) -> "FileMetadata":
        """Load metadata from a JSON file.

        Args:
            path: Path to load metadata from.

        Returns:
            FileMetadata instance.

        Raises:
            FileOperationError: If file cannot be read.
            ValidationError: If metadata is invalid.
        """
        try:
            path = Path(path)
            json_str = path.read_text(encoding="utf-8")
            return cls.from_json(json_str)
        except FileNotFoundError as e:
            raise FileOperationError(
                "Metadata file not found",
                path=str(path),
                operation="load_metadata",
            ) from e
        except OSError as e:
            raise FileOperationError(
                f"Failed to load metadata: {e}",
                path=str(path),
                operation="load_metadata",
            ) from e

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a custom attribute.

        Args:
            key: Attribute name.
            value: Attribute value (must be JSON-serializable).
        """
        self.attributes[key] = value

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get a custom attribute.

        Args:
            key: Attribute name.
            default: Default value if attribute not found.

        Returns:
            Attribute value or default.
        """
        return self.attributes.get(key, default)

