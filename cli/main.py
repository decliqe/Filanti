"""
Filanti CLI - Command Line Interface.

Provides command-line access to Filanti's file security operations.
Outputs are JSON by default for automation and scripting.
"""

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from filanti import __version__
from filanti.hashing import crypto_hash


# Create main CLI app
app = typer.Typer(
    name="filanti",
    help="A modular, security-focused file framework.",
    add_completion=False,
    no_args_is_help=True,
)


def output_json(data: dict) -> None:
    """Print JSON output to stdout."""
    typer.echo(json.dumps(data, indent=2))


def output_error(message: str, code: int = 1) -> None:
    """Print error as JSON and exit."""
    output_json({"success": False, "error": message})
    raise typer.Exit(code)


@app.command()
def version() -> None:
    """Show version information."""
    output_json({
        "name": "filanti",
        "version": __version__,
    })


@app.command()
def hash(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to hash",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Hash algorithm to use",
        )
    ] = "sha256",
) -> None:
    """Compute cryptographic hash of a file.

    Supported algorithms: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512, blake2b
    """
    try:
        digest = crypto_hash.hash_file(str(file), algorithm)
        output_json({
            "success": True,
            "file": str(file.resolve()),
            "algorithm": algorithm.lower(),
            "hash": digest,
        })
    except Exception as e:
        output_error(str(e))


@app.command()
def verify(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to verify",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    expected: Annotated[
        str,
        typer.Argument(help="Expected hash value (hex)"),
    ],
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Hash algorithm used",
        )
    ] = "sha256",
) -> None:
    """Verify file matches expected hash.

    Uses constant-time comparison to prevent timing attacks.
    """
    try:
        is_valid = crypto_hash.verify_file_hash(str(file), expected, algorithm)
        actual = crypto_hash.hash_file(str(file), algorithm)

        output_json({
            "success": True,
            "file": str(file.resolve()),
            "algorithm": algorithm.lower(),
            "valid": is_valid,
            "expected": expected.lower(),
            "actual": actual,
        })

        if not is_valid:
            raise typer.Exit(1)
    except typer.Exit:
        raise
    except Exception as e:
        output_error(str(e))


@app.command()
def algorithms() -> None:
    """List supported hash algorithms."""
    output_json({
        "success": True,
        "algorithms": crypto_hash.get_supported_algorithms(),
        "default": crypto_hash.DEFAULT_ALGORITHM.value,
    })


def main() -> None:
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()

