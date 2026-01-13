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
from filanti.crypto import (
    encrypt_file_with_password,
    decrypt_file_with_password,
    get_file_metadata,
    EncryptionAlgorithm,
)


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


@app.command()
def encrypt(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to encrypt",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output path (default: input.enc)",
        )
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Encryption password (prompted if not provided)",
        )
    ] = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Encryption algorithm (aes-256-gcm, chacha20-poly1305)",
        )
    ] = "aes-256-gcm",
) -> None:
    """Encrypt a file with password-based encryption.

    Uses Argon2id for key derivation and authenticated encryption.
    """
    try:
        # Prompt for password if not provided
        if password is None:
            password = typer.prompt("Password", hide_input=True)
            confirm = typer.prompt("Confirm password", hide_input=True)
            if password != confirm:
                output_error("Passwords do not match")

        # Determine output path
        out_path = output or Path(str(file) + ".enc")

        # Parse algorithm
        try:
            enc_alg = EncryptionAlgorithm(algorithm.lower())
        except ValueError:
            output_error(f"Unsupported algorithm: {algorithm}")

        # Encrypt
        metadata = encrypt_file_with_password(
            input_path=file,
            output_path=out_path,
            password=password,
            algorithm=enc_alg,
        )

        output_json({
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "algorithm": metadata.algorithm,
            "kdf": metadata.kdf_algorithm,
        })

    except typer.Exit:
        raise
    except Exception as e:
        output_error(str(e))


@app.command()
def decrypt(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to encrypted file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output path (default: removes .enc extension)",
        )
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Decryption password (prompted if not provided)",
        )
    ] = None,
) -> None:
    """Decrypt a file encrypted with Filanti.

    Verifies integrity before writing output.
    """
    try:
        # Prompt for password if not provided
        if password is None:
            password = typer.prompt("Password", hide_input=True)

        # Determine output path
        if output is None:
            file_str = str(file)
            if file_str.endswith(".enc"):
                out_path = Path(file_str[:-4])
            else:
                out_path = Path(file_str + ".dec")
        else:
            out_path = output

        # Decrypt
        size = decrypt_file_with_password(
            input_path=file,
            output_path=out_path,
            password=password,
        )

        output_json({
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "size": size,
        })

    except typer.Exit:
        raise
    except Exception as e:
        output_error(str(e))


@app.command()
def info(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to encrypted file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
) -> None:
    """Show metadata from an encrypted file."""
    try:
        metadata = get_file_metadata(file)

        output_json({
            "success": True,
            "file": str(file.resolve()),
            "version": metadata.version,
            "algorithm": metadata.algorithm,
            "kdf_algorithm": metadata.kdf_algorithm,
            "original_size": metadata.original_size,
        })

    except Exception as e:
        output_error(str(e))


def main() -> None:
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()

