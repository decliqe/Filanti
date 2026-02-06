"""
Filanti CLI - Command Line Interface.

Provides command-line access to Filanti's file security operations.
Outputs are JSON by default for automation and scripting.

Supports ENV-based secret resolution:
    filanti encrypt file.txt --password ENV:MY_PASSWORD
"""

import json
import os
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
from filanti.crypto.asymmetric import (
    AsymmetricAlgorithm,
    generate_asymmetric_keypair,
    save_asymmetric_keypair,
    hybrid_encrypt_file,
    hybrid_decrypt_file,
    get_hybrid_file_metadata,
    get_supported_asymmetric_algorithms,
)
from filanti.integrity import (
    # MAC
    MACAlgorithm,
    compute_file_mac,
    verify_file_mac,
    create_integrity_file,
    verify_integrity_file,
    # Signature
    SignatureAlgorithm,
    generate_keypair,
    save_keypair,
    sign_file,
    verify_file_signature,
    create_signature_file,
    verify_signature_file,
    # Checksum
    ChecksumAlgorithm,
    compute_file_checksum,
    verify_file_checksum,
    create_checksum_file,
    verify_checksum_file,
)
from filanti.core.secrets import (
    resolve_secret,
    is_env_reference,
    redact_secret,
    load_dotenv,
    REDACTED_PLACEHOLDER,
)
from filanti.core.errors import SecretError


# Common type annotations for secret-related options
EnvVarOption = Annotated[
    Optional[str],
    typer.Option(
        "--env",
        help="Environment variable name (PowerShell-friendly). Equivalent to --password ENV:VAR",
    ),
]

DotenvOption = Annotated[
    Optional[Path],
    typer.Option(
        "--dotenv",
        help="Path to .env file to load secrets from",
    ),
]

EnvKeyOption = Annotated[
    Optional[str],
    typer.Option(
        "--env-key",
        help="Variable name from .env file to use as secret",
    ),
]


def resolve_password_from_options(
    password: Optional[str] = None,
    env_var: Optional[str] = None,
    dotenv_path: Optional[Path] = None,
    env_key: Optional[str] = None,
    prompt: bool = True,
    confirm: bool = True,
    prompt_text: str = "Password",
) -> Optional[str]:
    """Resolve password from multiple sources with priority.

    Priority order:
    1. --password (literal or ENV reference)
    2. --env VAR_NAME (PowerShell-friendly)
    3. --env-key KEY_FROM_DOTENV
    4. Interactive prompt (if prompt=True)

    Args:
        password: Password value or ENV reference
        env_var: Environment variable name (PowerShell-friendly)
        dotenv_path: Path to .env file
        env_key: Key name from .env file
        prompt: Whether to prompt interactively if no password found
        confirm: Whether to confirm password when prompting
        prompt_text: Text to display when prompting

    Returns:
        Resolved password string, or None if not found and prompt=False

    Raises:
        SecretError: If ENV reference cannot be resolved
    """
    # Load .env file if provided
    loaded_vars: dict[str, str] = {}
    if dotenv_path is not None:
        loaded_vars = load_dotenv(dotenv_path, override=False)

    resolved_password: Optional[str] = None

    # Priority 1: --password (literal or ENV reference)
    if password is not None:
        resolved_password = resolve_secret(password)

    # Priority 2: --env VAR_NAME (PowerShell-friendly)
    elif env_var is not None:
        resolved_password = resolve_secret(f"ENV:{env_var}")

    # Priority 3: --env-key KEY_FROM_DOTENV
    elif env_key is not None:
        if env_key in loaded_vars:
            resolved_password = loaded_vars[env_key]
        elif env_key in os.environ:
            resolved_password = os.environ[env_key]
        else:
            raise SecretError(
                f"Variable '{env_key}' not found in .env file or environment",
                env_var=env_key,
            )

    # Priority 4: Interactive prompt
    if resolved_password is None and prompt:
        resolved_password = typer.prompt(prompt_text, hide_input=True)
        if confirm:
            confirm_password = typer.prompt(f"Confirm {prompt_text.lower()}", hide_input=True)
            if resolved_password != confirm_password:
                output_error(f"{prompt_text}s do not match")
                return None  # Will never reach here due to exit

    return resolved_password


def resolve_key_from_options(
    key: Optional[str] = None,
    env_var: Optional[str] = None,
    dotenv_path: Optional[Path] = None,
    env_key: Optional[str] = None,
) -> Optional[str]:
    """Resolve secret key from multiple sources (no prompting).

    Same priority as resolve_password_from_options but without interactive prompt.
    """
    return resolve_password_from_options(
        password=key,
        env_var=env_var,
        dotenv_path=dotenv_path,
        env_key=env_key,
        prompt=False,
        confirm=False,
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
            help="Encryption password (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Encryption algorithm (aes-256-gcm, chacha20-poly1305)",
        )
    ] = "aes-256-gcm",
    remove_source: Annotated[
        bool,
        typer.Option(
            "--remove-source",
            help="Delete original file after successful encryption",
        )
    ] = False,
    secure_delete: Annotated[
        bool,
        typer.Option(
            "--secure-delete/--no-secure-delete",
            help="Securely overwrite original file before deletion (when --remove-source is used)",
        )
    ] = True,
) -> None:
    """Encrypt a file with password-based encryption.

    Uses Argon2id for key derivation and authenticated encryption.

    Supports multiple secret resolution formats:
        filanti encrypt file.txt --password ENV:MY_PASSWORD
        filanti encrypt file.txt --password '$env:MY_PASSWORD'  # PowerShell
        filanti encrypt file.txt --password '${MY_PASSWORD}'    # Shell-style
        filanti encrypt file.txt --password env.MY_PASSWORD     # Dot notation
        filanti encrypt file.txt --env MY_PASSWORD              # PowerShell-friendly
        filanti encrypt file.txt --dotenv .env --env-key MY_PASSWORD

    Source file deletion:
        filanti encrypt file.txt --password secret --remove-source
        filanti encrypt file.txt --password secret --remove-source --no-secure-delete
    """
    try:
        # Resolve password using helper
        try:
            resolved_password = resolve_password_from_options(
                password=password,
                env_var=env_var,
                dotenv_path=dotenv,
                env_key=env_key,
                prompt=True,
                confirm=True,
            )
        except SecretError as e:
            output_error(str(e))
            return

        if resolved_password is None:
            return  # Error already output

        # Determine output path
        out_path = output or Path(str(file) + ".enc")

        # Parse algorithm
        try:
            enc_alg = EncryptionAlgorithm(algorithm.lower())
        except ValueError:
            output_error(f"Unsupported algorithm: {algorithm}")
            return

        # Encrypt
        metadata = encrypt_file_with_password(
            input_path=file,
            output_path=out_path,
            password=resolved_password,
            algorithm=enc_alg,
            remove_source=remove_source,
            secure_delete=secure_delete,
        )

        result = {
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "algorithm": metadata.algorithm,
            "kdf": metadata.kdf_algorithm,
        }

        if remove_source:
            result["source_removed"] = True
            result["secure_delete"] = secure_delete

        output_json(result)

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
            help="Decryption password (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    remove_source: Annotated[
        bool,
        typer.Option(
            "--remove-source",
            help="Delete encrypted file after successful decryption",
        )
    ] = False,
    secure_delete: Annotated[
        bool,
        typer.Option(
            "--secure-delete/--no-secure-delete",
            help="Securely overwrite encrypted file before deletion (when --remove-source is used)",
        )
    ] = True,
) -> None:
    """Decrypt a file encrypted with Filanti.

    Verifies integrity before writing output.

    Supports multiple secret resolution formats:
        filanti decrypt file.enc --password ENV:MY_PASSWORD
        filanti decrypt file.enc --password '$env:MY_PASSWORD'  # PowerShell
        filanti decrypt file.enc --env MY_PASSWORD              # PowerShell-friendly
        filanti decrypt file.enc --dotenv .env --env-key MY_PASSWORD

    Encrypted file deletion:
        filanti decrypt file.enc --password secret --remove-source
        filanti decrypt file.enc --password secret --remove-source --no-secure-delete
    """
    try:
        # Resolve password using helper
        try:
            resolved_password = resolve_password_from_options(
                password=password,
                env_var=env_var,
                dotenv_path=dotenv,
                env_key=env_key,
                prompt=True,
                confirm=False,
                prompt_text="Password",
            )
        except SecretError as e:
            output_error(str(e))
            return

        if resolved_password is None:
            return  # Error already output

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
            password=resolved_password,
        )

        # Remove encrypted source file if requested (after successful decryption)
        if remove_source:
            from filanti.core.file_manager import get_file_manager
            fm = get_file_manager()
            if secure_delete:
                fm.secure_delete(file)
            else:
                fm.delete(file)

        result = {
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "size": size,
        }

        if remove_source:
            result["source_removed"] = True
            result["secure_delete"] = secure_delete

        output_json(result)

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


# =============================================================================
# INTEGRITY COMMANDS (MAC)
# =============================================================================


@app.command()
def mac(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to compute MAC for",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    key: Annotated[
        Optional[str],
        typer.Option(
            "--key", "-k",
            help="Secret key for HMAC (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="MAC algorithm (hmac-sha256, hmac-sha384, hmac-sha512)",
        )
    ] = "hmac-sha256",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Create detached .mac file at this path",
        )
    ] = None,
    create_file: Annotated[
        bool,
        typer.Option(
            "--create-file", "-c",
            help="Create detached integrity file (.mac)",
        )
    ] = False,
    minimal: Annotated[
        bool,
        typer.Option(
            "--minimal",
            help="Use minimal metadata format (reduces information leakage - no filename, size, timestamp)",
        )
    ] = False,
) -> None:
    """Compute HMAC of a file for integrity verification.

    Supported algorithms: hmac-sha256, hmac-sha384, hmac-sha512, hmac-sha3-256, hmac-blake2b

    Supports multiple secret resolution formats:
        filanti mac file.txt --key ENV:HMAC_KEY
        filanti mac file.txt --key '$env:HMAC_KEY'   # PowerShell
        filanti mac file.txt --env HMAC_KEY          # PowerShell-friendly
        filanti mac file.txt --dotenv .env --env-key HMAC_KEY

    Minimal metadata format (for security):
        filanti mac file.txt --key secret --create-file --minimal
    """
    try:
        # Resolve key using helper (no prompting for MAC key)
        try:
            resolved_key = resolve_key_from_options(
                key=key,
                env_var=env_var,
                dotenv_path=dotenv,
                env_key=env_key,
            )
        except SecretError as e:
            output_error(str(e))
            return

        if resolved_key is None:
            output_error("Secret key is required. Use --key, --env, or --env-key")
            return

        # Parse key - try hex first, then treat as text
        try:
            key_bytes = bytes.fromhex(resolved_key)
        except ValueError:
            key_bytes = resolved_key.encode("utf-8")

        if create_file or output:
            # Create detached integrity file
            mac_path = create_integrity_file(
                file,
                key_bytes,
                algorithm,
                output,
                minimal=minimal,
            )
            result_data = {
                "success": True,
                "file": str(file.resolve()),
                "algorithm": algorithm.lower(),
                "mac_file": str(mac_path.resolve()),
            }
            if minimal:
                result_data["format"] = "minimal"
            output_json(result_data)
        else:
            # Just compute and display MAC
            result = compute_file_mac(file, key_bytes, algorithm)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "algorithm": result.algorithm,
                "mac": result.to_hex(),
                "created_at": result.created_at,
            })

    except Exception as e:
        output_error(str(e))


@app.command(name="verify-mac")
def verify_mac_cmd(
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
    key: Annotated[
        Optional[str],
        typer.Option(
            "--key", "-k",
            help="Secret key for HMAC (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    expected: Annotated[
        Optional[str],
        typer.Option(
            "--expected", "-e",
            help="Expected MAC value (hex)",
        )
    ] = None,
    mac_file: Annotated[
        Optional[Path],
        typer.Option(
            "--mac-file", "-m",
            help="Path to .mac metadata file",
        )
    ] = None,
) -> None:
    """Verify file integrity using HMAC.

    Either provide --expected MAC value or --mac-file with detached metadata.

    Supports multiple secret resolution formats:
        filanti verify-mac file.txt --key ENV:HMAC_KEY
        filanti verify-mac file.txt --key '$env:HMAC_KEY'  # PowerShell
        filanti verify-mac file.txt --env HMAC_KEY         # PowerShell-friendly
        filanti verify-mac file.txt --dotenv .env --env-key HMAC_KEY
    """
    try:
        # Resolve key using helper
        try:
            resolved_key = resolve_key_from_options(
                key=key,
                env_var=env_var,
                dotenv_path=dotenv,
                env_key=env_key,
            )
        except SecretError as e:
            output_error(str(e))
            return

        if resolved_key is None:
            output_error("Secret key is required. Use --key, --env, or --env-key")
            return

        # Parse key
        try:
            key_bytes = bytes.fromhex(resolved_key)
        except ValueError:
            key_bytes = resolved_key.encode("utf-8")

        if mac_file or (not expected):
            # Verify using metadata file
            is_valid = verify_integrity_file(file, key_bytes, mac_file)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "valid": is_valid,
                "mac_file": str((mac_file or file.with_suffix(file.suffix + ".mac")).resolve()),
            })
        else:
            # Verify against expected value
            expected_bytes = bytes.fromhex(expected)
            is_valid = verify_file_mac(file, expected_bytes, key_bytes)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "valid": is_valid,
                "expected": expected,
            })

    except Exception as e:
        output_error(str(e))


# =============================================================================
# SIGNATURE COMMANDS
# =============================================================================


@app.command(name="keygen")
def keygen(
    output: Annotated[
        Path,
        typer.Argument(
            help="Output path for private key (public key will be .pub)",
        )
    ],
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Signature algorithm (ed25519, ecdsa-p256, ecdsa-p384, ecdsa-p521)",
        )
    ] = "ed25519",
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Password to protect private key (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    protect: Annotated[
        bool,
        typer.Option(
            "--protect",
            help="Encrypt private key with password",
        )
    ] = False,
) -> None:
    """Generate a new signing key pair.

    Creates private key at OUTPUT and public key at OUTPUT.pub

    Supports multiple secret resolution formats:
        filanti keygen mykey --protect --password ENV:KEY_PASSWORD
        filanti keygen mykey --protect --password '$env:KEY_PASSWORD'  # PowerShell
        filanti keygen mykey --protect --env KEY_PASSWORD              # PowerShell-friendly
        filanti keygen mykey --protect --dotenv .env --env-key KEY_PASSWORD
    """
    try:
        # Resolve password using helper
        resolved_password = None
        if password is not None or env_var is not None or env_key is not None:
            try:
                resolved_password = resolve_password_from_options(
                    password=password,
                    env_var=env_var,
                    dotenv_path=dotenv,
                    env_key=env_key,
                    prompt=False,
                    confirm=False,
                )
            except SecretError as e:
                output_error(str(e))
                return

        # Handle password - prompt if protect is set but no password provided
        if protect and resolved_password is None:
            resolved_password = typer.prompt("Password", hide_input=True)
            confirm = typer.prompt("Confirm password", hide_input=True)
            if resolved_password != confirm:
                output_error("Passwords do not match")
                return

        password_bytes = resolved_password.encode("utf-8") if resolved_password else None

        # Generate keypair
        keypair = generate_keypair(algorithm, password_bytes)

        # Save to files
        priv_path, pub_path = save_keypair(keypair, output)

        output_json({
            "success": True,
            "algorithm": keypair.algorithm,
            "private_key": str(priv_path.resolve()),
            "public_key": str(pub_path.resolve()),
            "encrypted": protect or (resolved_password is not None),
        })

    except Exception as e:
        output_error(str(e))


@app.command()
def sign(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to sign",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
    key: Annotated[
        Path,
        typer.Option(
            "--key", "-k",
            help="Path to private key file",
            exists=True,
        )
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output path for signature file (default: file.sig)",
        )
    ] = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Signature algorithm",
        )
    ] = "ed25519",
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Password for encrypted private key (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    embed_key: Annotated[
        bool,
        typer.Option(
            "--embed-key",
            help="Embed public key in signature file",
        )
    ] = True,
) -> None:
    """Sign a file with a private key.

    Creates a detached signature file (.sig) containing the signature and metadata.

    Supports multiple secret resolution formats:
        filanti sign file.txt --key mykey --password ENV:KEY_PASSWORD
        filanti sign file.txt --key mykey --password '$env:KEY_PASSWORD'  # PowerShell
        filanti sign file.txt --key mykey --env KEY_PASSWORD              # PowerShell-friendly
        filanti sign file.txt --key mykey --dotenv .env --env-key KEY_PASSWORD
    """
    try:
        # Resolve password using helper
        resolved_password = None
        if password is not None or env_var is not None or env_key is not None:
            try:
                resolved_password = resolve_password_from_options(
                    password=password,
                    env_var=env_var,
                    dotenv_path=dotenv,
                    env_key=env_key,
                    prompt=False,
                    confirm=False,
                )
            except SecretError as e:
                output_error(str(e))
                return

        # Read private key
        private_key = key.read_bytes()
        password_bytes = resolved_password.encode("utf-8") if resolved_password else None

        # Create signature file
        sig_path = create_signature_file(
            file,
            private_key,
            algorithm,
            password_bytes,
            output,
            include_public_key=embed_key,
        )

        output_json({
            "success": True,
            "file": str(file.resolve()),
            "signature_file": str(sig_path.resolve()),
            "algorithm": algorithm,
            "public_key_embedded": embed_key,
        })

    except Exception as e:
        output_error(str(e))


@app.command(name="verify-sig")
def verify_sig(
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
    signature: Annotated[
        Optional[Path],
        typer.Option(
            "--signature", "-s",
            help="Path to signature file (default: file.sig)",
        )
    ] = None,
    key: Annotated[
        Optional[Path],
        typer.Option(
            "--key", "-k",
            help="Path to public key file (uses embedded key if not provided)",
            exists=True,
        )
    ] = None,
) -> None:
    """Verify a file's digital signature.

    Uses the embedded public key in the signature file, or provide one with --key.
    """
    try:
        # Read public key if provided
        public_key = key.read_bytes() if key else None

        # Verify
        is_valid = verify_signature_file(file, signature, public_key)

        sig_path = signature or file.with_suffix(file.suffix + ".sig")

        output_json({
            "success": True,
            "file": str(file.resolve()),
            "signature_file": str(sig_path.resolve()),
            "valid": is_valid,
            "public_key_source": "provided" if key else "embedded",
        })

    except Exception as e:
        output_error(str(e))


# =============================================================================
# CHECKSUM COMMANDS
# =============================================================================


@app.command()
def checksum(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to file to checksum",
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
            help="Checksum algorithm (crc32, adler32, xxhash64)",
        )
    ] = "crc32",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Create detached checksum file",
        )
    ] = None,
    create_file: Annotated[
        bool,
        typer.Option(
            "--create-file", "-c",
            help="Create detached checksum file (.checksum)",
        )
    ] = False,
) -> None:
    """Compute checksum of a file (non-cryptographic).

    Fast checksums for detecting accidental corruption.
    NOT suitable for security purposes - use 'hash' or 'mac' instead.
    """
    try:
        if create_file or output:
            checksum_path = create_checksum_file(file, algorithm, output)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "algorithm": algorithm.lower(),
                "checksum_file": str(checksum_path.resolve()),
            })
        else:
            result = compute_file_checksum(file, algorithm)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "algorithm": result.algorithm,
                "checksum": result.to_hex(),
                "checksum_int": result.checksum,
            })

    except Exception as e:
        output_error(str(e))


@app.command(name="verify-checksum")
def verify_checksum_cmd(
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
        Optional[str],
        typer.Option(
            "--expected", "-e",
            help="Expected checksum value (hex or integer)",
        )
    ] = None,
    checksum_file: Annotated[
        Optional[Path],
        typer.Option(
            "--checksum-file", "-c",
            help="Path to .checksum metadata file",
        )
    ] = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Checksum algorithm",
        )
    ] = "crc32",
) -> None:
    """Verify file checksum.

    Either provide --expected value or --checksum-file with detached metadata.
    """
    try:
        if checksum_file or (not expected):
            # Verify using metadata file
            is_valid = verify_checksum_file(file, checksum_file)
            chk_path = checksum_file or file.with_suffix(file.suffix + ".checksum")
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "valid": is_valid,
                "checksum_file": str(chk_path.resolve()),
            })
        else:
            # Parse expected value (hex or int)
            try:
                expected_int = int(expected, 16) if expected.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in expected) else int(expected)
            except ValueError:
                expected_int = int(expected, 16)

            is_valid = verify_file_checksum(file, expected_int, algorithm)
            output_json({
                "success": True,
                "file": str(file.resolve()),
                "valid": is_valid,
                "expected": expected,
            })

    except Exception as e:
        output_error(str(e))


# =============================================================================
# ASYMMETRIC / HYBRID ENCRYPTION COMMANDS
# =============================================================================


@app.command(name="keygen-asymmetric")
def keygen_asymmetric(
    output: Annotated[
        Path,
        typer.Argument(
            help="Output path for private key (public key will be .pub)",
        )
    ],
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Key exchange algorithm (x25519, rsa-oaep)",
        )
    ] = "x25519",
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Password to protect private key (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    protect: Annotated[
        bool,
        typer.Option(
            "--protect",
            help="Encrypt private key with password",
        )
    ] = False,
    rsa_size: Annotated[
        int,
        typer.Option(
            "--rsa-size",
            help="RSA key size in bits (only for rsa-oaep)",
        )
    ] = 4096,
) -> None:
    """Generate asymmetric key pair for hybrid encryption.

    Creates private key at OUTPUT and public key at OUTPUT.pub

    X25519 is recommended for most use cases (fast, secure, compact keys).
    RSA-OAEP is provided for compatibility.

    Supports multiple secret resolution formats:
        filanti keygen-asymmetric mykey --protect --password ENV:KEY_PASSWORD
        filanti keygen-asymmetric mykey --protect --password '$env:KEY_PASSWORD'  # PowerShell
        filanti keygen-asymmetric mykey --protect --env KEY_PASSWORD              # PowerShell-friendly
        filanti keygen-asymmetric mykey --protect --dotenv .env --env-key KEY_PASSWORD
    """
    try:
        # Resolve password using helper
        resolved_password = None
        if password is not None or env_var is not None or env_key is not None:
            try:
                resolved_password = resolve_password_from_options(
                    password=password,
                    env_var=env_var,
                    dotenv_path=dotenv,
                    env_key=env_key,
                    prompt=False,
                    confirm=False,
                )
            except SecretError as e:
                output_error(str(e))
                return

        # Handle password - prompt if protect is set but no password provided
        if protect and resolved_password is None:
            resolved_password = typer.prompt("Password", hide_input=True)
            confirm = typer.prompt("Confirm password", hide_input=True)
            if resolved_password != confirm:
                output_error("Passwords do not match")
                return

        password_bytes = resolved_password.encode("utf-8") if resolved_password else None

        # Generate keypair
        keypair = generate_asymmetric_keypair(algorithm, password_bytes, rsa_size)

        # Save to files
        priv_path, pub_path = save_asymmetric_keypair(keypair, output)

        output_json({
            "success": True,
            "algorithm": keypair.algorithm,
            "private_key": str(priv_path.resolve()),
            "public_key": str(pub_path.resolve()),
            "encrypted": protect or (resolved_password is not None),
        })

    except Exception as e:
        output_error(str(e))


@app.command(name="encrypt-pubkey")
def encrypt_pubkey(
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
    pubkey: Annotated[
        list[Path],
        typer.Option(
            "--pubkey", "-k",
            help="Path to recipient public key (can specify multiple)",
        )
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output path (default: input.henc)",
        )
    ] = None,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm", "-a",
            help="Key exchange algorithm (x25519, rsa-oaep)",
        )
    ] = "x25519",
    recipient_id: Annotated[
        Optional[list[str]],
        typer.Option(
            "--recipient-id", "-r",
            help="Recipient identifier (one per pubkey, in order)",
        )
    ] = None,
    remove_source: Annotated[
        bool,
        typer.Option(
            "--remove-source",
            help="Delete original file after successful encryption",
        )
    ] = False,
    secure_delete: Annotated[
        bool,
        typer.Option(
            "--secure-delete/--no-secure-delete",
            help="Securely overwrite original file before deletion (when --remove-source is used)",
        )
    ] = True,
) -> None:
    """Encrypt a file for specific recipients using public keys.

    Uses hybrid encryption: asymmetric key exchange + symmetric AEAD.
    Supports multi-recipient encryption - each recipient can decrypt with their private key.

    Examples:
        # Encrypt for single recipient
        filanti encrypt-pubkey secret.txt --pubkey alice.pub

        # Encrypt for multiple recipients
        filanti encrypt-pubkey secret.txt --pubkey alice.pub --pubkey bob.pub

        # With recipient IDs
        filanti encrypt-pubkey secret.txt --pubkey alice.pub -r alice --pubkey bob.pub -r bob

        # With source file removal
        filanti encrypt-pubkey secret.txt --pubkey alice.pub --remove-source
    """
    try:
        # Validate pubkeys
        if not pubkey:
            output_error("At least one --pubkey is required")
            return

        # Validate recipient IDs count if provided
        if recipient_id and len(recipient_id) != len(pubkey):
            output_error("Number of --recipient-id must match number of --pubkey")
            return

        # Convert paths to strings for the function
        pubkey_paths = [str(p) for p in pubkey]

        # Determine output path
        out_path = output or Path(str(file) + ".henc")

        # Parse algorithm
        try:
            asym_alg = AsymmetricAlgorithm(algorithm.lower())
        except ValueError:
            output_error(f"Unsupported algorithm: {algorithm}")
            return

        # Encrypt
        metadata = hybrid_encrypt_file(
            input_path=file,
            output_path=out_path,
            recipient_public_keys=pubkey_paths,
            algorithm=asym_alg,
            recipient_ids=recipient_id,
            remove_source=remove_source,
            secure_delete=secure_delete,
        )

        result = {
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "asymmetric_algorithm": metadata.asymmetric_algorithm,
            "symmetric_algorithm": metadata.symmetric_algorithm,
            "recipient_count": metadata.recipient_count,
        }

        if remove_source:
            result["source_removed"] = True
            result["secure_delete"] = secure_delete

        output_json(result)

    except Exception as e:
        output_error(str(e))


@app.command(name="decrypt-privkey")
def decrypt_privkey(
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
    privkey: Annotated[
        Path,
        typer.Option(
            "--privkey", "-k",
            help="Path to private key file",
            exists=True,
        )
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output", "-o",
            help="Output path (default: removes .henc extension)",
        )
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password", "-p",
            help="Password for encrypted private key (supports: ENV:VAR, $env:VAR, ${VAR}, env.VAR)",
        )
    ] = None,
    env_var: EnvVarOption = None,
    dotenv: DotenvOption = None,
    env_key: EnvKeyOption = None,
    recipient_id: Annotated[
        Optional[str],
        typer.Option(
            "--recipient-id", "-r",
            help="Recipient ID to use for decryption (for multi-recipient files)",
        )
    ] = None,
    remove_source: Annotated[
        bool,
        typer.Option(
            "--remove-source",
            help="Delete encrypted file after successful decryption",
        )
    ] = False,
    secure_delete: Annotated[
        bool,
        typer.Option(
            "--secure-delete/--no-secure-delete",
            help="Securely overwrite encrypted file before deletion (when --remove-source is used)",
        )
    ] = True,
) -> None:
    """Decrypt a file encrypted with public key encryption.

    Decrypts files created with 'encrypt-pubkey' command.

    Supports multiple secret resolution formats:
        filanti decrypt-privkey file.henc --privkey mykey --password ENV:KEY_PASSWORD
        filanti decrypt-privkey file.henc --privkey mykey --password '$env:KEY_PASSWORD'  # PowerShell
        filanti decrypt-privkey file.henc --privkey mykey --env KEY_PASSWORD              # PowerShell-friendly
        filanti decrypt-privkey file.henc --privkey mykey --dotenv .env --env-key KEY_PASSWORD

    Examples:
        # Basic decryption
        filanti decrypt-privkey secret.txt.henc --privkey mykey.pem

        # With encrypted private key
        filanti decrypt-privkey secret.txt.henc --privkey mykey.pem --password mypass

        # Remove encrypted file after decryption
        filanti decrypt-privkey secret.txt.henc --privkey mykey.pem --remove-source
    """
    try:
        # Resolve password using helper
        resolved_password = None
        if password is not None or env_var is not None or env_key is not None:
            try:
                resolved_password = resolve_password_from_options(
                    password=password,
                    env_var=env_var,
                    dotenv_path=dotenv,
                    env_key=env_key,
                    prompt=False,
                    confirm=False,
                )
            except SecretError as e:
                output_error(str(e))
                return

        password_bytes = resolved_password.encode("utf-8") if resolved_password else None

        # Determine output path
        if output is None:
            file_str = str(file)
            if file_str.endswith(".henc"):
                out_path = Path(file_str[:-5])
            else:
                out_path = Path(file_str + ".dec")
        else:
            out_path = output

        # Decrypt
        size = hybrid_decrypt_file(
            input_path=file,
            output_path=out_path,
            private_key=str(privkey),
            password=password_bytes,
            recipient_id=recipient_id,
        )

        # Remove encrypted source file if requested (after successful decryption)
        if remove_source:
            from filanti.core.file_manager import get_file_manager
            fm = get_file_manager()
            if secure_delete:
                fm.secure_delete(file)
            else:
                fm.delete(file)

        result = {
            "success": True,
            "input": str(file.resolve()),
            "output": str(out_path.resolve()),
            "size": size,
        }

        if remove_source:
            result["source_removed"] = True
            result["secure_delete"] = secure_delete

        output_json(result)

    except Exception as e:
        output_error(str(e))


@app.command(name="info-hybrid")
def info_hybrid(
    file: Annotated[
        Path,
        typer.Argument(
            help="Path to hybrid encrypted file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        )
    ],
) -> None:
    """Show metadata from a hybrid encrypted file."""
    try:
        metadata = get_hybrid_file_metadata(file)

        output_json({
            "success": True,
            "file": str(file.resolve()),
            "version": metadata.version,
            "asymmetric_algorithm": metadata.asymmetric_algorithm,
            "symmetric_algorithm": metadata.symmetric_algorithm,
            "recipient_count": metadata.recipient_count,
            "created_at": metadata.created_at,
        })

    except Exception as e:
        output_error(str(e))


# =============================================================================
# SUPPORTED ALGORITHMS
# =============================================================================


@app.command(name="list-algorithms")
def list_algorithms() -> None:
    """List all supported algorithms for each operation."""
    output_json({
        "success": True,
        "hash": {
            "algorithms": crypto_hash.get_supported_algorithms(),
            "default": crypto_hash.DEFAULT_ALGORITHM.value,
        },
        "encryption": {
            "algorithms": [e.value for e in EncryptionAlgorithm],
            "default": "aes-256-gcm",
        },
        "asymmetric": {
            "algorithms": get_supported_asymmetric_algorithms(),
            "default": "x25519",
        },
        "mac": {
            "algorithms": [m.value for m in MACAlgorithm],
            "default": "hmac-sha256",
        },
        "signature": {
            "algorithms": [s.value for s in SignatureAlgorithm],
            "default": "ed25519",
        },
        "checksum": {
            "algorithms": [c.value for c in ChecksumAlgorithm],
            "default": "crc32",
        },
    })


def main() -> None:
    """Main entry point for CLI."""
    app()


if __name__ == "__main__":
    main()