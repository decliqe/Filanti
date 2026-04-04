"""
Filanti v2 REPL — Stateful interactive command shell.

Launched with ``filanti`` or ``python -m filanti``.

Supports session state (mode, policy, key provider) and
routes every operation through the Orchestrator.
"""

from __future__ import annotations

import os
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from filanti import __version__
from filanti.core.orchestrator import Orchestrator
from filanti.policy.engine import PolicyEngine
from filanti.threat.engine import ThreatEngine

# ------------------------------------------------------------------
# Readline (optional — graceful fallback if unavailable)
# ------------------------------------------------------------------

try:
    import readline
except ImportError:
    readline = None  # type: ignore[assignment]

_HAS_READLINE = readline is not None

# ------------------------------------------------------------------
# ANSI colors (disabled when output is not a terminal)
# ------------------------------------------------------------------


class _Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    CYAN = "\033[36m"
    DIM = "\033[2m"

    @classmethod
    def strip(cls) -> None:
        """Disable all color codes (for non-TTY output)."""
        for attr in ("RESET", "BOLD", "GREEN", "YELLOW", "RED", "CYAN", "DIM"):
            setattr(cls, attr, "")


# Disable colors when stdout is not a terminal
if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
    _Colors.strip()

C = _Colors

# ------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------

BANNER = rf"""
{C.CYAN}{C.BOLD}███████╗██╗██╗      █████╗ ███╗   ██╗████████╗██╗
██╔════╝██║██║     ██╔══██╗████╗  ██║╚══██╔══╝██║
█████╗  ██║██║     ███████║██╔██╗ ██║   ██║   ██║
██╔══╝  ██║██║     ██╔══██║██║╚██╗██║   ██║   ██║
██║     ██║███████╗██║  ██║██║ ╚████║   ██║   ██║
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝{C.RESET}
{C.DIM}A secure cryptographic file execution platform
            with policy enforcement,
    key management, and stateful control  ·  v2{C.RESET}
"""

PROMPT = f"{C.GREEN}{C.BOLD}filanti>{C.RESET} "

HISTORY_FILE = Path.home() / ".filanti_history"
HISTORY_MAX = 1000

# ------------------------------------------------------------------
# Per-command help text
# ------------------------------------------------------------------

COMMAND_HELP: dict[str, str] = {
    "encrypt": (
        "Encrypt a file using password-based encryption (Argon2id KDF + AEAD).\n"
        "  Usage: encrypt <file> --password <PW> [--output OUT] [--algorithm ALG]\n"
        "         [--remove-source] [--no-secure-delete]\n"
        "  Example: encrypt secrets.txt --password mypass\n"
        "           encrypt data.bin -p mypass --algorithm chacha20-poly1305\n"
        "           encrypt old.txt --password s3cr3t --remove-source\n"
        "  Algorithms: aes-256-gcm (default), chacha20-poly1305"
    ),
    "decrypt": (
        "Decrypt a file previously encrypted with Filanti.\n"
        "  Usage: decrypt <file> --password <PW> [--output OUT]\n"
        "         [--remove-source] [--no-secure-delete]\n"
        "  Example: decrypt secrets.txt.enc --password mypass\n"
        "           decrypt data.bin.enc -p mypass -o restored.bin\n"
        "           decrypt old.txt.enc --password s3cr3t --remove-source"
    ),
    "hash": (
        "Compute a cryptographic hash digest of a file.\n"
        "  Usage: hash <file> [algorithm]\n"
        "  Example: hash report.pdf sha3-256\n"
        "  Algorithms: sha256 (default), sha384, sha512, sha3-256, sha3-512, blake2b"
    ),
    "verify-hash": (
        "Verify a file's hash against an expected value.\n"
        "  Usage: verify-hash <file> <expected_hash> [algorithm]\n"
        "  Example: verify-hash report.pdf abc123def... sha256"
    ),
    "sign": (
        "Sign a file with a private key (Ed25519).\n"
        "  Usage: sign <file> --key-ref <private_key_file>\n"
        "  Example: sign document.pdf --key-ref mykey"
    ),
    "verify": (
        "Verify a file's digital signature.\n"
        "  Usage: verify <file> --sig <hex> --key-ref <public_key_file>\n"
        "  Example: verify document.pdf --sig a1b2c3... --key-ref mykey.pub"
    ),
    "mac": (
        "Compute HMAC of a file for integrity verification.\n"
        "  Usage: mac <file> --password <hex_key> [--algorithm ALG]\n"
        "  Example: mac data.bin --password 0a1b2c3d...\n"
        "  Algorithms: hmac-sha256 (default), hmac-sha512, hmac-blake2b"
    ),
    "verify-mac": (
        "Verify the HMAC of a file.\n"
        "  Usage: verify-mac <file> --password <hex_key> --mac <hex> [--algorithm ALG]\n"
        "  Example: verify-mac data.bin --password 0a1b2c... --mac deadbeef..."
    ),
    "checksum": (
        "Compute a fast non-cryptographic checksum.\n"
        "  Usage: checksum <file> [algorithm]\n"
        "  Example: checksum archive.tar.gz adler32\n"
        "  Algorithms: sha256 (default), crc32, adler32"
    ),
    "verify-checksum": (
        "Verify a file's checksum against an expected value.\n"
        "  Usage: verify-checksum <file> <expected> [algorithm]\n"
        "  Example: verify-checksum archive.tar.gz 0x1a2b3c4d crc32"
    ),
    "keygen": (
        "Generate a signing key pair (Ed25519 / ECDSA).\n"
        "  Usage: keygen <output_path> [--algorithm ALG] [--password PW]\n"
        "  Example: keygen mykey\n"
        "           keygen mykey --algorithm ecdsa-p256\n"
        "           keygen mykey --password s3cr3t\n"
        "  Creates: <output_path> (private) + <output_path>.pub (public)\n"
        "  Algorithms: ed25519 (default), ecdsa-p256, ecdsa-p384, ecdsa-p521"
    ),
    "keygen-asymmetric": (
        "Generate an asymmetric key pair for hybrid encryption (X25519 / RSA).\n"
        "  Usage: keygen-asymmetric <output_path> [--algorithm ALG] [--password PW]\n"
        "  Example: keygen-asymmetric mykey\n"
        "           keygen-asymmetric mykey --algorithm rsa-oaep\n"
        "           keygen-asymmetric mykey --password s3cr3t\n"
        "  Creates: <output_path>.pem (private) + <output_path>.pub (public)\n"
        "  Algorithms: x25519 (default), rsa-oaep"
    ),
    "encrypt-pubkey": (
        "Encrypt a file for recipients using their public keys (hybrid encryption).\n"
        "  Usage: encrypt-pubkey <file> --pubkey <key.pub> [--pubkey <key2.pub>] [--output OUT]\n"
        "  Example: encrypt-pubkey secret.txt --pubkey alice.pub\n"
        "           encrypt-pubkey secret.txt --pubkey alice.pub --pubkey bob.pub\n"
        "  Creates a .henc file that only the private-key holder can decrypt."
    ),
    "decrypt-privkey": (
        "Decrypt a hybrid encrypted (.henc) file with a private key.\n"
        "  Usage: decrypt-privkey <file.henc> --key-ref <key.pem> [--password PW] [--output OUT]\n"
        "  Example: decrypt-privkey secret.txt.henc --key-ref mykey.pem\n"
        "           decrypt-privkey secret.txt.henc --key-ref mykey.pem --password keypass"
    ),
    "info-hybrid": (
        "Show metadata from a hybrid encrypted (.henc) file.\n"
        "  Usage: info-hybrid <file.henc>\n"
        "  Example: info-hybrid secret.txt.henc\n"
        "  Displays algorithm, recipient count, and creation timestamp."
    ),
    "algorithms": (
        "List all supported algorithms by category.\n"
        "  Usage: algorithms\n"
        "  Shows: encryption, hashing, MAC, signature, checksum, asymmetric algorithms."
    ),
    "version": "Show the current Filanti version.",
    "set": (
        "Change session settings.\n"
        "  Usage: set mode <name>    — change threat mode (dev, production, paranoid)\n"
        "         set policy <name>  — change policy (default, enterprise, relaxed)\n"
        "  Modes control encryption strength, KDF parameters, and hashing defaults.\n"
        "  Policies enforce minimum password length, algorithm restrictions, etc."
    ),
    "use": "Alias for 'set'. Usage: use policy <name>",
    "status": "Show current session state (mode, policy, provider, history count).",
    "history": "Show command history for this session.",
    "modes": "List available threat modes with their security characteristics.",
    "policies": "List available policies with their enforcement rules.",
    "clear": "Clear the terminal screen.",
    "exit": "Exit the REPL (also: quit, Ctrl-D).",
    "quit": "Exit the REPL (also: exit, Ctrl-D).",
    "help": "Show command list, or 'help <command>' for details.",
    "kms": (
        "Key Management System — envelope encryption with master keys.\n"
        "  kms status                 — show KMS provider info\n"
        "  kms create-key <key_id>    — create a new master key\n"
        "  kms list                   — list available master keys\n"
        "  kms encrypt <file> <key_id> [--output OUT]\n"
        "  kms decrypt <file> <key_id> <wrapped_hex> [--output OUT]\n"
        "\n"
        "  How it works:\n"
        "    1. Create a master key:  kms create-key myapp\n"
        "    2. Encrypt a file:       kms encrypt secret.txt myapp\n"
        "       (outputs a wrapped key hex — save it!)\n"
        "    3. Decrypt later:        kms decrypt secret.txt.enc myapp <wrapped_hex>\n"
        "\n"
        "  Master keys stored in ~/.filanti/keys/ (local provider).\n"
        "  Data keys are generated per-file and wrapped with the master key."
    ),
}

# ------------------------------------------------------------------
# Session state
# ------------------------------------------------------------------


@dataclass
class Session:
    """Persistent state for one REPL session."""

    mode: str = "production"
    policy: str = "default"
    key_provider: str = "local"
    history: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# Tab-completion
# ------------------------------------------------------------------

# Top-level command names (populated once from REPL handler methods)
_COMMANDS: list[str] = sorted(COMMAND_HELP.keys())

# Sub-completions for two-word commands
_SUB_COMPLETIONS: dict[str, list[str]] = {
    "set": ["mode", "policy"],
    "use": ["mode", "policy"],
    "help": _COMMANDS,
    "kms": ["status", "create-key", "list", "encrypt", "decrypt"],
}

# Flag completions per command
_FLAG_COMPLETIONS: dict[str, list[str]] = {
    "encrypt": ["--password", "--output", "--algorithm", "--remove-source", "--no-secure-delete"],
    "decrypt": ["--password", "--output", "--remove-source", "--no-secure-delete"],
    "sign": ["--key-ref"],
    "verify": ["--sig", "--key-ref"],
    "mac": ["--password", "--algorithm"],
    "verify-mac": ["--password", "--mac", "--algorithm"],
    "checksum": [],
    "verify-checksum": [],
    "keygen": ["--algorithm", "--password"],
    "keygen-asymmetric": ["--algorithm", "--password"],
    "encrypt-pubkey": ["--pubkey", "--output", "--algorithm"],
    "decrypt-privkey": ["--key-ref", "--password", "--output"],
}

# Algorithm values per command
_ALGORITHM_VALUES: dict[str, list[str]] = {
    "encrypt": ["aes-256-gcm", "chacha20-poly1305"],
    "hash": ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512", "blake2b"],
    "verify-hash": ["sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512", "blake2b"],
    "mac": ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha3-256", "hmac-blake2b"],
    "verify-mac": ["hmac-sha256", "hmac-sha384", "hmac-sha512", "hmac-sha3-256", "hmac-blake2b"],
    "checksum": ["sha256", "crc32", "adler32", "xxhash64"],
    "verify-checksum": ["sha256", "crc32", "adler32", "xxhash64"],
    "keygen": ["ed25519", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521"],
    "keygen-asymmetric": ["x25519", "rsa-oaep"],
    "encrypt-pubkey": ["x25519", "rsa-oaep"],
}


class _Completer:
    """readline tab-completer for the REPL."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._matches: list[str] = []

    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            line = readline.get_line_buffer() if readline is not None else ""
            stripped = line.lstrip()
            parts = stripped.split()
            n_parts = len(parts)

            # If we're still typing the first word (or line is empty)
            if n_parts == 0 or (n_parts == 1 and not stripped.endswith(" ")):
                self._matches = [c + " " for c in _COMMANDS if c.startswith(text)]
            elif n_parts >= 1:
                cmd = parts[0].lower()

                # Second token completion for sub-commands
                if cmd in _SUB_COMPLETIONS and (n_parts == 1 or (n_parts == 2 and not stripped.endswith(" "))):
                    subs = _SUB_COMPLETIONS[cmd]
                    self._matches = [s + " " for s in subs if s.startswith(text)]
                elif cmd in ("set", "use") and n_parts >= 2:
                    subcmd = parts[1].lower()
                    # Third token: mode/policy values
                    if subcmd == "mode":
                        modes = ThreatEngine.available()
                        self._matches = [m + " " for m in modes if m.startswith(text)]
                    elif subcmd == "policy":
                        policies = PolicyEngine.available()
                        self._matches = [p + " " for p in policies if p.startswith(text)]
                    else:
                        self._matches = []
                elif text.startswith("-") and cmd in _FLAG_COMPLETIONS:
                    # Complete flag names
                    flags = _FLAG_COMPLETIONS[cmd]
                    self._matches = [f + " " for f in flags if f.startswith(text)]
                elif n_parts >= 2 and parts[-1 if not stripped.endswith(" ") else -2] in ("--algorithm", "-a"):
                    # Complete algorithm values
                    if cmd in _ALGORITHM_VALUES:
                        self._matches = [a + " " for a in _ALGORITHM_VALUES[cmd] if a.startswith(text)]
                    else:
                        self._matches = []
                else:
                    # File path completion
                    self._matches = self._complete_path(text)
            else:
                self._matches = []

        return self._matches[state] if state < len(self._matches) else None

    @staticmethod
    def _complete_path(text: str) -> list[str]:
        """Complete file/directory paths."""
        if not text:
            p = Path(".")
            prefix = ""
        else:
            p = Path(text)
            prefix = text

        try:
            if p.is_dir() and text.endswith(os.sep):
                children = list(p.iterdir())
            else:
                parent = p.parent if p.parent != p else Path(".")
                children = [c for c in parent.iterdir() if str(c).startswith(prefix)]
        except OSError:
            return []

        matches = []
        for c in sorted(children):
            s = str(c) + (os.sep if c.is_dir() else " ")
            matches.append(s)
        return matches[:50]  # limit to avoid flooding


# ------------------------------------------------------------------
# REPL engine
# ------------------------------------------------------------------


class REPL:
    """Interactive REPL that wraps an ``Orchestrator``."""

    def __init__(
        self,
        orchestrator: Orchestrator | None = None,
        *,
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self._orch = orchestrator or Orchestrator()
        self._session = Session()
        self._stdin: TextIO = stdin or sys.stdin
        self._stdout: TextIO = stdout or sys.stdout
        self._running = False
        self._interactive = (stdin is None) and _HAS_READLINE

    # ------------------------------------------------------------------
    # Readline setup
    # ------------------------------------------------------------------

    def _setup_readline(self) -> None:
        """Configure readline for tab-completion and persistent history."""
        if not self._interactive or readline is None:
            return
        completer = _Completer(self._session)
        readline.set_completer(completer.complete)
        # macOS libedit vs GNU readline
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t")
        # Load history
        try:
            readline.read_history_file(str(HISTORY_FILE))
        except (FileNotFoundError, OSError):
            pass
        readline.set_history_length(HISTORY_MAX)

    def _save_history(self) -> None:
        """Persist readline history to disk."""
        if not self._interactive or readline is None:
            return
        try:
            readline.write_history_file(str(HISTORY_FILE))
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the read-eval-print loop."""
        self._setup_readline()
        self._print(BANNER)
        self._print(f"  mode={self._session.mode}  policy={self._session.policy}")
        self._print("  Type 'help' for commands, 'exit' to quit.\n")
        self._running = True

        while self._running:
            try:
                line = self._readline()
            except (EOFError, KeyboardInterrupt):
                self._save_history()
                self._print("\nBye.")
                break

            line = line.strip()
            if not line:
                continue
            self._session.history.append(line)
            self._eval(line)

    # ------------------------------------------------------------------
    # Command evaluation
    # ------------------------------------------------------------------

    def _eval(self, line: str) -> None:
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            self._print(f"Parse error: {exc}")
            return

        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        # Hyphenated commands → underscore method names
        method_name = f"_cmd_{cmd.replace('-', '_')}"
        handler = getattr(self, method_name, None)
        if handler is not None:
            try:
                handler(args)
            except Exception as exc:
                self._print(f"Error: {exc}")
        else:
            self._print(f"Unknown command: {cmd}. Type 'help'.")

    # ------------------------------------------------------------------
    # Built-in commands
    # ------------------------------------------------------------------

    def _cmd_help(self, args: list[str]) -> None:
        # Per-command help: help <command>
        if args:
            cmd = args[0].lower()
            text = COMMAND_HELP.get(cmd)
            if text:
                self._print(f"\n{C.BOLD}{cmd}{C.RESET}")
                self._print(text)
                self._print("")
            else:
                self._print(f"No help for '{cmd}'. Type 'help' for a command list.")
            return

        self._print(
            f"\n{C.BOLD}Commands:{C.RESET}\n"
            f"  {C.CYAN}set mode <name>{C.RESET}       — change threat mode (dev, production, paranoid)\n"
            f"  {C.CYAN}set policy <name>{C.RESET}     — change active policy (default, enterprise, relaxed)\n"
            f"  {C.CYAN}use policy <name>{C.RESET}     — alias for set policy\n"
            f"\n  {C.BOLD}Encryption:{C.RESET}\n"
            f"  {C.CYAN}encrypt{C.RESET} <file> --password <PW> [--output OUT] [--algorithm ALG]\n"
            f"  {C.CYAN}decrypt{C.RESET} <file> --password <PW> [--output OUT]\n"
            f"\n  {C.BOLD}Hashing:{C.RESET}\n"
            f"  {C.CYAN}hash{C.RESET} <file> [algorithm]         — compute cryptographic hash\n"
            f"  {C.CYAN}verify-hash{C.RESET} <file> <expected> [algorithm]  — verify hash\n"
            f"\n  {C.BOLD}Signatures:{C.RESET}\n"
            f"  {C.CYAN}keygen{C.RESET} <output> [--algorithm ALG]  — generate signing key pair\n"
            f"  {C.CYAN}sign{C.RESET} <file> --key-ref <private_key>\n"
            f"  {C.CYAN}verify{C.RESET} <file> --sig <hex> --key-ref <public_key>\n"
            f"\n  {C.BOLD}Integrity:{C.RESET}\n"
            f"  {C.CYAN}mac{C.RESET} <file> --password <hex_key> [--algorithm ALG]\n"
            f"  {C.CYAN}verify-mac{C.RESET} <file> --password <hex_key> --mac <hex>\n"
            f"  {C.CYAN}checksum{C.RESET} <file> [algorithm]\n"
            f"  {C.CYAN}verify-checksum{C.RESET} <file> <expected> [algorithm]\n"
            f"\n  {C.BOLD}Hybrid / Asymmetric:{C.RESET}\n"
            f"  {C.CYAN}keygen-asymmetric{C.RESET} <output> [--algorithm ALG]  — generate key pair\n"
            f"  {C.CYAN}encrypt-pubkey{C.RESET} <file> --pubkey <key.pub>      — hybrid encrypt\n"
            f"  {C.CYAN}decrypt-privkey{C.RESET} <file.henc> --key-ref <key.pem>  — hybrid decrypt\n"
            f"  {C.CYAN}info-hybrid{C.RESET} <file.henc>      — show .henc metadata\n"
            f"\n  {C.BOLD}KMS & Utility:{C.RESET}\n"
            f"  {C.CYAN}kms{C.RESET} <subcommand>        — key management (create, list, encrypt, decrypt)\n"
            f"  {C.CYAN}algorithms{C.RESET}             — list all supported algorithms\n"
            f"  {C.CYAN}version{C.RESET}                — show Filanti version\n"
            f"  {C.CYAN}status{C.RESET}                 — show session state\n"
            f"  {C.CYAN}history{C.RESET}                — show command history\n"
            f"  {C.CYAN}modes{C.RESET}                  — list available threat modes\n"
            f"  {C.CYAN}policies{C.RESET}               — list available policies\n"
            f"  {C.CYAN}clear{C.RESET}                  — clear the terminal screen\n"
            f"  {C.CYAN}exit{C.RESET} / {C.CYAN}quit{C.RESET}            — exit the REPL\n"
            f"\n  {C.DIM}Tip: Use Tab for auto-completion. Type 'help <command>' for details.{C.RESET}\n"
        )

    def _cmd_exit(self, _args: list[str]) -> None:
        self._save_history()
        self._print("Bye.")
        self._running = False

    def _cmd_quit(self, args: list[str]) -> None:
        self._cmd_exit(args)

    def _cmd_clear(self, _args: list[str]) -> None:
        """Clear the terminal screen."""
        # Use ANSI escape codes directly — avoid os.system() to prevent
        # command injection via PATH manipulation.
        self._stdout.write("\033[2J\033[H")
        self._stdout.flush()

    def _cmd_set(self, args: list[str]) -> None:
        if len(args) < 2:
            self._print("Usage: set <mode|policy> <value>")
            return
        what, value = args[0].lower(), args[1]
        if what == "mode":
            # Validate
            try:
                ThreatEngine.load(value)
            except ValueError as exc:
                self._print(str(exc))
                return
            self._session.mode = value
            self._print(f"Threat mode → {value}")
        elif what == "policy":
            try:
                PolicyEngine.load(value)
            except ValueError as exc:
                self._print(str(exc))
                return
            self._session.policy = value
            self._print(f"Policy → {value}")
        else:
            self._print(f"Unknown setting: {what}")

    def _cmd_use(self, args: list[str]) -> None:
        """Alias for ``set``."""
        self._cmd_set(args)

    def _cmd_status(self, _args: list[str]) -> None:
        s = self._session
        self._print(
            f"  {C.BOLD}mode{C.RESET}     : {C.CYAN}{s.mode}{C.RESET}\n"
            f"  {C.BOLD}policy{C.RESET}   : {C.CYAN}{s.policy}{C.RESET}\n"
            f"  {C.BOLD}provider{C.RESET} : {s.key_provider}\n"
            f"  {C.BOLD}history{C.RESET}  : {len(s.history)} commands"
        )

    def _cmd_history(self, _args: list[str]) -> None:
        for i, h in enumerate(self._session.history, 1):
            self._print(f"  {C.DIM}{i:3d}{C.RESET}  {h}")

    def _cmd_modes(self, _args: list[str]) -> None:
        for m in ThreatEngine.available():
            if m == self._session.mode:
                self._print(f"  {C.GREEN}{m} (active){C.RESET}")
            else:
                self._print(f"  {m}")

    def _cmd_policies(self, _args: list[str]) -> None:
        for p in PolicyEngine.available():
            if p == self._session.policy:
                self._print(f"  {C.GREEN}{p} (active){C.RESET}")
            else:
                self._print(f"  {p}")

    # --- crypto operations ------------------------------------------------

    def _cmd_encrypt(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        if not opts.get("password"):
            self._print(f"{C.RED}Error:{C.RESET} Password required. Usage: encrypt <file> --password <PW>")
            return
        ctx = {
            "input_path": opts["file"],
            "output_path": opts.get("output"),
            "password": opts.get("password"),
            "key_ref": opts.get("key_ref"),
            "algorithm": opts.get("algorithm", "aes-256-gcm"),
            "policy_name": self._session.policy,
            "threat_mode": self._session.mode,
            "remove_source": opts.get("remove_source", False),
            "secure_delete": opts.get("secure_delete", True),
        }
        result = self._orch.execute("encrypt", ctx)
        d = result.to_dict()
        out = d.get("output_path", "")
        alg = d.get("algorithm", "?")
        kdf = d.get("kdf", "")
        self._print(f"{C.GREEN}Encrypted{C.RESET} → {out}  [{alg}]")
        if kdf:
            self._print(f"  KDF: {kdf}")
        if d.get("source_removed"):
            self._print(f"  {C.YELLOW}Source file removed{C.RESET}")

    def _cmd_decrypt(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        if not opts.get("password"):
            self._print(f"{C.RED}Error:{C.RESET} Password required. Usage: decrypt <file> --password <PW>")
            return
        ctx = {
            "input_path": opts["file"],
            "output_path": opts.get("output"),
            "password": opts.get("password"),
            "key_ref": opts.get("key_ref"),
            "policy_name": self._session.policy,
            "threat_mode": self._session.mode,
            "remove_source": opts.get("remove_source", False),
            "secure_delete": opts.get("secure_delete", True),
        }
        result = self._orch.execute("decrypt", ctx)
        d = result.to_dict()
        out = d.get("output_path", "")
        sz = d.get("size", "?")
        self._print(f"{C.GREEN}Decrypted{C.RESET} → {out}  ({sz} bytes)")
        if d.get("source_removed"):
            self._print(f"  {C.YELLOW}Encrypted file removed{C.RESET}")

    def _cmd_hash(self, args: list[str]) -> None:
        if not args:
            self._print("Usage: hash <file> [algorithm]")
            return
        file_path = args[0]
        algorithm = args[1] if len(args) > 1 else "sha256"
        result = self._orch.execute(
            "hash",
            {"input_path": file_path, "algorithm": algorithm},
        )
        self._print(f"{result.hash}")  # type: ignore[attr-defined]

    def _cmd_sign(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        key_path = opts.get("key_ref")  # --key-ref supplies the key file
        if key_path is None:
            self._print("Usage: sign <file> --key-ref <private_key_file>")
            return
        from pathlib import Path
        pk_bytes = Path(key_path).read_bytes()
        result = self._orch.execute(
            "sign",
            {
                "input_path": opts["file"],
                "metadata": {"private_key": pk_bytes},
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            },
        )
        self._print(f"Signature: {result.signature}")  # type: ignore[attr-defined]

    def _cmd_verify(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        key_path = opts.get("key_ref")
        sig_hex = opts.get("algorithm")  # reuse --algorithm slot for --sig
        # Also support explicit --signature parsing
        if sig_hex is None:
            for i, a in enumerate(args):
                if a == "--sig" and i + 1 < len(args):
                    sig_hex = args[i + 1]
                    break
        if key_path is None or sig_hex is None:
            self._print("Usage: verify <file> --sig <hex> --key-ref <public_key_file>")
            return
        from pathlib import Path
        pub_bytes = Path(key_path).read_bytes()
        result = self._orch.execute(
            "verify",
            {
                "input_path": opts["file"],
                "metadata": {"public_key": pub_bytes, "signature": sig_hex},
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            },
        )
        valid = result.valid  # type: ignore[attr-defined]
        self._print("Valid" if valid else "INVALID")

    def _cmd_mac(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        key_hex = opts.get("password")  # reuse --password slot for MAC key
        if key_hex is None:
            self._print("Usage: mac <file> --password <hex_key> [--algorithm ALG]")
            return
        key_bytes = bytes.fromhex(key_hex)
        algorithm = opts.get("algorithm", "hmac-sha256")
        result = self._orch.execute(
            "mac",
            {
                "input_path": opts["file"],
                "key": key_bytes,
                "algorithm": algorithm,
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            },
        )
        self._print(f"MAC: {result.mac}")  # type: ignore[attr-defined]

    def _cmd_checksum(self, args: list[str]) -> None:
        if not args:
            self._print("Usage: checksum <file> [algorithm]")
            return
        file_path = args[0]
        algorithm = args[1] if len(args) > 1 else "sha256"
        result = self._orch.execute(
            "checksum",
            {
                "input_path": file_path,
                "algorithm": algorithm,
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            },
        )
        self._print(f"{result.checksum}")  # type: ignore[attr-defined]

    # --- Verification commands ---

    def _cmd_verify_hash(self, args: list[str]) -> None:
        if len(args) < 2:
            self._print("Usage: verify-hash <file> <expected_hash> [algorithm]")
            return
        file_path = args[0]
        expected = args[1]
        algorithm = args[2] if len(args) > 2 else "sha256"
        result = self._orch.execute(
            "hash",
            {"input_path": file_path, "algorithm": algorithm},
        )
        digest = result.hash  # type: ignore[attr-defined]
        if digest.lower() == expected.lower():
            self._print(f"{C.GREEN}Valid{C.RESET} — hash matches")
        else:
            self._print(f"{C.RED}INVALID{C.RESET} — hash mismatch")
            self._print(f"  expected: {expected}")
            self._print(f"  actual:   {digest}")

    def _cmd_verify_mac(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            return
        key_hex = opts.get("password")
        # Parse --mac flag
        mac_hex: str | None = None
        for i, a in enumerate(args):
            if a == "--mac" and i + 1 < len(args):
                mac_hex = args[i + 1]
                break
        if key_hex is None or mac_hex is None:
            self._print("Usage: verify-mac <file> --password <hex_key> --mac <hex> [--algorithm ALG]")
            return
        key_bytes = bytes.fromhex(key_hex)
        algorithm = opts.get("algorithm", "hmac-sha256")
        from filanti.integrity.mac import compute_file_mac
        computed = compute_file_mac(opts["file"], key_bytes, algorithm)
        import hmac as _hmac
        if _hmac.compare_digest(str(computed.mac), str(mac_hex)):
            self._print(f"{C.GREEN}Valid{C.RESET} — MAC matches")
        else:
            self._print(f"{C.RED}INVALID{C.RESET} — MAC mismatch")

    def _cmd_verify_checksum(self, args: list[str]) -> None:
        if len(args) < 2:
            self._print("Usage: verify-checksum <file> <expected> [algorithm]")
            return
        file_path = args[0]
        expected = args[1]
        algorithm = args[2] if len(args) > 2 else "sha256"
        from filanti.integrity.checksum import compute_file_checksum
        result = compute_file_checksum(file_path, algorithm)
        if str(result.checksum).lower() == expected.lower():
            self._print(f"{C.GREEN}Valid{C.RESET} — checksum matches")
        else:
            self._print(f"{C.RED}INVALID{C.RESET} — checksum mismatch")
            self._print(f"  expected: {expected}")
            self._print(f"  actual:   {result.checksum}")

    # --- Key generation commands ---

    def _cmd_keygen(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            self._print("Usage: keygen <output_path> [--algorithm ALG] [--password PW]")
            return
        output_path = opts["file"]
        algorithm = opts.get("algorithm", "ed25519")
        password_str = opts.get("password")
        password_bytes = password_str.encode("utf-8") if isinstance(password_str, str) else None

        from filanti.integrity.signature import generate_keypair, save_keypair
        keypair = generate_keypair(algorithm, password_bytes)
        priv_path, pub_path = save_keypair(keypair, Path(output_path))
        self._print(f"{C.GREEN}Generated{C.RESET} {algorithm} signing key pair")
        self._print(f"  private: {priv_path}")
        self._print(f"  public:  {pub_path}")

    def _cmd_keygen_asymmetric(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            self._print("Usage: keygen-asymmetric <output_path> [--algorithm ALG] [--password PW]")
            return
        output_path = opts["file"]
        algorithm = opts.get("algorithm", "x25519")
        password_str = opts.get("password")
        password_bytes = password_str.encode("utf-8") if isinstance(password_str, str) else None

        from filanti.crypto.asymmetric import (
            generate_asymmetric_keypair,
            save_asymmetric_keypair,
        )
        keypair = generate_asymmetric_keypair(algorithm, password_bytes)
        priv_path, pub_path = save_asymmetric_keypair(keypair, Path(output_path))
        self._print(f"{C.GREEN}Generated{C.RESET} {algorithm} asymmetric key pair")
        self._print(f"  private: {priv_path}")
        self._print(f"  public:  {pub_path}")

    # --- Hybrid encryption commands ---

    def _cmd_encrypt_pubkey(self, args: list[str]) -> None:
        if not args:
            self._print(
                "Usage: encrypt-pubkey <file> --pubkey <key.pub> "
                "[--pubkey <key2.pub>] [--output OUT]"
            )
            return
        file_path = args[0]
        pubkeys: list[bytes | str | Path] = []
        output: str | None = None
        algorithm = "x25519"
        i = 1
        while i < len(args):
            a = args[i]
            if a in ("--pubkey", "-k") and i + 1 < len(args):
                pubkeys.append(args[i + 1])
                i += 2
            elif a in ("--output", "-o") and i + 1 < len(args):
                output = args[i + 1]
                i += 2
            elif a in ("--algorithm", "-a") and i + 1 < len(args):
                algorithm = args[i + 1]
                i += 2
            else:
                i += 1

        if not pubkeys:
            self._print(f"{C.RED}Error:{C.RESET} At least one --pubkey required")
            return

        from filanti.crypto.asymmetric import (
            AsymmetricAlgorithm,
            hybrid_encrypt_file,
        )
        out_path = Path(output) if output else Path(file_path + ".henc")
        metadata = hybrid_encrypt_file(
            input_path=Path(file_path),
            output_path=out_path,
            recipient_public_keys=pubkeys,
            algorithm=AsymmetricAlgorithm(algorithm),
        )
        self._print(f"{C.GREEN}Hybrid Encrypted{C.RESET} → {out_path}")
        self._print(f"  algorithm: {metadata.asymmetric_algorithm}")
        self._print(f"  recipients: {metadata.recipient_count}")

    def _cmd_decrypt_privkey(self, args: list[str]) -> None:
        opts = self._parse_file_opts(args)
        if opts is None:
            self._print("Usage: decrypt-privkey <file.henc> --key-ref <key.pem> [--password PW] [--output OUT]")
            return
        file_path = opts["file"]
        key_path = opts.get("key_ref")
        if key_path is None:
            self._print(f"{C.RED}Error:{C.RESET} --key-ref required (path to private key)")
            return
        password_str = opts.get("password")
        password_bytes = password_str.encode("utf-8") if isinstance(password_str, str) else None
        output = opts.get("output")

        from filanti.crypto.asymmetric import hybrid_decrypt_file
        if output is None:
            file_str = str(file_path)
            out_path = Path(file_str[:-5]) if file_str.endswith(".henc") else Path(file_str + ".dec")
        else:
            out_path = Path(output)

        size = hybrid_decrypt_file(
            input_path=Path(file_path),
            output_path=out_path,
            private_key=str(key_path),
            password=password_bytes,
        )
        self._print(f"{C.GREEN}Hybrid Decrypted{C.RESET} → {out_path}  ({size} bytes)")

    def _cmd_info_hybrid(self, args: list[str]) -> None:
        if not args:
            self._print("Usage: info-hybrid <file.henc>")
            return
        file_path = args[0]
        from filanti.crypto.asymmetric import get_hybrid_file_metadata
        metadata = get_hybrid_file_metadata(Path(file_path))
        self._print(f"  version:    {metadata.version}")
        self._print(f"  asymmetric: {metadata.asymmetric_algorithm}")
        self._print(f"  symmetric:  {metadata.symmetric_algorithm}")
        self._print(f"  recipients: {metadata.recipient_count}")
        self._print(f"  created:    {metadata.created_at}")

    # --- Utility commands ---

    def _cmd_algorithms(self, _args: list[str]) -> None:
        from filanti.hashing import crypto_hash
        from filanti.crypto import EncryptionAlgorithm
        from filanti.crypto.asymmetric import get_supported_asymmetric_algorithms
        from filanti.integrity.mac import MACAlgorithm
        from filanti.integrity.signature import SignatureAlgorithm
        from filanti.integrity.checksum import ChecksumAlgorithm

        self._print(f"\n{C.BOLD}Supported Algorithms:{C.RESET}")
        self._print(f"\n  {C.CYAN}Encryption:{C.RESET}  {', '.join(e.value for e in EncryptionAlgorithm)}")
        self._print(f"  {C.CYAN}Asymmetric:{C.RESET}  {', '.join(get_supported_asymmetric_algorithms())}")
        self._print(f"  {C.CYAN}Hashing:{C.RESET}     {', '.join(crypto_hash.get_supported_algorithms())}")
        self._print(f"  {C.CYAN}MAC:{C.RESET}         {', '.join(m.value for m in MACAlgorithm)}")
        self._print(f"  {C.CYAN}Signature:{C.RESET}   {', '.join(s.value for s in SignatureAlgorithm)}")
        self._print(f"  {C.CYAN}Checksum:{C.RESET}    {', '.join(c.value for c in ChecksumAlgorithm)}")
        self._print("")

    def _cmd_version(self, _args: list[str]) -> None:
        self._print(f"Filanti v{__version__}")

    # --- KMS operations ---------------------------------------------------

    def _cmd_kms(self, args: list[str]) -> None:
        """KMS (Key Management System) subcommands."""
        if not args:
            self._print(
                f"{C.BOLD}KMS Commands:{C.RESET}\n"
                f"  kms status                 — show KMS provider info\n"
                f"  kms create-key <key_id>    — create a new master key\n"
                f"  kms list                   — list available master keys\n"
                f"  kms encrypt <file> <key_id> [--output OUT] — encrypt using KMS envelope\n"
                f"  kms decrypt <file> <key_id> <wrapped_hex> [--output OUT] — decrypt with KMS"
            )
            return

        subcmd = args[0].lower()
        sub_args = args[1:]

        handler = {
            "status": self._kms_status,
            "create-key": self._kms_create_key,
            "list": self._kms_list,
            "encrypt": self._kms_encrypt,
            "decrypt": self._kms_decrypt,
        }.get(subcmd)

        if handler:
            handler(sub_args)
        else:
            self._print(f"Unknown kms subcommand: {subcmd}. Type 'kms' for help.")

    def _kms_status(self, _args: list[str]) -> None:
        self._print(f"  provider: {self._orch.kms_provider_name}")
        self._print(f"  keys dir: ~/.filanti/keys/")

    def _kms_create_key(self, args: list[str]) -> None:
        if not args:
            self._print("Usage: kms create-key <key_id>")
            return
        key_id = args[0]
        try:
            path = self._orch.kms_create_master_key(key_id)
            self._print(f"{C.GREEN}Created{C.RESET} master key '{key_id}' → {path}")
        except Exception as e:
            self._print(f"{C.RED}Error:{C.RESET} {e}")

    def _kms_list(self, _args: list[str]) -> None:
        try:
            keys = self._orch.kms_list_keys()
            if not keys:
                self._print("  (no keys)")
                return
            for key_id in keys:
                self._print(f"  {key_id}")
        except Exception as e:
            self._print(f"{C.RED}Error:{C.RESET} {e}")

    def _kms_encrypt(self, args: list[str]) -> None:
        if len(args) < 2:
            self._print("Usage: kms encrypt <file> <key_id> [--output OUT]")
            return
        file_path = args[0]
        key_id = args[1]
        output = None
        for i, a in enumerate(args[2:], 2):
            if a in ("--output", "-o") and i + 1 < len(args):
                output = args[i + 1]

        try:
            dk = self._orch.kms_generate_data_key(key_id)
            ctx = {
                "input_path": file_path,
                "output_path": output,
                "key": dk.plaintext,
                "algorithm": "aes-256-gcm",
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            }
            result = self._orch.execute("encrypt", ctx)
            d = result.to_dict()
            self._print(f"{C.GREEN}KMS Encrypted{C.RESET} → {d.get('output_path', '')}")
            self._print(f"  wrapped key: {dk.wrapped.hex()}")
            self._print(f"  key_id: {key_id}")
            self._print(f"  {C.DIM}Save the wrapped key — you need it to decrypt.{C.RESET}")
        except Exception as e:
            self._print(f"{C.RED}Error:{C.RESET} {e}")

    def _kms_decrypt(self, args: list[str]) -> None:
        if len(args) < 3:
            self._print("Usage: kms decrypt <file> <key_id> <wrapped_key_hex> [--output OUT]")
            return
        file_path = args[0]
        key_id = args[1]
        wrapped_hex = args[2]
        output = None
        for i, a in enumerate(args[3:], 3):
            if a in ("--output", "-o") and i + 1 < len(args):
                output = args[i + 1]

        try:
            wrapped = bytes.fromhex(wrapped_hex)
            raw_key = self._orch.kms_unwrap_key(wrapped, key_id)
            ctx = {
                "input_path": file_path,
                "output_path": output,
                "key": raw_key,
                "policy_name": self._session.policy,
                "threat_mode": self._session.mode,
            }
            result = self._orch.execute("decrypt", ctx)
            d = result.to_dict()
            self._print(f"{C.GREEN}KMS Decrypted{C.RESET} → {d.get('output_path', '')}  ({d.get('size', '?')} bytes)")
        except Exception as e:
            self._print(f"{C.RED}Error:{C.RESET} {e}")

    # ------------------------------------------------------------------
    # Option parsing helpers
    # ------------------------------------------------------------------

    def _parse_file_opts(self, args: list[str]) -> dict[str, Any] | None:
        """Minimal ``--key value`` / ``--flag`` parser for crypto commands."""
        if not args:
            self._print(
                "Usage: <command> <file> [--password PW] [--key-ref REF] "
                "[--output OUT] [--algorithm ALG] [--remove-source] [--no-secure-delete]"
            )
            return None

        opts: dict[str, Any] = {"file": args[0]}
        i = 1
        while i < len(args):
            a = args[i]
            if a in ("--password", "-p") and i + 1 < len(args):
                opts["password"] = args[i + 1]
                i += 2
            elif a in ("--key-ref", "-k") and i + 1 < len(args):
                opts["key_ref"] = args[i + 1]
                i += 2
            elif a in ("--output", "-o") and i + 1 < len(args):
                opts["output"] = args[i + 1]
                i += 2
            elif a in ("--algorithm", "-a") and i + 1 < len(args):
                opts["algorithm"] = args[i + 1]
                i += 2
            elif a == "--remove-source":
                opts["remove_source"] = True
                i += 1
            elif a == "--no-secure-delete":
                opts["secure_delete"] = False
                i += 1
            else:
                i += 1
        return opts

    # ------------------------------------------------------------------
    # IO helpers
    # ------------------------------------------------------------------

    def _print(self, msg: str) -> None:
        self._stdout.write(msg + "\n")
        self._stdout.flush()

    def _readline(self) -> str:
        if self._stdin is sys.stdin:
            return input(PROMPT)
        self._stdout.write(PROMPT)
        self._stdout.flush()
        line = self._stdin.readline()
        if not line:
            raise EOFError
        return line


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def repl_main() -> None:
    """Launch the Filanti v2 ."""
    r = REPL()
    r.run()
