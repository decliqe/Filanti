<p align="center">
<pre align="center">
███████╗██╗██╗      █████╗ ███╗   ██╗████████╗██╗
██╔════╝██║██║     ██╔══██╗████╗  ██║╚══██╔══╝██║
█████╗  ██║██║     ███████║██╔██╗ ██║   ██║   ██║
██╔══╝  ██║██║     ██╔══██║██║╚██╗██║   ██║   ██║
██║     ██║███████╗██║  ██║██║ ╚████║   ██║   ██║
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝
</pre>
</p>

<h3 align="center">A secure cryptographic file execution platform</h3>
<p align="center">
  Policy enforcement · Key management · Stateful control · v2.0
</p>

<p align="center">
  <a href="#whats-new-in-v2">What's New</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#interactive-repl">REPL</a> •
  <a href="#cli-reference">CLI</a> •
  <a href="#python-sdk-v2">SDK v2</a> •
  <a href="#security-model">Security</a>
</p>

---

## Overview

Filanti is a production-grade cryptographic toolkit for Python. It provides **encryption**, **hashing**, **digital signatures**, **HMAC integrity**, **checksums**, **hybrid (public-key) encryption**, **key derivation**, and **streaming large-file support** — all behind a unified API, CLI, and interactive REPL.

**Key capabilities:**

| Category | Algorithms |
|---|---|
| Symmetric Encryption | AES-256-GCM, ChaCha20-Poly1305 (Argon2id KDF) |
| Asymmetric / Hybrid | X25519, RSA-OAEP (multi-recipient) |
| Hashing | SHA-256/384/512, SHA3-256/384/512, BLAKE2b |
| HMAC | HMAC-SHA256/384/512, HMAC-SHA3-256, HMAC-BLAKE2b |
| Digital Signatures | Ed25519, ECDSA P-256/P-384/P-521 |
| Checksums | CRC32, Adler32, XXHash64 |
| Key Derivation | Argon2id, Scrypt |

---

## What's New in v2

Filanti v2 is a ground-up redesign of the execution model. Every operation now flows through a **pipeline** that enforces security policy before reaching the crypto engine:

```
 Request
    │
    ▼
┌──────────────┐     ┌──────────────┐     ┌─────────┐     ┌─────────────┐
│ Threat Engine │ ──▶ │ Policy Engine │ ──▶ │   KMS   │ ──▶ │ Engine Router│
│  (mode)       │     │ (enforcement) │     │ (keys)  │     │  (dispatch)  │
└──────────────┘     └──────────────┘     └─────────┘     └──────┬──────┘
                                                                  │
                              ┌────────────┬──────────┬───────────┤
                              ▼            ▼          ▼           ▼
                         CryptoEngine  HashEngine  IntegrityEngine  KDFEngine
```

### v1 → v2 Transition Highlights

| Feature | v1 | v2 |
|---|---|---|
| Execution model | Direct function calls | Orchestrator pipeline |
| Threat modes | — | dev · production · paranoid |
| Policy enforcement | — | default · enterprise · relaxed |
| Key management | Manual | Built-in KMS with envelope encryption |
| Interactive mode | — | Full REPL with tab-completion & history |
| Security tests | Basic | 380+ tests (OWASP, timing, tampering) |
| Secure deletion | — | Multi-pass overwrite with `--remove-source` |
| ENV secrets | `ENV:VAR` only | `ENV:VAR`, `$env:VAR`, `${VAR}`, `env.VAR` |
| v1 compatibility | — | ✅ Full backward compatibility |

### Threat Modes

| Mode | Description |
|---|---|
| `dev` | Relaxed — fast iteration, minimal KDF cost |
| `production` | **Default** — balanced security and performance |
| `paranoid` | Maximum — strongest KDF, strictest algorithms |

### Policy Enforcement

| Policy | Description |
|---|---|
| `default` | Sensible defaults for most applications |
| `enterprise` | Stricter — minimum password lengths, algorithm restrictions |
| `relaxed` | Minimal enforcement for testing |

---

## Installation

### Requirements

- Python ≥ 3.10
- `cryptography` ≥ 43.0
- `argon2-cffi` ≥ 23.1
- `xxhash` ≥ 3.0

### Install

```bash
pip install filanti
```

### Development

```bash
git clone https://github.com/decliqe/Filanti.git
cd filanti
pip install -e ".[dev]"
```

---

## Quick Start

### Python SDK (v2 — recommended)

```python
from filanti.api.sdk_v2 import Filanti

# Encrypt a file (routes through Orchestrator → policy check → KMS → engine)
Filanti.encrypt("secret.txt", password="my-password")

# Decrypt
Filanti.decrypt("secret.txt.enc", password="my-password")

# Hash
result = Filanti.hash_file("document.pdf")
print(result.hash)

# Sign & verify
keypair = Filanti.generate_keypair()  # Ed25519
sig = Filanti.sign("document.pdf", private_key=keypair.private_key)
ok = Filanti.verify("document.pdf",
                     signature=sig.signature,
                     public_key=keypair.public_key)
print(ok.valid)

# Hybrid (public-key) encryption
akp = Filanti.generate_asymmetric_keypair()  # X25519
Filanti.save_asymmetric_keypair(akp, "alice")
Filanti.hybrid_encrypt("secret.txt", ["alice.pub"])
Filanti.hybrid_decrypt("secret.txt.henc", "alice.pem")

# List all algorithms
print(Filanti.algorithms())
```

### Python SDK (v1 — backward compatible)

```python
from filanti.api import Filanti

# All v1 functions still work exactly as before
result = Filanti.hash_file("document.pdf")
Filanti.encrypt("secret.txt", password="my-password")
Filanti.decrypt("secret.txt.enc", password="my-password")
```

### CLI

```bash
# Encrypt / decrypt
filanti encrypt secret.txt --password "my-password"
filanti decrypt secret.txt.enc --password "my-password"

# Hash
filanti hash document.pdf --algorithm sha3-256

# Sign / verify
filanti keygen mykey
filanti sign document.pdf --key mykey
filanti verify-sig document.pdf --key mykey.pub

# Hybrid encryption
filanti keygen-asymmetric alice
filanti encrypt-pubkey secret.txt --pubkey alice.pub
filanti decrypt-privkey secret.txt.henc --privkey alice.pem
```

---

## Interactive REPL

Filanti launches into an interactive REPL by default:

```bash
filanti          # or: python -m filanti
```

```
███████╗██╗██╗      █████╗ ███╗   ██╗████████╗██╗
██╔════╝██║██║     ██╔══██╗████╗  ██║╚══██╔══╝██║
█████╗  ██║██║     ███████║██╔██╗ ██║   ██║   ██║
██╔══╝  ██║██║     ██╔══██║██║╚██╗██║   ██║   ██║
██║     ██║███████╗██║  ██║██║ ╚████║   ██║   ██║
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝
A secure cryptographic file execution platform  ·  v2

  mode=production  policy=default
  Type 'help' for commands, 'exit' to quit.

filanti>
```

### REPL Features

- **Tab-completion** — commands, subcommands, flags, algorithms, file paths
- **Persistent history** — `~/.filanti_history` (survives restarts)
- **Session state** — mode, policy, provider carry across commands
- **Colored output** — ANSI colors (auto-disabled for non-TTY)

### REPL Command Reference

**Session:**
```
set mode <dev|production|paranoid>
set policy <default|enterprise|relaxed>
status                          — show current mode, policy, history count
modes                           — list available threat modes
policies                        — list available policies
history                         — show command history
```

**Encryption:**
```
encrypt <file> --password <PW> [--output OUT] [--algorithm ALG]
        [--remove-source] [--no-secure-delete]
decrypt <file> --password <PW> [--output OUT]
        [--remove-source] [--no-secure-delete]
```

**Hashing:**
```
hash <file> [algorithm]
verify-hash <file> <expected_hash> [algorithm]
```

**Signatures:**
```
keygen <output> [--algorithm ALG] [--password PW]
sign <file> --key-ref <private_key>
verify <file> --sig <hex> --key-ref <public_key>
```

**Integrity:**
```
mac <file> --password <hex_key> [--algorithm ALG]
verify-mac <file> --password <hex_key> --mac <hex>
checksum <file> [algorithm]
verify-checksum <file> <expected> [algorithm]
```

**Hybrid / Asymmetric:**
```
keygen-asymmetric <output> [--algorithm ALG] [--password PW]
encrypt-pubkey <file> --pubkey <key.pub> [--pubkey <key2.pub>]
decrypt-privkey <file.henc> --key-ref <key.pem> [--password PW]
info-hybrid <file.henc>
```

**KMS (Key Management System):**
```
kms status                           — show provider info
kms create-key <key_id>              — create master key
kms list                             — list master keys
kms encrypt <file> <key_id>          — encrypt with envelope encryption
kms decrypt <file> <key_id> <wrapped_hex>  — decrypt with wrapped key
```

**Utility:**
```
algorithms     — list all supported algorithms
version        — show Filanti version
clear          — clear the terminal
help [command] — show help
exit / quit    — exit the REPL
```

---

## CLI Reference

All CLI commands output JSON for automation and scripting.

### Encryption

```bash
# Encrypt with password (Argon2id KDF + AES-256-GCM)
filanti encrypt secret.txt --password "my-password"
filanti encrypt secret.txt -p "password" --algorithm chacha20-poly1305

# Encrypt with ENV-based secret (recommended for automation)
export ENCRYPT_PASSWORD="my-secure-password"
filanti encrypt secret.txt --password ENV:ENCRYPT_PASSWORD

# Encrypt and securely delete original
filanti encrypt secret.txt -p "password" --remove-source

# Decrypt
filanti decrypt secret.txt.enc --password "my-password"
filanti decrypt secret.txt.enc -p "password" -o original.txt
```

### Hashing

```bash
# Hash a file (SHA-256 default)
filanti hash document.pdf
filanti hash document.pdf --algorithm sha3-256

# Verify file hash
filanti verify document.pdf abc123...
filanti verify document.pdf abc123... --algorithm sha512
```

### Digital Signatures

```bash
# Generate signing key pair (Ed25519 default)
filanti keygen mykey
filanti keygen mykey --algorithm ecdsa-p384
filanti keygen mykey --protect  # password-protected

# Sign
filanti sign document.pdf --key mykey

# Verify
filanti verify-sig document.pdf
filanti verify-sig document.pdf --key mykey.pub
```

### MAC (Integrity)

```bash
# Generate HMAC
filanti mac file.txt --key "my-secret-key"
filanti mac file.txt --key ENV:HMAC_KEY --create-file

# Verify
filanti verify-mac file.txt --key ENV:HMAC_KEY
```

### Checksums

```bash
filanti checksum file.txt
filanti checksum file.txt --algorithm xxhash64
filanti verify-checksum file.txt --expected "0x1a2b3c4d"
```

### Asymmetric / Hybrid Encryption

```bash
# Generate key pair
filanti keygen-asymmetric mykey                          # X25519 (default)
filanti keygen-asymmetric mykey --algorithm rsa-oaep     # RSA
filanti keygen-asymmetric mykey --protect                # password-protected

# Encrypt for recipient(s)
filanti encrypt-pubkey secret.txt --pubkey alice.pub
filanti encrypt-pubkey secret.txt --pubkey alice.pub --pubkey bob.pub

# Decrypt
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem

# Inspect
filanti info-hybrid secret.txt.henc
```

### Utility

```bash
filanti version
filanti list-algorithms
```

### ENV-Based Secrets

All password-accepting commands support multiple ENV patterns:

| Pattern | Example |
|---|---|
| `ENV:VAR` | `--password ENV:MY_PASSWORD` |
| `$env:VAR` | `--password '$env:MY_PASSWORD'` |
| `${VAR}` | `--password '${MY_PASSWORD}'` |
| `env.VAR` | `--password env.MY_PASSWORD` |

```bash
# PowerShell-friendly --env option
filanti encrypt secret.txt --env ENCRYPT_PASSWORD

# Load from .env file
filanti encrypt secret.txt --dotenv .env --env-key MY_PASSWORD
```

---

## Python SDK (v2)

The v2 SDK routes all operations through the Orchestrator pipeline with threat-mode and policy enforcement.

```python
from filanti.api.sdk_v2 import Filanti
```

### Encryption

| Method | Description |
|---|---|
| `Filanti.encrypt(path, *, password/key/key_ref, output, algorithm, policy, threat_mode)` | Encrypt file |
| `Filanti.decrypt(path, *, password/key/key_ref, output)` | Decrypt file |
| `Filanti.encrypt_bytes(data, *, password/key, algorithm)` | Encrypt bytes |
| `Filanti.decrypt_bytes(data, *, key)` | Decrypt bytes |

### Hashing

| Method | Description |
|---|---|
| `Filanti.hash_file(path, algorithm)` | Hash a file |
| `Filanti.hash_bytes(data, algorithm)` | Hash bytes |
| `Filanti.verify_hash(path, expected, algorithm)` | Verify file hash → bool |

### Signatures

| Method | Description |
|---|---|
| `Filanti.sign(path, *, private_key)` | Sign file |
| `Filanti.sign_bytes(data, *, private_key)` | Sign bytes |
| `Filanti.verify(path, *, signature, public_key)` | Verify file sig → VerifyResult |
| `Filanti.verify_bytes(data, *, signature, public_key)` | Verify bytes sig → VerifyResult |
| `Filanti.generate_keypair(algorithm, password)` | Generate signing key pair * |
| `Filanti.save_keypair(keypair, output_path)` | Save key pair to files * |

### Integrity

| Method | Description |
|---|---|
| `Filanti.mac(path, *, key, algorithm)` | Compute file MAC |
| `Filanti.mac_bytes(data, *, key, algorithm)` | Compute bytes MAC |
| `Filanti.verify_mac_value(path, *, key, expected_mac, algorithm)` | Verify MAC → bool |
| `Filanti.checksum(path, algorithm)` | Compute file checksum |
| `Filanti.checksum_bytes(data, algorithm)` | Compute bytes checksum |
| `Filanti.verify_checksum_value(path, expected, algorithm)` | Verify checksum → bool |

### Hybrid / Asymmetric

| Method | Description |
|---|---|
| `Filanti.generate_asymmetric_keypair(algorithm, password, rsa_key_size)` | Generate key pair * |
| `Filanti.save_asymmetric_keypair(keypair, output_path)` | Save key pair * |
| `Filanti.hybrid_encrypt(path, public_keys, *, output, algorithm)` | Hybrid encrypt file * |
| `Filanti.hybrid_decrypt(path, private_key, *, output, password)` | Hybrid decrypt file * |
| `Filanti.hybrid_encrypt_bytes(data, public_keys)` | Hybrid encrypt bytes * |
| `Filanti.hybrid_decrypt_bytes(data, private_key)` | Hybrid decrypt bytes * |
| `Filanti.get_hybrid_file_info(path)` | Read .henc metadata * |

### Utility

| Method | Description |
|---|---|
| `Filanti.generate_key(size)` | Generate random key * |
| `Filanti.derive(password, *, algorithm, ...)` | Derive key via KDF |
| `Filanti.algorithms()` | List all supported algorithms |
| `Filanti.resolve_secret(value)` | Resolve ENV reference |
| `Filanti.is_env_reference(value)` | Check if ENV reference |
| `Filanti.load_dotenv(path)` | Load .env file |
| `Filanti.execute(operation, **kwargs)` | Generic orchestrator call |
| `Filanti.configure(key_manager)` | Configure orchestrator |

> \* Marked methods bypass the Orchestrator (`@unsafe`) and emit a `UserWarning`.

### Direct Module Access

For maximum control, import directly from submodules:

```python
# Hashing
from filanti.hashing.crypto_hash import hash_file

# Encryption
from filanti.crypto import encrypt_file_with_password, decrypt_file_with_password

# Asymmetric / Hybrid
from filanti.crypto.asymmetric import generate_asymmetric_keypair, hybrid_encrypt_file

# Streaming (large files)
from filanti.crypto.streaming import encrypt_stream_file, decrypt_stream_file

# Integrity
from filanti.integrity.mac import compute_file_mac
from filanti.integrity.signature import generate_keypair, sign_file
from filanti.integrity.checksum import compute_file_checksum

# Secure memory
from filanti.core.secure_memory import SecureBytes, SecureString

# Secrets
from filanti.core.secrets import resolve_secret, load_dotenv
```

---

## Python SDK (v1 — backward compatible)

The original v1 SDK continues to work unchanged:

```python
from filanti.api import Filanti

Filanti.encrypt("secret.txt", password="my-password")
Filanti.decrypt("secret.txt.enc", password="my-password")
Filanti.hash_file("document.pdf")
keypair = Filanti.generate_keypair()
Filanti.hybrid_encrypt("secret.txt", ["alice.pub"])
```

All v1 method signatures are preserved. See the [v1 SDK reference tables](#v1-sdk-reference) for the full API.

<details>
<summary><strong>v1 SDK Reference (click to expand)</strong></summary>

### Hashing

| Method | Description |
|---|---|
| `Filanti.hash(data, algorithm)` | Hash bytes |
| `Filanti.hash_file(path, algorithm)` | Hash file |
| `Filanti.verify_hash(data, expected, algorithm)` | Verify hash |
| `Filanti.verify_file_hash(path, expected, algorithm)` | Verify file hash |

### Encryption

| Method | Description |
|---|---|
| `Filanti.encrypt(path, password/key, output, algorithm)` | Encrypt file |
| `Filanti.decrypt(path, password/key, output)` | Decrypt file |
| `Filanti.encrypt_bytes(data, password/key, algorithm)` | Encrypt bytes |
| `Filanti.decrypt_bytes(data, password/key)` | Decrypt bytes |

### Signatures

| Method | Description |
|---|---|
| `Filanti.generate_keypair(algorithm, password)` | Generate signing key pair |
| `Filanti.sign(data, private_key)` | Sign bytes |
| `Filanti.sign_file(path, private_key, ...)` | Sign file |
| `Filanti.verify_signature(data, signature, public_key)` | Verify bytes signature |
| `Filanti.verify_signature_file(path, signature_file, public_key)` | Verify file signature |

### Asymmetric / Hybrid

| Method | Description |
|---|---|
| `Filanti.generate_asymmetric_keypair(algorithm, password, rsa_key_size)` | Generate key pair |
| `Filanti.save_asymmetric_keypair(keypair, private_path, public_path)` | Save key pair |
| `Filanti.hybrid_encrypt(path, public_keys, output, algorithm)` | Hybrid encrypt file |
| `Filanti.hybrid_decrypt(path, private_key, output, password)` | Hybrid decrypt file |
| `Filanti.hybrid_encrypt_bytes(data, public_keys, algorithm)` | Hybrid encrypt bytes |
| `Filanti.hybrid_decrypt_bytes(data, private_key, password)` | Hybrid decrypt bytes |
| `Filanti.get_hybrid_file_info(path)` | Read .henc metadata |

### Integrity

| Method | Description |
|---|---|
| `Filanti.mac(data, key, algorithm)` | MAC bytes |
| `Filanti.mac_file(path, key, algorithm, create_file)` | MAC file |
| `Filanti.verify_mac(data, mac_value, key, algorithm)` | Verify MAC bytes |
| `Filanti.verify_mac_file(path, key, mac_value/mac_file)` | Verify MAC file |
| `Filanti.checksum(data, algorithm)` | Checksum bytes |
| `Filanti.checksum_file(path, algorithm, create_file)` | Checksum file |
| `Filanti.verify_checksum(data, expected, algorithm)` | Verify checksum bytes |
| `Filanti.verify_checksum_file(path, expected/checksum_file, algorithm)` | Verify checksum file |

### Utility

| Method | Description |
|---|---|
| `Filanti.generate_key(size)` | Random key |
| `Filanti.derive_key(password, salt, algorithm)` | KDF |
| `Filanti.algorithms()` | All algorithms |
| `Filanti.resolve_secret(value)` | Resolve ENV reference |
| `Filanti.is_env_reference(value)` | Check ENV pattern |
| `Filanti.redact_secret(text, secret)` | Redact from string |
| `Filanti.safe_json_output(data, secrets, secret_keys)` | Safe JSON |

</details>

---

## Architecture

```
filanti/
├── api/
│   ├── sdk.py              # v1 SDK (backward compatible)
│   └── sdk_v2.py           # v2 SDK (orchestrator-backed)
├── cli/
│   ├── main.py             # Typer CLI (19 commands)
│   └── repl.py             # Interactive REPL with tab-completion
├── core/
│   ├── context.py          # ExecutionContext + Operation enum
│   ├── orchestrator.py     # Pipeline: Threat → Policy → KMS → Engine
│   ├── errors.py           # Exception hierarchy
│   ├── file_manager.py     # File I/O + secure deletion
│   ├── metadata.py         # File format metadata
│   ├── plugins.py          # Plugin registry
│   ├── secrets.py          # ENV secret resolution
│   └── secure_memory.py    # SecureBytes / SecureString
├── crypto/
│   ├── encryption.py       # AES-256-GCM, ChaCha20-Poly1305
│   ├── decryption.py       # Symmetric decryption
│   ├── asymmetric.py       # X25519, RSA-OAEP hybrid encryption
│   ├── kdf.py              # Argon2id, Scrypt
│   ├── key_management.py   # Key generation, splitting, derivation
│   └── streaming.py        # Chunked processing for large files
├── engines/
│   ├── crypto.py           # CryptoEngine (encrypt/decrypt dispatch)
│   ├── hashing.py          # HashingEngine
│   ├── integrity.py        # IntegrityEngine (sign/verify/mac/checksum)
│   ├── kdf.py              # KDFEngine
│   └── router.py           # EngineRouter (operation → engine)
├── hashing/
│   └── crypto_hash.py      # SHA-2, SHA-3, BLAKE2b
├── integrity/
│   ├── mac.py              # HMAC algorithms
│   ├── signature.py        # Ed25519, ECDSA
│   └── checksum.py         # CRC32, Adler32, XXHash64
├── kms/
│   └── manager.py          # KeyManager + LocalProvider (~/.filanti/keys/)
├── policy/
│   └── engine.py           # Policy enforcement (default/enterprise/relaxed)
└── threat/
    └── engine.py           # Threat modes (dev/production/paranoid)
```

### Orchestrator Pipeline

```python
from filanti.core.orchestrator import Orchestrator

orch = Orchestrator()

# Every operation follows the same pipeline:
result = orch.execute("encrypt", {
    "input_path": "secret.txt",
    "password": "my-password",
    "policy_name": "enterprise",
    "threat_mode": "paranoid",
})
```

1. **ThreatEngine** — applies mode-specific defaults (KDF cost, algorithm selection)
2. **PolicyEngine** — validates inputs (password strength, algorithm restrictions)
3. **KMS** — resolves key references, applies envelope encryption
4. **EngineRouter** — dispatches to CryptoEngine, HashingEngine, IntegrityEngine, or KDFEngine

---

## KMS (Key Management System)

Filanti includes a built-in local KMS for envelope encryption.

```
┌──────────────┐        ┌───────────────┐
│  Master Key   │──wraps─▶│  Data Key     │──encrypts─▶  Ciphertext
│ (~/.filanti/) │        │ (per-file)    │
└──────────────┘        └───────────────┘
```

**REPL:**
```
kms create-key myapp
kms encrypt secret.txt myapp
kms decrypt secret.txt.enc myapp <wrapped_key_hex>
```

**Python:**
```python
from filanti.kms.manager import KeyManager, LocalProvider

km = KeyManager(LocalProvider())
dk = km.generate_data_key("myapp")
# dk.plaintext → use to encrypt
# dk.wrapped   → store alongside ciphertext
```

---

## Security Model

### Threat Assumptions

Filanti is designed assuming:
- **Host compromise is possible** — keys should be protected
- **Files may be intercepted** — all encryption is authenticated (AEAD)
- **Password reuse may occur** — unique salt + strong KDF (Argon2id)
- **Timing attacks are a concern** — constant-time comparisons everywhere

### Mitigations

| Threat | Mitigation |
|---|---|
| Eavesdropping | Authenticated encryption (AES-GCM, ChaCha20-Poly1305) |
| Tampering | Authentication tags, HMAC, digital signatures |
| Replay attacks | Unique nonces per encryption |
| Password cracking | Argon2id with high memory cost |
| Timing attacks | `secrets.compare_digest` for all comparisons |
| Memory leaks | `SecureBytes` / `SecureString` with auto-zeroing |
| Algorithm confusion | Explicit algorithm selection, policy enforcement |
| Key leakage | KMS envelope encryption, secure deletion |

### Best Practices

1. **Password-based encryption** for user-facing features (Argon2id)
2. **Raw keys** for server-to-server (`Filanti.generate_key(32)`)
3. **Hybrid encryption** for secure file sharing (X25519)
4. **HMAC** for integrity when confidentiality isn't needed
5. **Signatures** for non-repudiation
6. **Checksums** only for accidental corruption detection

---

## File Formats

### Encrypted File (.enc)

```
FLNT           # Magic bytes (4 bytes)
VERSION        # Format version (1 byte)
METADATA_LEN   # Metadata length (4 bytes)
METADATA_JSON  # Algorithm, nonce, salt, KDF params
CIPHERTEXT     # Encrypted data with auth tag
```

### Hybrid Encrypted File (.henc)

```
FLAS           # Magic bytes (4 bytes) — "Filanti Asymmetric"
METADATA_LEN   # Metadata length (4 bytes)
METADATA_JSON  # asymmetric_algorithm, nonce, session_keys[], ...
CIPHERTEXT     # Encrypted data with auth tag
```

---

## Error Handling

```python
from filanti import (
    FilantiError,        # Base
    FileOperationError,  # File I/O
    HashingError,        # Hash operations
    ValidationError,     # Input validation
    EncryptionError,     # Encrypt failures
    DecryptionError,     # Decrypt failures
    IntegrityError,      # MAC/checksum failures
    SignatureError,      # Sign/verify failures
    SecretError,         # ENV resolution failures
)

try:
    Filanti.decrypt("file.enc", password="wrong")
except DecryptionError as e:
    print(f"Failed: {e}")
```

---

## Plugin Architecture

Extend Filanti with custom algorithms:

```python
from filanti.core.plugins import PluginRegistry, HashPlugin

class MyHash(HashPlugin):
    name = "my-hash"
    digest_size = 32
    def hash(self, data: bytes) -> bytes:
        return custom_hash(data)

PluginRegistry.register_hash(MyHash())
```

Plugin types: `HashPlugin`, `EncryptionPlugin`, `MACPlugin`, `SignaturePlugin`, `ChecksumPlugin`, `KDFPlugin`

---

## Streaming

Memory-efficient processing for large files:

```python
from filanti.crypto.streaming import encrypt_stream_file, decrypt_stream_file

def progress(done, total):
    print(f"{done}/{total}")

encrypt_stream_file("large.bin", "large.bin.enc", key,
                     chunk_size=64*1024, progress_callback=progress)
```

---

## Secure Memory

```python
from filanti.core.secure_memory import SecureBytes, SecureString

with SecureBytes(sensitive_data) as secure:
    process(secure.data)
# Automatically zeroed on exit

with SecureString("my-password") as pwd:
    use_password(pwd.value)
```

---

## Changelog

### v2.0.0

**New:**
- Orchestrator pipeline (ThreatEngine → PolicyEngine → KMS → EngineRouter)
- Interactive REPL with tab-completion, persistent history, session state
- Threat modes: dev, production, paranoid
- Policy enforcement: default, enterprise, relaxed
- Built-in KMS with LocalProvider + envelope encryption
- v2 SDK (`filanti.api.sdk_v2.Filanti`) — orchestrator-routed
- Engine architecture: CryptoEngine, HashingEngine, IntegrityEngine, KDFEngine
- 380+ security tests (OWASP, timing, tampering, memory)
- REPL commands for all operations: keygen, keygen-asymmetric, encrypt-pubkey, decrypt-privkey, info-hybrid, verify-hash, verify-mac, verify-checksum, algorithms, version, KMS subcommands

**Changed:**
- Default entry point is now the REPL (`python -m filanti`)
- Encrypted metadata format v2 (backward compatible — reads v1)
- Expanded ENV secret patterns ($env:, ${}, env.)

**Security:**
- All 21 OWASP-audit findings remediated
- Constant-time comparisons everywhere
- Secure memory zeroing for sensitive data
- Multi-pass secure deletion
- Policy-enforced minimum password lengths
- Algorithm restriction enforcement

### v1.1.0

- Secret resolution: `$env:VAR`, `${VAR}`, `env.VAR` formats
- `.env` file loading
- `--remove-source` / `--no-secure-delete` options
- CLI `--env` / `--dotenv` / `--env-key` options

### v1.0.0

- Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305)
- Hybrid encryption (X25519, RSA-OAEP)
- Hashing (SHA-2, SHA-3, BLAKE2b)
- HMAC, digital signatures, checksums
- Streaming large-file support
- Plugin architecture
- Secure memory handling
- CLI + Python SDK

---

## Contributors & Acknowledgements

[@stephenlb](https://github.com/stephenlb) — inspiration and guidance on encryption and security best practices.

---

## License

MIT License

---

<p align="center">
  Maintained by Decliqe
</p>
