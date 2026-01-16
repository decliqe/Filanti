<h1 align="center">
 FILANTI
</h1>
<p align="center">
  <strong>A modular, security-focused file framework for Python</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#cli-reference">CLI</a> •
  <a href="#python-sdk">SDK</a> •
  <a href="#security">Security</a>
</p>

---

## Overview

**Filanti** is a production-ready Python framework providing secure-by-default primitives for:

-  **File Encryption** - AES-256-GCM, ChaCha20-Poly1305 with password-based encryption
-  **Cryptographic Hashing** - SHA-256/384/512, SHA3, BLAKE2b
-  **Integrity Verification** - HMAC, digital signatures, checksums
-  **Streaming Support** - Memory-efficient processing of large files
-  **Plugin Architecture** - Extensible algorithm support

Filanti acts as a **secure abstraction layer** over cryptographic operations, avoiding unsafe custom implementations while remaining extensible and auditable.

## Installation

### From PyPI

```bash
pip install filanti
```

### From Source

```bash
git clone https://github.com/decliqe/filanti.git
cd filanti
pip install -e .
```

### Development Installation

```bash
pip install -e ".[dev]"
```

This includes testing and linting tools: pytest, pytest-cov, ruff, mypy.

## Requirements

- **Python**: 3.11 or higher
- **Dependencies**:
  - `cryptography>=42.0.0` - Core cryptographic operations
  - `typer>=0.9.0` - CLI framework
  - `argon2-cffi>=23.1.0` - Password hashing and KDF

---

## Quick Start

### Python SDK

```python
from filanti.api import Filanti

# Hash a file
result = Filanti.hash_file("document.pdf")
print(f"SHA-256: {result.hash}")

# Encrypt with password
Filanti.encrypt("secret.txt", password="my-secure-password")

# Decrypt
Filanti.decrypt("secret.txt.enc", password="my-secure-password")

# Generate signing keys
keypair = Filanti.generate_keypair()

# Sign a file
signature = Filanti.sign_file("document.pdf", keypair.private_key, create_file=True)

# Verify signature
Filanti.verify_signature_file("document.pdf")
```

### Command Line

```bash
# Hash a file
filanti hash document.pdf

# Encrypt a file
filanti encrypt secret.txt --password "my-password"

# Decrypt a file
filanti decrypt secret.txt.enc --password "my-password"

# Generate signing keys
filanti keygen my_key --protect

# Sign a file
filanti sign document.pdf --key my_key

# Verify signature
filanti verify-sig document.pdf
```

---

## Features

###  Encryption

Modern authenticated encryption with automatic integrity verification.

| Algorithm | Description | Key Size | Use Case |
|-----------|-------------|----------|----------|
| `aes-256-gcm` | AES-256 in GCM mode (default) | 256-bit | General purpose, hardware-accelerated |
| `chacha20-poly1305` | ChaCha20 with Poly1305 MAC | 256-bit | Excellent software performance |

**Password-Based Encryption:**
- Uses **Argon2id** (OWASP recommended) for key derivation
- Automatic salt generation (32 bytes)
- Secure memory handling for passwords

```python
from filanti.api import Filanti

# Password-based encryption
Filanti.encrypt("file.txt", password="secure-password")
Filanti.decrypt("file.txt.enc", password="secure-password")

# Raw key encryption
key = Filanti.generate_key(32)  # 256-bit key
Filanti.encrypt("file.txt", key=key)
```

###  Hashing

Cryptographic hash functions for file fingerprinting and integrity.

| Algorithm | Digest Size | Description |
|-----------|-------------|-------------|
| `sha256` | 256-bit | SHA-2 family (default) |
| `sha384` | 384-bit | SHA-2 family |
| `sha512` | 512-bit | SHA-2 family |
| `sha3-256` | 256-bit | SHA-3 family |
| `sha3-384` | 384-bit | SHA-3 family |
| `sha3-512` | 512-bit | SHA-3 family |
| `blake2b` | 512-bit | Modern, fast hash |

```python
from filanti.api import Filanti

# Hash bytes
result = Filanti.hash(b"Hello, Filanti!")
print(result.hash)

# Hash file with specific algorithm
result = Filanti.hash_file("document.pdf", algorithm="blake2b")

# Verify hash
is_valid = Filanti.verify_file_hash("document.pdf", expected_hash)
```

###  Integrity Verification

#### HMAC (Message Authentication Code)

Keyed integrity verification for detecting tampering.

| Algorithm | Description |
|-----------|-------------|
| `hmac-sha256` | HMAC with SHA-256 (default) |
| `hmac-sha384` | HMAC with SHA-384 |
| `hmac-sha512` | HMAC with SHA-512 |
| `hmac-sha3-256` | HMAC with SHA3-256 |
| `hmac-blake2b` | HMAC with BLAKE2b |

```python
from filanti.api import Filanti

# Compute MAC
key = Filanti.generate_key(32)
result = Filanti.mac_file("file.txt", key, create_file=True)

# Verify MAC (uses .mac metadata file)
is_valid = Filanti.verify_mac_file("file.txt", key)
```

#### Digital Signatures

Asymmetric signature operations for authenticity verification.

| Algorithm | Description |
|-----------|-------------|
| `ed25519` | EdDSA with Curve25519 (default) |
| `ecdsa-p256` | ECDSA with P-256 curve |
| `ecdsa-p384` | ECDSA with P-384 curve |
| `ecdsa-p521` | ECDSA with P-521 curve |

```python
from filanti.api import Filanti

# Generate key pair
keypair = Filanti.generate_keypair(algorithm="ed25519", password="key-password")

# Sign file (creates .sig file)
Filanti.sign_file("document.pdf", keypair.private_key, create_file=True)

# Verify signature
is_valid = Filanti.verify_signature_file("document.pdf")
```

#### Checksums

Non-cryptographic checksums for detecting accidental corruption.

| Algorithm | Description |
|-----------|-------------|
| `crc32` | CRC-32 (default) |
| `adler32` | Adler-32 |
| `xxhash64` | XXHash 64-bit (fast) |

⚠️ **Note**: Checksums are NOT cryptographically secure. Use for detecting accidental corruption only.

```python
from filanti.api import Filanti

# Compute checksum
result = Filanti.checksum_file("file.txt", algorithm="crc32", create_file=True)

# Verify checksum
is_valid = Filanti.verify_checksum_file("file.txt")
```

###  Streaming Encryption

Memory-efficient processing of large files with progress callbacks.

```python
from filanti.crypto.streaming import encrypt_stream_file, decrypt_stream_file

# Encrypt large file with progress
def progress(bytes_done, total):
    print(f"Progress: {bytes_done} bytes")

encrypt_stream_file(
    "large_file.bin",
    "large_file.bin.enc",
    key,
    chunk_size=64 * 1024,  # 64 KB chunks
    progress_callback=progress,
)

# Decrypt with streaming
decrypt_stream_file("large_file.bin.enc", "large_file.bin", key)
```

###  Plugin Architecture

Extend Filanti with custom algorithms without modifying core code.

```python
from filanti.core.plugins import PluginRegistry, HashPlugin

class MyCustomHash(HashPlugin):
    name = "my-hash"
    digest_size = 32
    
    def hash(self, data: bytes) -> bytes:
        # Your implementation
        return custom_hash(data)

# Register plugin
PluginRegistry.register_hash(MyCustomHash())

# Use it
from filanti.api import Filanti
result = Filanti.hash(data, algorithm="my-hash")
```

**Plugin Types:**
- `HashPlugin` - Custom hash algorithms
- `EncryptionPlugin` - Custom encryption algorithms
- `MACPlugin` - Custom MAC algorithms
- `SignaturePlugin` - Custom signature algorithms
- `ChecksumPlugin` - Custom checksum algorithms
- `KDFPlugin` - Custom key derivation functions

###  Secure Memory Handling

Defense-in-depth memory protection for sensitive data.

```python
from filanti.core.secure_memory import SecureBytes, SecureString

# Secure bytes handling
with SecureBytes(sensitive_data) as secure:
    process(secure.data)
# Data is automatically cleared

# Secure string handling
with SecureString("my-password") as pwd:
    use_password(pwd.value)
# Password is automatically cleared
```

---

## CLI Reference

All CLI commands output JSON for automation and scripting.

### General Commands

```bash
# Show version
filanti version

# List all supported algorithms
filanti list-algorithms

# Show supported hash algorithms
filanti algorithms
```

### Hashing

```bash
# Hash a file (SHA-256 default)
filanti hash document.pdf

# Hash with specific algorithm
filanti hash document.pdf --algorithm sha512
filanti hash document.pdf -a blake2b

# Verify file hash
filanti verify document.pdf abc123...
filanti verify document.pdf abc123... --algorithm sha512
```

### Encryption

```bash
# Encrypt with password (will prompt)
filanti encrypt secret.txt

# Encrypt with password argument
filanti encrypt secret.txt --password "my-password"

# Encrypt with specific algorithm
filanti encrypt secret.txt -p "password" --algorithm chacha20-poly1305

# Specify output path
filanti encrypt secret.txt -o encrypted_file.bin -p "password"

# Decrypt
filanti decrypt secret.txt.enc --password "my-password"
filanti decrypt secret.txt.enc -o original.txt -p "password"
```

### MAC (Integrity)

```bash
# Generate MAC
filanti mac file.txt --key-file secret.key

# Generate MAC with hex key
filanti mac file.txt --key-hex abc123...

# Create detached .mac file
filanti mac file.txt --key-file secret.key --create-file

# Verify MAC
filanti verify-mac file.txt --key-file secret.key
filanti verify-mac file.txt --key-file secret.key --mac-file file.txt.mac
```

### Digital Signatures

```bash
# Generate key pair
filanti keygen my_signing_key

# Generate protected key pair (encrypted private key)
filanti keygen my_signing_key --protect
# (prompts for password)

# Generate with specific algorithm
filanti keygen my_key --algorithm ecdsa-p384

# Sign a file
filanti sign document.pdf --key my_signing_key

# Sign with password-protected key
filanti sign document.pdf --key my_signing_key --password "key-password"

# Sign without embedding public key
filanti sign document.pdf --key my_signing_key --no-embed-key

# Verify signature (uses embedded public key)
filanti verify-sig document.pdf

# Verify with external public key
filanti verify-sig document.pdf --key my_signing_key.pub
```

### Checksums

```bash
# Compute checksum (CRC-32 default)
filanti checksum file.txt

# Compute with specific algorithm
filanti checksum file.txt --algorithm xxhash64

# Create detached .checksum file
filanti checksum file.txt --create-file

# Verify checksum
filanti verify-checksum file.txt --expected "0x1a2b3c4d"
filanti verify-checksum file.txt --checksum-file file.txt.checksum
```

---

## Python SDK

### Filanti Class

The `Filanti` class provides a unified high-level API for all operations.

```python
from filanti.api import Filanti
```

#### Hashing Methods

| Method | Description |
|--------|-------------|
| `Filanti.hash(data, algorithm)` | Hash bytes data |
| `Filanti.hash_file(path, algorithm)` | Hash a file |
| `Filanti.verify_hash(data, expected, algorithm)` | Verify hash of bytes |
| `Filanti.verify_file_hash(path, expected, algorithm)` | Verify hash of file |

#### Encryption Methods

| Method | Description |
|--------|-------------|
| `Filanti.encrypt(path, password/key, output, algorithm)` | Encrypt a file |
| `Filanti.decrypt(path, password/key, output)` | Decrypt a file |
| `Filanti.encrypt_bytes(data, password/key, algorithm)` | Encrypt bytes |
| `Filanti.decrypt_bytes(data, password/key)` | Decrypt bytes |

#### Integrity Methods

| Method | Description |
|--------|-------------|
| `Filanti.mac(data, key, algorithm)` | Compute MAC of bytes |
| `Filanti.mac_file(path, key, algorithm, create_file)` | Compute MAC of file |
| `Filanti.verify_mac(data, mac_value, key, algorithm)` | Verify MAC of bytes |
| `Filanti.verify_mac_file(path, key, mac_value/mac_file)` | Verify MAC of file |

#### Signature Methods

| Method | Description |
|--------|-------------|
| `Filanti.generate_keypair(algorithm, password)` | Generate key pair |
| `Filanti.sign(data, private_key, algorithm, password)` | Sign bytes |
| `Filanti.sign_file(path, private_key, algorithm, password, create_file)` | Sign file |
| `Filanti.verify_signature(data, signature, public_key, algorithm)` | Verify signature of bytes |
| `Filanti.verify_signature_file(path, signature_file, public_key)` | Verify signature of file |

#### Checksum Methods

| Method | Description |
|--------|-------------|
| `Filanti.checksum(data, algorithm)` | Compute checksum of bytes |
| `Filanti.checksum_file(path, algorithm, create_file)` | Compute checksum of file |
| `Filanti.verify_checksum(data, expected, algorithm)` | Verify checksum of bytes |
| `Filanti.verify_checksum_file(path, expected/checksum_file, algorithm)` | Verify checksum of file |

#### Utility Methods

| Method | Description |
|--------|-------------|
| `Filanti.generate_key(size)` | Generate random key |
| `Filanti.derive_key(password, salt, algorithm)` | Derive key from password |
| `Filanti.algorithms()` | Get all supported algorithms |

### Direct Module Access

For more control, use the underlying modules directly:

```python
# Hashing
from filanti.hashing import crypto_hash
digest = crypto_hash.hash_file("file.txt", "sha256")

# Encryption
from filanti.crypto import encrypt_file, decrypt_file
encrypt_file(input_path, output_path, key)

# Integrity
from filanti.integrity import compute_file_mac, verify_file_mac
mac = compute_file_mac("file.txt", key)

# Signatures
from filanti.integrity import generate_keypair, sign_file
keypair = generate_keypair("ed25519")
sign_file("file.txt", keypair.private_key)

# Streaming
from filanti.crypto.streaming import encrypt_stream_file
encrypt_stream_file(input_path, output_path, key)

# Secure Memory
from filanti.core.secure_memory import SecureBytes, secure_random_bytes
random = secure_random_bytes(32)
```

---

## Architecture

```
filanti/
├── core/              # Core infrastructure
│   ├── errors.py      # Exception hierarchy
│   ├── file_manager.py # File I/O operations
│   ├── metadata.py    # Metadata handling
│   ├── plugins.py     # Plugin architecture
│   └── secure_memory.py # Secure memory utilities
│
├── crypto/            # Encryption subsystem
│   ├── encryption.py  # Encryption primitives
│   ├── decryption.py  # Decryption primitives
│   ├── key_management.py # Key generation/handling
│   ├── kdf.py         # Key derivation functions
│   └── streaming.py   # Large file streaming
│
├── hashing/           # Hashing subsystem
│   └── crypto_hash.py # Cryptographic hashing
│
├── integrity/         # Integrity subsystem
│   ├── checksum.py    # Non-crypto checksums
│   ├── mac.py         # HMAC operations
│   └── signature.py   # Digital signatures
│
├── cli/               # Command-line interface
│   └── main.py        # CLI commands
│
└── api/               # High-level API
    └── sdk.py         # Filanti SDK class
```

### Module Dependencies

```
api/sdk.py
    ├── hashing/crypto_hash.py
    ├── crypto/encryption.py
    ├── crypto/decryption.py
    ├── crypto/kdf.py
    ├── crypto/key_management.py
    ├── integrity/mac.py
    ├── integrity/signature.py
    ├── integrity/checksum.py
    └── core/errors.py

cli/main.py
    └── (same dependencies as sdk.py)
```

---

## Security Model

### Threat Assumptions

Filanti is designed assuming:

- **Host compromise is possible** - Keys should be protected
- **Files may be intercepted** - All encryption is authenticated
- **Password reuse may occur** - Strong KDF with unique salts
- **Timing attacks are a concern** - Constant-time comparisons

### Security Mitigations

| Threat | Mitigation |
|--------|------------|
| Eavesdropping | Authenticated encryption (AES-GCM, ChaCha20-Poly1305) |
| Tampering | Authentication tags, HMAC, digital signatures |
| Replay attacks | Unique nonces per encryption |
| Password cracking | Argon2id with high memory cost |
| Timing attacks | Constant-time comparison (secrets.compare_digest) |
| Memory leaks | Secure memory zeroing |
| Algorithm confusion | Explicit algorithm selection |

### Best Practices

1. **Use password-based encryption for user-facing features**
   - Argon2id provides excellent protection against GPU/ASIC attacks

2. **Use raw keys for server-to-server encryption**
   - Generate keys with `Filanti.generate_key(32)`
   - Store keys securely (HSM, vault, secure key management)

3. **Always verify signatures with trusted public keys**
   - Don't rely solely on embedded public keys

4. **Use HMAC for integrity when confidentiality isn't needed**
   - Faster than signatures
   - Requires shared secret key

5. **Use checksums only for accidental corruption**
   - Not secure against malicious modification

---

## Metadata Formats

### Encrypted File Format

```
FLNT           # Magic bytes (4 bytes)
VERSION        # Format version (1 byte)
METADATA_LEN   # Metadata length (4 bytes)
METADATA_JSON  # Algorithm, nonce, salt, KDF params
CIPHERTEXT     # Encrypted data with auth tag
```

### Detached Metadata Files

#### .mac File

```json
{
  "version": "1.0",
  "algorithm": "hmac-sha256",
  "mac": "a1b2c3...",
  "filename": "document.pdf",
  "filesize": 12345,
  "created_at": "2026-01-16T12:00:00Z"
}
```

#### .sig File

```json
{
  "version": "1.0",
  "algorithm": "ed25519",
  "signature": "d4e5f6...",
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "filename": "document.pdf",
  "filesize": 12345,
  "created_at": "2026-01-16T12:00:00Z"
}
```

#### .checksum File

```json
{
  "version": "1.0",
  "algorithm": "crc32",
  "checksum": "0x1a2b3c4d",
  "filename": "document.pdf",
  "filesize": 12345,
  "created_at": "2026-01-16T12:00:00Z"
}
```

---

[//]: # (## Testing)

[//]: # ()
[//]: # (### Running Tests)

[//]: # ()
[//]: # (```bash)

[//]: # (# Run all tests)

[//]: # (pytest)

[//]: # ()
[//]: # (# Run with coverage)

[//]: # (pytest --cov=filanti)

[//]: # ()
[//]: # (# Run specific test file)

[//]: # (pytest tests/test_encryption.py)

[//]: # ()
[//]: # (# Run with verbose output)

[//]: # (pytest -v)

[//]: # (```)

[//]: # ()
[//]: # (### Test Coverage)

[//]: # ()
[//]: # (Filanti includes comprehensive tests:)

[//]: # ()
[//]: # (- **Unit tests** for all modules)

[//]: # (- **Integration tests** for CLI and SDK)

[//]: # (- **Security tests** for timing attacks, tampering detection)

[//]: # (- **Edge case tests** for error handling)

[//]: # ()
[//]: # (---)

## Error Handling

All Filanti exceptions inherit from `FilantiError`:

```python
from filanti import (
    FilantiError,        # Base exception
    FileOperationError,  # File I/O errors
    HashingError,        # Hashing errors
    ValidationError,     # Verification failures
    EncryptionError,     # Encryption errors
    DecryptionError,     # Decryption errors
    IntegrityError,      # MAC verification errors
    SignatureError,      # Signature errors
)

try:
    Filanti.decrypt("file.enc", password="wrong")
except DecryptionError as e:
    print(f"Decryption failed: {e}")
    print(f"Context: {e.context}")
```

---

## Configuration

### KDF Parameters

Adjust Argon2id parameters for security/performance trade-off:

```python
from filanti.crypto.kdf import KDFParams, derive_key

# High-security settings (slower)
params = KDFParams(
    argon2_memory_cost=131072,  # 128 MiB
    argon2_time_cost=4,
    argon2_parallelism=4,
)

# Derive key with custom params
result = derive_key(password, salt, params)
```

### Streaming Chunk Size

Optimize for memory vs. performance:

```python
from filanti.crypto.streaming import encrypt_stream_file

# Larger chunks = faster, more memory
encrypt_stream_file(input_path, output_path, key, chunk_size=1024*1024)  # 1 MB

# Smaller chunks = slower, less memory
encrypt_stream_file(input_path, output_path, key, chunk_size=16*1024)   # 16 KB
```

---

## Contributing

### Development Setup

```bash
git clone https://github.com/decliqe/FILANTI.git
cd filanti
pip install -e ".[dev]"
```

[//]: # (### Code Quality)

[//]: # ()
[//]: # (```bash)

[//]: # (# Linting)

[//]: # (ruff check .)

[//]: # ()
[//]: # (# Type checking)

[//]: # (mypy filanti)

[//]: # ()
[//]: # (# Format code)

[//]: # (ruff format .)

[//]: # (```)

### Pull Request Guidelines

1. Write tests for new features
2. Update documentation
3. Follow existing code style
4. Add type hints
5. Run full test suite before submitting

---

## Changelog

### v1.0.0 (2026-01-16)

[//]: # (**Phase 1 - Foundation**)

[//]: # (- Project scaffolding and architecture)

[//]: # (- Core file handling and error framework)

[//]: # (- Cryptographic hashing &#40;SHA-256, SHA-512, SHA-3, BLAKE2b&#41;)

[//]: # (- Initial test suite)

[//]: # ()
[//]: # (**Phase 2 - Encryption Layer**)

[//]: # (- Symmetric encryption &#40;AES-256-GCM, ChaCha20-Poly1305&#41;)

[//]: # (- Password-based encryption with Argon2id)

[//]: # (- Key derivation functions &#40;Argon2id, Scrypt&#41;)

[//]: # (- Secure metadata format)

[//]: # ()
[//]: # (**Phase 3 - Integrity & Authentication**)

[//]: # (- HMAC integrity checks &#40;SHA-256/384/512, SHA3, BLAKE2b&#41;)

[//]: # (- Digital signatures &#40;Ed25519, ECDSA P-256/P-384/P-521&#41;)

[//]: # (- Verification workflows)

[//]: # (- Detached metadata support &#40;.mac, .sig, .checksum files&#41;)

[//]: # (- Non-cryptographic checksums &#40;CRC32, Adler32, XXHash64&#41;)

[//]: # ()
[//]: # (**Phase 4 - CLI & SDK**)

[//]: # (- Full CLI with all operations)

[//]: # (- Python SDK &#40;`Filanti` class&#41;)

[//]: # (- JSON output for automation)

[//]: # (- Key management commands)

[//]: # (- Comprehensive test coverage)

[//]: # ()
[//]: # (**Phase 5 - Hardening & Extensions**)

[//]: # (- Streaming large-file support)

[//]: # (- Secure memory handling &#40;SecureBytes, SecureString&#41;)

[//]: # (- Performance optimizations)

[//]: # (- Plugin architecture)

[//]: # (- Security testing &#40;51+ security tests&#41;)

[//]: # ()
[//]: # (---)

[//]: # ()
[//]: # (## License)

[//]: # ()
[//]: # (MIT License)

[//]: # ()
[//]: # (Copyright &#40;c&#41; 2026 Filanti Contributors)

[//]: # ()
[//]: # (Permission is hereby granted, free of charge, to any person obtaining a copy)

[//]: # (of this software and associated documentation files &#40;the "Software"&#41;, to deal)

[//]: # (in the Software without restriction, including without limitation the rights)

[//]: # (to use, copy, modify, merge, publish, distribute, sublicense, and/or sell)

[//]: # (copies of the Software, and to permit persons to whom the Software is)

[//]: # (furnished to do so, subject to the following conditions:)

[//]: # ()
[//]: # (The above copyright notice and this permission notice shall be included in all)

[//]: # (copies or substantial portions of the Software.)

[//]: # ()
[//]: # (THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR)

[//]: # (IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,)

[//]: # (FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE)

[//]: # (AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER)

[//]: # (LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,)

[//]: # (OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE)

[//]: # (SOFTWARE.)

[//]: # ()
[//]: # (---)

[//]: # ()
[//]: # (<p align="center">)

[//]: # (  Made by Decliqe)

[//]: # (</p>)

[//]: # ()
