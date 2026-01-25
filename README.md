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
  <a href="#security-model">Security</a>
</p>

---

## Overview

**Filanti** is a production-ready Python framework providing secure-by-default primitives for:

-  **File Encryption** - AES-256-GCM, ChaCha20-Poly1305 with password-based encryption
-  **Asymmetric Encryption** - Hybrid encryption with X25519, RSA-OAEP for multi-recipient file exchange
-  **Cryptographic Hashing** - SHA-256/384/512, SHA3, BLAKE2b
-  **Integrity Verification** - HMAC, digital signatures, checksums
-  **Streaming Support** - Memory-efficient processing of large files
-  **Plugin Architecture** - Extensible algorithm support
-  **ENV-Based Secrets** - Secure secret injection for automation workflows

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

# Asymmetric encryption (for secure file sharing)
keypair = Filanti.generate_asymmetric_keypair()
Filanti.save_asymmetric_keypair(keypair, "mykey.pem")
Filanti.hybrid_encrypt("secret.txt", ["recipient.pub"])
Filanti.hybrid_decrypt("secret.txt.henc", "mykey.pem")

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

# Asymmetric encryption (for secure file sharing)
filanti keygen-asymmetric mykey
filanti encrypt-pubkey secret.txt --pubkey recipient.pub
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem

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

###  ENV-Based Secrets

Secure secret injection for automation and CI/CD workflows. Avoid hardcoding passwords in scripts or command lines.

```python
import os
from filanti.api import Filanti

# Set secret in environment (done by CI/CD, Docker, etc.)
os.environ["ENCRYPT_PASSWORD"] = "my-secure-password"

# Use ENV reference - secret is resolved at runtime
Filanti.encrypt("secret.txt", password="ENV:ENCRYPT_PASSWORD")
Filanti.decrypt("secret.txt.enc", password="ENV:ENCRYPT_PASSWORD")

# Check if value is an ENV reference
Filanti.is_env_reference("ENV:MY_SECRET")  # True

# Resolve secret manually
password = Filanti.resolve_secret("ENV:ENCRYPT_PASSWORD")

# Redact secrets from output (for logging)
safe_text = Filanti.redact_secret("Password is secret123", "secret123")
# Returns: "Password is [REDACTED]"

# Create JSON-safe output with redacted secrets
data = {"password": "secret123", "user": "admin"}
safe = Filanti.safe_json_output(data, secret_keys=["password"])
# Returns: {"password": "[REDACTED]", "user": "admin"}
```

**CLI Support:**

```bash
# Set environment variable
export ENCRYPT_PASSWORD="my-secure-password"

# Use in CLI commands
filanti encrypt secret.txt --password ENV:ENCRYPT_PASSWORD
filanti decrypt secret.txt.enc --password ENV:ENCRYPT_PASSWORD
filanti mac file.txt --key ENV:HMAC_KEY
filanti sign document.pdf --key mykey --password ENV:KEY_PASSWORD
```

**Benefits:**
-  Secrets don't appear in command line or process listings
-  Works with CI/CD (GitHub Actions, GitLab CI, Jenkins)
-  Compatible with Docker/Kubernetes secrets
-  12-factor app compliance

###  Asymmetric / Hybrid Encryption

Public-key based encryption for secure file exchange between parties who don't share a secret key.

**How it works:**
1. Sender encrypts file with recipient's **public key**
2. A random session key is generated and encrypted for each recipient
3. Data is encrypted with fast symmetric AEAD (AES-256-GCM)
4. Recipient decrypts with their **private key**

| Algorithm | Description | Key Type |
|-----------|-------------|----------|
| `x25519` | Modern elliptic curve Diffie-Hellman (default) | 256-bit |
| `rsa-oaep` | RSA with OAEP padding | 2048/3072/4096-bit |

**Key Generation:**

```python
from filanti.api import Filanti

# Generate X25519 key pair (recommended)
keypair = Filanti.generate_asymmetric_keypair()
Filanti.save_asymmetric_keypair(keypair, "alice.pem")
# Creates: alice.pem (private) and alice.pub (public)

# Generate RSA key pair
keypair = Filanti.generate_asymmetric_keypair(
    algorithm="rsa-oaep",
    rsa_key_size=4096
)

# Generate with password protection
keypair = Filanti.generate_asymmetric_keypair(password="my-password")
```

**Encryption & Decryption:**

```python
from filanti.api import Filanti

# Encrypt file for a recipient
Filanti.hybrid_encrypt("secret.txt", ["recipient.pub"])
# Creates: secret.txt.henc

# Encrypt for multiple recipients
Filanti.hybrid_encrypt(
    "secret.txt",
    ["alice.pub", "bob.pub", "charlie.pub"],
    recipient_ids=["alice", "bob", "charlie"]
)

# Decrypt with private key
Filanti.hybrid_decrypt("secret.txt.henc", "my-key.pem")

# Decrypt with password-protected key
Filanti.hybrid_decrypt(
    "secret.txt.henc",
    "my-key.pem",
    password="key-password"
)

# Get file metadata
info = Filanti.get_hybrid_file_info("secret.txt.henc")
print(f"Recipients: {info.recipient_count}")
print(f"Algorithm: {info.asymmetric_algorithm}")
```

**Bytes Encryption:**

```python
from filanti.api import Filanti

# Encrypt bytes for recipients
encrypted = Filanti.hybrid_encrypt_bytes(
    b"secret data",
    ["recipient.pub"]
)

# Decrypt bytes
decrypted = Filanti.hybrid_decrypt_bytes(encrypted, "my-key.pem")
```

**CLI Usage:**

```bash
# Generate X25519 key pair
filanti keygen-asymmetric mykey

# Generate RSA key pair
filanti keygen-asymmetric mykey --algorithm rsa-oaep --rsa-size 4096

# Generate with password protection
filanti keygen-asymmetric mykey --protect

# Encrypt file for recipient
filanti encrypt-pubkey secret.txt --pubkey recipient.pub

# Encrypt for multiple recipients
filanti encrypt-pubkey secret.txt --pubkey alice.pub --pubkey bob.pub

# Decrypt with private key
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem

# Decrypt with password-protected key
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem --password "key-pass"

# Show hybrid file info
filanti info-hybrid secret.txt.henc
```

**Use Cases:**
-  **Secure file sharing** - Send encrypted files without exchanging passwords
-  **Team collaboration** - Encrypt for multiple team members at once
-  **End-to-end encryption** - Each recipient uses their own private key
-  **Key escrow** - Include backup recipient for recovery

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

# Encrypt with ENV-based secret (recommended for automation)
export ENCRYPT_PASSWORD="my-secure-password"
filanti encrypt secret.txt --password ENV:ENCRYPT_PASSWORD

# Encrypt with specific algorithm
filanti encrypt secret.txt -p "password" --algorithm chacha20-poly1305

# Specify output path
filanti encrypt secret.txt -o encrypted_file.bin -p "password"

# Decrypt
filanti decrypt secret.txt.enc --password "my-password"

# Decrypt with ENV-based secret
filanti decrypt secret.txt.enc --password ENV:ENCRYPT_PASSWORD

filanti decrypt secret.txt.enc -o original.txt -p "password"
```

### MAC (Integrity)

```bash
# Generate MAC with key
filanti mac file.txt --key "my-secret-key"

# Generate MAC with ENV-based secret (recommended)
export HMAC_KEY="my-hmac-secret-key"
filanti mac file.txt --key ENV:HMAC_KEY

# Generate MAC with hex key
filanti mac file.txt --key abc123def456...

# Create detached .mac file
filanti mac file.txt --key ENV:HMAC_KEY --create-file

# Verify MAC
filanti verify-mac file.txt --key ENV:HMAC_KEY
filanti verify-mac file.txt --key ENV:HMAC_KEY --mac-file file.txt.mac
```

### Digital Signatures

```bash
# Generate key pair
filanti keygen my_signing_key

# Generate protected key pair (encrypted private key)
filanti keygen my_signing_key --protect
# (prompts for password)

# Generate with ENV-based password
filanti keygen my_signing_key --password ENV:KEY_PASSWORD

# Generate with specific algorithm
filanti keygen my_key --algorithm ecdsa-p384

# Sign a file
filanti sign document.pdf --key my_signing_key

# Sign with password-protected key
filanti sign document.pdf --key my_signing_key --password "key-password"

# Sign with ENV-based password (recommended for automation)
filanti sign document.pdf --key my_signing_key --password ENV:KEY_PASSWORD

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

### Asymmetric / Hybrid Encryption

```bash
# Generate X25519 key pair (default)
filanti keygen-asymmetric mykey

# Generate with password protection
filanti keygen-asymmetric mykey --protect

# Generate RSA key pair
filanti keygen-asymmetric mykey --algorithm rsa-oaep --rsa-size 4096

# Generate with ENV-based password
filanti keygen-asymmetric mykey --password ENV:KEY_PASSWORD

# Encrypt file for recipient
filanti encrypt-pubkey secret.txt --pubkey recipient.pub

# Encrypt with specific algorithm
filanti encrypt-pubkey secret.txt --pubkey recipient.pub --algorithm rsa-oaep

# Encrypt for multiple recipients
filanti encrypt-pubkey secret.txt --pubkey alice.pub --pubkey bob.pub

# Encrypt with recipient IDs
filanti encrypt-pubkey secret.txt --pubkey alice.pub -r alice --pubkey bob.pub -r bob

# Specify output path
filanti encrypt-pubkey secret.txt --pubkey recipient.pub -o encrypted_file.henc

# Decrypt with private key
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem

# Decrypt with password-protected key
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem --password "key-pass"

# Decrypt with ENV-based password
filanti decrypt-privkey secret.txt.henc --privkey mykey.pem --password ENV:KEY_PASSWORD

# Show hybrid encrypted file metadata
filanti info-hybrid secret.txt.henc
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

#### Asymmetric / Hybrid Encryption Methods

| Method | Description |
|--------|-------------|
| `Filanti.generate_asymmetric_keypair(algorithm, password, rsa_key_size)` | Generate asymmetric key pair |
| `Filanti.save_asymmetric_keypair(keypair, private_path, public_path)` | Save key pair to files |
| `Filanti.hybrid_encrypt(path, public_keys, output, algorithm)` | Encrypt file for recipients |
| `Filanti.hybrid_decrypt(path, private_key, output, password)` | Decrypt hybrid encrypted file |
| `Filanti.hybrid_encrypt_bytes(data, public_keys, algorithm)` | Encrypt bytes for recipients |
| `Filanti.hybrid_decrypt_bytes(data, private_key, password)` | Decrypt hybrid encrypted bytes |
| `Filanti.get_hybrid_file_info(path)` | Get hybrid file metadata |

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

#### Secrets Methods

| Method | Description |
|--------|-------------|
| `Filanti.resolve_secret(value, allow_empty)` | Resolve ENV:VAR_NAME to value |
| `Filanti.is_env_reference(value)` | Check if value is ENV reference |
| `Filanti.redact_secret(text, secret)` | Redact secret from text |
| `Filanti.redact_secrets(text, secrets)` | Redact multiple secrets |
| `Filanti.safe_json_output(data, secrets, secret_keys)` | Create JSON with redacted secrets |

### Direct Module Access

For more control, use the underlying modules directly:

```python
# Hashing
from filanti.hashing import crypto_hash
digest = crypto_hash.hash_file("file.txt", "sha256")

# Encryption
from filanti.crypto import encrypt_file, decrypt_file
encrypt_file(input_path, output_path, key)

# Asymmetric/Hybrid Encryption
from filanti.crypto.asymmetric import (
    generate_asymmetric_keypair,
    hybrid_encrypt_file,
    hybrid_decrypt_file,
)
keypair = generate_asymmetric_keypair("x25519")
hybrid_encrypt_file(input_path, output_path, [keypair.public_key])

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

# Secrets
from filanti.core.secrets import resolve_secret, redact_secret
password = resolve_secret("ENV:MY_PASSWORD")
safe_output = redact_secret("Password is secret123", "secret123")
```

---

## Architecture

```
filanti/
├── core/              
│   ├── errors.py      
│   ├── file_manager.py 
│   ├── metadata.py    
│   ├── plugins.py     
│   ├── secrets.py     
│   └── secure_memory.py 
│
├── crypto/            
│   ├── encryption.py  
│   ├── decryption.py  
│   ├── key_management.py 
│   ├── kdf.py         
│   ├── streaming.py   
│   └── asymmetric.py  
│
├── hashing/           
│   └── crypto_hash.py 
│
├── integrity/        
│   ├── checksum.py    
│   ├── mac.py         
│   └── signature.py   
│
├── cli/               
│   └── main.py        
│
└── api/               
    └── sdk.py         
```

### Module Dependencies

```
api/sdk.py
    ├── hashing/crypto_hash.py
    ├── crypto/encryption.py
    ├── crypto/decryption.py
    ├── crypto/asymmetric.py
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

3. **Use hybrid encryption for secure file sharing**
   - X25519 recommended for performance and security
   - Protect private keys with passwords
   - Multi-recipient encryption for team collaboration

4. **Always verify signatures with trusted public keys**
   - Don't rely solely on embedded public keys

5. **Use HMAC for integrity when confidentiality isn't needed**
   - Faster than signatures
   - Requires shared secret key

6. **Use checksums only for accidental corruption**
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

### Hybrid Encrypted File Format (.henc)

```
FLAS           # Magic bytes (4 bytes) - "Filanti Asymmetric"
METADATA_LEN   # Metadata length (4 bytes)
METADATA_JSON  # Includes:
               #   - symmetric_algorithm
               #   - nonce
               #   - created_at
               #   - session_keys[] (one per recipient)
               #     - encrypted_key
               #     - ephemeral_public_key (X25519)
               #     - algorithm
               #     - recipient_id (optional)
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
    FilantiError,       
    FileOperationError, 
    HashingError,        
    ValidationError,     
    EncryptionError,     
    DecryptionError,     
    IntegrityError,      
    SignatureError,      
    SecretError,         
)

try:
    Filanti.decrypt("file.enc", password="wrong")
except DecryptionError as e:
    print(f"Decryption failed: {e}")
    print(f"Context: {e.context}")

# Handle missing ENV secrets
try:
    Filanti.encrypt("file.txt", password="ENV:MISSING_VAR")
except SecretError as e:
    print(f"Secret error: {e}")
    print(f"Missing variable: {e.env_var}")
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
## License


MIT License

[//]: # ()
[//]: # (Copyright &#40;c&#41; 2026 Filanti Contributors)

[//]: # ()
[//]: # ()
[//]: # (Permission is hereby granted, free of charge, to any person obtaining a copy)

[//]: # ()
[//]: # (of this software and associated documentation files &#40;the "Software"&#41;, to deal)

[//]: # ()
[//]: # (in the Software without restriction, including without limitation the rights)

[//]: # ()
[//]: # (to use, copy, modify, merge, publish, distribute, sublicense, and/or sell)

[//]: # ()
[//]: # (copies of the Software, and to permit persons to whom the Software is)

[//]: # ()
[//]: # (furnished to do so, subject to the following conditions:)

[//]: # ()
[//]: # ()
[//]: # (The above copyright notice and this permission notice shall be included in all)

[//]: # ()
[//]: # (copies or substantial portions of the Software.)

[//]: # ()
[//]: # ()
[//]: # (THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR)

[//]: # ()
[//]: # (IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,)

[//]: # ()
[//]: # (FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE)

[//]: # ()
[//]: # (AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER)

[//]: # ()
[//]: # (LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,)

[//]: # ()
[//]: # (OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE)

[//]: # ()
[//]: # (SOFTWARE.)


---


<p align="center">

  Made by Decliqe

</p>

[//]: # ()
