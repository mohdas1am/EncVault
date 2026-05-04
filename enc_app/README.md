# enc_app — Post-Quantum Hybrid Encryption

A production-safe standalone CLI application that encrypts user data using a **KEM-DEM** (Key Encapsulation Mechanism – Data Encapsulation Mechanism) architecture combining **ML-KEM 768** (NIST FIPS 203) for post-quantum key exchange and **AES-256-GCM** for authenticated symmetric encryption.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Installation](#installation)
- [Usage](#usage)
- [Encrypted Payload Format](#encrypted-payload-format)
- [Module Reference](#module-reference)
- [Security Properties](#security-properties)
- [Testing](#testing)
- [Dependencies](#dependencies)
- [Threat Model & Limitations](#threat-model--limitations)

---

## Overview

This application provides end-to-end encryption of arbitrary user data using a two-layer key wrapping scheme:

1. **Data Encryption**: User data is encrypted with a randomly generated AES-256-GCM key (the **Data Encryption Key**, or DEK).
2. **Key Wrapping**: The DEK is encrypted using a **Key Encryption Key** (KEK) derived from an ML-KEM shared secret via HKDF-SHA256.
3. **Key Encapsulation**: ML-KEM 768 encapsulation produces the shared secret and a KEM ciphertext that only the secret key holder can decapsulate.

The recipient uses their ML-KEM secret key to decapsulate → derive the KEK → unwrap the DEK → decrypt the data.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        ENCRYPTION                            │
│                                                              │
│  User Data ──┐                                               │
│              │                                               │
│              ▼                                               │
│  ┌─────────────────────┐    AES-256-GCM     ┌─────────────┐ │
│  │ Random AES-256 Key  │───────────────────▶ │  Ciphertext │ │
│  │       (DEK)         │                     │  + msg_nonce│ │
│  └────────┬────────────┘                     └─────────────┘ │
│           │                                                  │
│           │  Wrapped by KEK                                  │
│           ▼                                                  │
│  ┌─────────────────────┐    AES-256-GCM     ┌─────────────┐ │
│  │ Key Encryption Key  │───────────────────▶ │enc_aes_key  │ │
│  │       (KEK)         │                     │+ key_nonce  │ │
│  └────────┬────────────┘                     └─────────────┘ │
│           │                                                  │
│           │  Derived via HKDF-SHA256                         │
│           │                                                  │
│  ┌─────────────────────┐                     ┌─────────────┐ │
│  │   Shared Secret     │  ML-KEM 768        │  kem_ct      │ │
│  │  (from encapsulate) │◀───────────────────│ (1088 bytes) │ │
│  └─────────────────────┘   + Public Key      └─────────────┘ │
│                                                              │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                        DECRYPTION                            │
│                                                              │
│  kem_ct + Secret Key                                         │
│        │                                                     │
│        ▼  ML-KEM decapsulate                                 │
│  Shared Secret                                               │
│        │                                                     │
│        ▼  HKDF-SHA256                                        │
│      KEK                                                     │
│        │                                                     │
│        ▼  AES-256-GCM decrypt (enc_aes_key, key_nonce)       │
│      DEK (AES-256 key)                                       │
│        │                                                     │
│        ▼  AES-256-GCM decrypt (ciphertext, msg_nonce)        │
│   Original Data                                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Cryptographic Design

### Algorithm Selection

| Component              | Algorithm               | Standard       | Key/Output Size |
|------------------------|-------------------------|----------------|-----------------|
| Key Encapsulation      | ML-KEM 768              | NIST FIPS 203  | SS: 32 B, CT: 1088 B |
| Symmetric Encryption   | AES-256-GCM             | NIST SP 800-38D | Key: 32 B, Nonce: 12 B |
| Key Derivation         | HKDF-SHA256             | RFC 5869       | 32 B output     |
| Encoding               | Base64 (standard)       | RFC 4648       | —               |

### Key Hierarchy

```
ML-KEM 768 Keypair
    │
    ├── Public Key (1184 bytes)  →  used by sender for encapsulation
    └── Secret Key (2400 bytes)  →  used by recipient for decapsulation
              │
              ▼
        Shared Secret (32 bytes)
              │
              ▼  HKDF-SHA256 (info: "aes-key-wrapping")
        Key Encryption Key / KEK (32 bytes)
              │
              ▼  Wraps / Unwraps
        Data Encryption Key / DEK (32 bytes, random)
              │
              ▼  Encrypts / Decrypts
        User Data
```

### Why ML-KEM + AES (KEM-DEM)?

- **Quantum Resistance**: ML-KEM 768 is standardized by NIST (FIPS 203) as a post-quantum secure KEM, providing IND-CCA2 security against both classical and quantum adversaries.
- **Performance**: AES-256-GCM provides hardware-accelerated authenticated encryption for bulk data, while ML-KEM handles only the 32-byte key exchange.
- **Key Isolation**: The two-layer key wrapping (DEK wrapped by KEK) ensures that the DEK never touches the KEM directly, providing clean cryptographic separation.

---

## Installation

### Prerequisites

- **Rust toolchain** ≥ 1.70.0 (edition 2021)
- **C compiler** (for `pqcrypto` native bindings) — `gcc` or `clang`

### Build

```bash
# Clone / navigate to the project
cd enc_app

# Debug build
cargo build

# Release build (optimized)
cargo build --release
```

The release binary is located at `target/release/enc_app`.

---

## Usage

### Quick Demo (Self-Test)

```bash
cargo run -- demo
```

Runs a full keygen → encrypt → decrypt roundtrip with sample data and verifies correctness.

### Generate Keypair

```bash
cargo run -- keygen
```

Writes two files to the current directory:

| File     | Contents                        | Size     |
|----------|---------------------------------|----------|
| `pk.b64` | ML-KEM 768 public key (base64) | ~1580 B  |
| `sk.b64` | ML-KEM 768 secret key (base64) | ~3200 B  |

> **⚠️ Security**: Protect `sk.b64` — anyone with this file can decrypt all messages encrypted to the corresponding public key.

### Encrypt Data

```bash
# From command-line argument
cargo run -- encrypt --pk pk.b64 --data "Hello, post-quantum world!"

# From command-line argument, save to file
cargo run -- encrypt --pk pk.b64 --data "secret message" -o encrypted.json

# From stdin
echo "sensitive data" | cargo run -- encrypt --pk pk.b64

# From a file via stdin
cat document.txt | cargo run -- encrypt --pk pk.b64 -o encrypted.json
```

**Options:**

| Flag         | Required | Description                                      |
|--------------|----------|--------------------------------------------------|
| `--pk`       | Yes      | Path to the public key file (`pk.b64`)           |
| `--data`     | No       | Plaintext string to encrypt (reads stdin if omitted) |
| `-o/--output`| No       | Output file path (prints to stdout if omitted)   |

### Decrypt Data

```bash
# From file
cargo run -- decrypt --sk sk.b64 -i encrypted.json

# From stdin (pipe)
cargo run -- encrypt --pk pk.b64 --data "test" | cargo run -- decrypt --sk sk.b64

# From stdin (interactive)
cargo run -- decrypt --sk sk.b64
# Paste JSON, then Ctrl+D
```

**Options:**

| Flag         | Required | Description                                      |
|--------------|----------|--------------------------------------------------|
| `--sk`       | Yes      | Path to the secret key file (`sk.b64`)           |
| `-i/--input` | No       | Input file path (reads stdin if omitted)         |

### Web Server (GUI)

The application includes a built-in HTTP server exposing a web-based UI for managing accounts and exchanging encrypted files.

```bash
# Start the server on port 8080
cargo run -- server --port 8080

# Specify a custom port
cargo run -- server --port 3000
```

Once running, navigate to `http://localhost:8080` in your browser. The web UI allows you to:
- Sign up and auto-generate ML-KEM keypairs securely.
- Exchange fully encrypted messages with other users.
- Automatically track your Inbox and Sent files.

### Help

```bash
cargo run -- --help
cargo run -- encrypt --help
cargo run -- decrypt --help
cargo run -- server --help
```

---

## Encrypted Payload Format

The encryption output is a JSON object with all binary fields base64-encoded:

```json
{
  "kem_ct":      "<base64>",
  "enc_aes_key": "<base64>",
  "key_nonce":   "<base64>",
  "ciphertext":  "<base64>",
  "msg_nonce":   "<base64>"
}
```

| Field          | Raw Size       | Description                                              |
|----------------|----------------|----------------------------------------------------------|
| `kem_ct`       | 1088 bytes     | ML-KEM 768 ciphertext (encapsulated shared secret)       |
| `enc_aes_key`  | 48 bytes       | AES-256-GCM encrypted DEK (32 B key + 16 B auth tag)    |
| `key_nonce`    | 12 bytes       | Nonce used to encrypt the DEK                            |
| `ciphertext`   | `len(data)+16` | AES-256-GCM encrypted user data (data + 16 B auth tag)  |
| `msg_nonce`    | 12 bytes       | Nonce used to encrypt the user data                      |

---

## Module Reference

### `main.rs` — Application Entry Point & CLI

| Function          | Signature                                              | Description |
|-------------------|--------------------------------------------------------|-------------|
| `encrypt_data`    | `fn(data: &str, pk_bytes: &[u8]) -> Result<String>`   | Core encryption pipeline: generates DEK, encapsulates, derives KEK, wraps DEK, encrypts data. Returns JSON string. |
| `decrypt_data`    | `fn(json_input: &str, sk_bytes: &[u8]) -> Result<String>` | Core decryption pipeline: decapsulates, derives KEK, unwraps DEK, decrypts data. Returns plaintext. |
| `cmd_keygen`      | `fn() -> Result<()>`                                   | Generates keypair and writes `pk.b64`, `sk.b64`.   |
| `cmd_encrypt`     | `fn(pk_path, data, output) -> Result<()>`              | CLI handler for encryption.                         |
| `cmd_decrypt`     | `fn(sk_path, input) -> Result<()>`                     | CLI handler for decryption.                         |
| `cmd_demo`        | `fn() -> Result<()>`                                   | Self-test roundtrip demonstration.                  |

### `server.rs` — Web API & Backend

| Component         | Description                                              |
|-------------------|----------------------------------------------------------|
| **Actix-Web API** | Endpoints for `/api/signup`, `/api/login`, `/api/encrypt`, `/api/decrypt` etc. |
| **State Mgt**     | In-memory `Mutex<AppState>` tracking `users`, `files`, and `sessions`. |
| **Static Files**  | Serves `index.html`, `style.css`, and `app.js` from the `./static` directory. |

### `kem.rs` — ML-KEM 768 Key Encapsulation

| Function          | Signature                                                 | Description |
|-------------------|-----------------------------------------------------------|-------------|
| `keygen`          | `fn() -> (Vec<u8>, Vec<u8>)`                              | Generate ML-KEM 768 keypair. Returns `(public_key, secret_key)`. |
| `encapsulate_key` | `fn(pk_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>`       | Encapsulate against a public key. Returns `(kem_ciphertext, shared_secret)`. |
| `decapsulate_key` | `fn(ct_bytes: &[u8], sk_bytes: &[u8]) -> Result<Vec<u8>>` | Decapsulate a KEM ciphertext. Returns the shared secret. |

### `crypto.rs` — AES-256-GCM & HKDF

| Function     | Signature                                                          | Description |
|--------------|--------------------------------------------------------------------|-------------|
| `derive_key` | `fn(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>>`         | Derives a 256-bit key from a shared secret using HKDF-SHA256 with info `"aes-key-wrapping"`. Returns zeroizing wrapper. |
| `encrypt`    | `fn(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])>` | Encrypts with AES-256-GCM using a random 96-bit nonce from `OsRng`. Returns `(ciphertext_with_tag, nonce)`. |
| `decrypt`    | `fn(aes_key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>>` | Decrypts AES-256-GCM ciphertext. Verifies the authentication tag. |

### `errors.rs` — Error Types

Defines `AppError` enum with variants for every failure mode:

| Variant                  | Trigger                                              |
|--------------------------|------------------------------------------------------|
| `KemEncapsulationFailed` | Invalid public key bytes                             |
| `KemDecapsulationFailed` | Invalid ciphertext or secret key bytes               |
| `AesEncryptionFailed`    | AES-GCM encryption error                            |
| `AesDecryptionFailed`    | AES-GCM decryption / authentication failure          |
| `KeyDerivationFailed`    | HKDF expansion error                                |
| `Base64DecodeFailed`     | Malformed base64 input                               |
| `JsonError`              | JSON serialization / deserialization error            |
| `IoError`                | File read/write or stdin error                       |
| `InvalidInput`           | Empty data, missing files, etc.                      |
| `InvalidKeyLength`       | Recovered AES key is not 32 bytes                    |
| `InvalidNonceLength`     | Decoded nonce is not 12 bytes                        |
| `Utf8Error`              | Decrypted bytes are not valid UTF-8                  |

### `utils.rs` — Encoding Utilities

| Function | Signature                        | Description |
|----------|----------------------------------|-------------|
| `b64e`   | `fn(data: &[u8]) -> String`     | Encode bytes to base64 (standard alphabet). |
| `b64d`   | `fn(data: &str) -> Result<Vec<u8>>` | Decode base64 to bytes with error handling. |

---

## Security Properties

### Achieved

| Property                     | Mechanism                                                   |
|------------------------------|-------------------------------------------------------------|
| **Confidentiality**          | AES-256-GCM encryption of data; KEK wrapping of DEK        |
| **Integrity & Authenticity** | AES-GCM 128-bit authentication tags on both layers          |
| **Post-Quantum Security**    | ML-KEM 768 (NIST Security Level 3, IND-CCA2)               |
| **Forward Secrecy**          | Fresh DEK generated per encryption; fresh KEM encapsulation |
| **Key Zeroization**          | `Zeroizing<>` wrappers erase DEK and KEK from memory on drop |
| **CSPRNG**                   | `OsRng` (OS-level cryptographic RNG) for all randomness     |
| **Tamper Detection**         | Any modification to ciphertext, nonce, or wrapped key is rejected |

### HKDF Parameters

| Parameter | Value               |
|-----------|---------------------|
| Hash      | SHA-256             |
| Salt      | None (zeroed)       |
| IKM       | ML-KEM shared secret (32 bytes) |
| Info      | `b"aes-key-wrapping"` |
| Output    | 32 bytes            |

---

## Testing

### Run All Tests

```bash
cargo test
```

### Test Suite (11 tests)

**KEM Module** (`kem::tests`):

| Test                         | Validates                                           |
|------------------------------|-----------------------------------------------------|
| `test_kem_roundtrip`         | Encapsulate → decapsulate produces matching shared secrets; ciphertext is 1088 B |
| `test_encapsulate_invalid_pk`| Rejects malformed public key bytes                   |
| `test_decapsulate_invalid_ct`| Rejects malformed ciphertext bytes                   |

**Crypto Module** (`crypto::tests`):

| Test                            | Validates                                       |
|---------------------------------|-------------------------------------------------|
| `test_aes_roundtrip`           | Encrypt → decrypt recovers original plaintext    |
| `test_aes_decrypt_wrong_key_fails` | Wrong key produces authentication failure    |
| `test_derive_key_deterministic`| Same shared secret → same derived key            |

**Integration** (`tests`):

| Test                          | Validates                                          |
|-------------------------------|----------------------------------------------------|
| `test_full_roundtrip`         | Full pipeline with Unicode data                    |
| `test_roundtrip_large_payload`| 100 KB payload roundtrip                           |
| `test_empty_data_rejected`    | Empty string input returns `InvalidInput` error    |
| `test_decrypt_wrong_key_fails`| Decryption with a different SK fails               |
| `test_tampered_ciphertext_fails` | Flipping a ciphertext byte causes auth failure  |

---

## Dependencies

| Crate              | Version | Purpose                                      |
|--------------------|---------|----------------------------------------------|
| `pqcrypto-mlkem`   | 0.1     | ML-KEM 768 key generation, encapsulation, decapsulation |
| `pqcrypto-traits`  | 0.3     | Trait interfaces for PQCrypto types          |
| `aes-gcm`          | 0.10    | AES-256-GCM authenticated encryption         |
| `hkdf`             | 0.12    | HKDF-SHA256 key derivation                   |
| `sha2`             | 0.10    | SHA-256 hash function (used by HKDF)         |
| `rand`             | 0.8     | `OsRng` cryptographically secure RNG         |
| `serde`            | 1.0     | Serialization framework                      |
| `serde_json`       | 1.0     | JSON serialization / deserialization         |
| `base64`           | 0.21    | Base64 encoding / decoding                   |
| `clap`             | 4       | Command-line argument parsing                |
| `thiserror`        | 1.0     | Ergonomic error type derivation              |
| `zeroize`          | 1       | Secure memory erasure of sensitive key material |
| `actix-web`        | 4       | HTTP web framework for the backend server    |
| `actix-files`      | 0.6     | Serve static frontend assets (`html`/`js`)   |
| `uuid`             | 1       | Session token generation                     |
| `chrono`           | 0.4     | Timestamping functionality                   |

---

## Threat Model & Limitations

### In Scope

- Encryption of data at rest or in transit between two parties
- Protection against classical and quantum passive/active adversaries on the ciphertext
- Tamper detection on ciphertext, wrapped key, and nonces

### Out of Scope / Limitations

| Limitation                    | Explanation                                                  |
|-------------------------------|--------------------------------------------------------------|
| **No key storage encryption** | `sk.b64` is stored as plaintext. In production, wrap the secret key with a passphrase (e.g., Argon2 + AES) or use a secure enclave / HSM. |
| **No key rotation**           | Each keypair is static. Implement key versioning and rotation policies for long-lived deployments. |
| **No multi-recipient**        | Each encryption targets a single public key. For multi-recipient, encapsulate separately per recipient. |
| **No streaming**              | Entire plaintext is loaded into memory. For very large files (>1 GB), consider chunked encryption with a streaming AEAD. |
| **No hybrid classical+PQ**    | Uses ML-KEM only (no X25519 hybrid). For defense-in-depth, a production system may combine ML-KEM with X25519. |
| **Nonce collision risk**      | AES-GCM nonces are 96-bit random. Collision probability is negligible at ~2^48 encryptions per key (birthday bound). Since each key is ephemeral, this is effectively zero risk. |

---

## Project Structure

```
enc_app/
├── Cargo.toml          # Package manifest & dependencies
├── Cargo.lock          # Locked dependency versions
├── static/             # Frontend Application
│   ├── app.js          # Client-side web logic
│   ├── index.html      # Main application view & auth forms
│   └── style.css       # Premium dark glassmorphism styling
└── src/
    ├── main.rs         # CLI, data structures, encrypt/decrypt pipelines, tests
    ├── kem.rs          # ML-KEM 768 keygen / encapsulate / decapsulate
    ├── crypto.rs       # AES-256-GCM encrypt/decrypt, HKDF key derivation
    ├── server.rs       # Actix-web server for the Web interface
    ├── errors.rs       # AppError enum (thiserror)
    └── utils.rs        # Base64 encoding/decoding helpers
```

---

## License

*Specify your license here.*
