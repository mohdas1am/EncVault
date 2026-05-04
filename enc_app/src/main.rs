mod crypto;
mod errors;
mod kem;
mod server;
pub mod utils;

use clap::{Parser, Subcommand};
use errors::{AppError, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use zeroize::Zeroizing;

// ─── Data Structures ────────────────────────────────────────────────

/// JSON payload produced by encryption and consumed by decryption.
#[derive(Serialize, Deserialize)]
struct EncryptedPayload {
    /// ML-KEM ciphertext (base64).
    kem_ct: String,
    /// AES key encrypted by the key-encryption-key derived from the KEM shared secret (base64).
    enc_aes_key: String,
    /// Nonce used when encrypting the AES key (base64).
    key_nonce: String,
    /// User data encrypted by the AES key (base64).
    ciphertext: String,
    /// Nonce used when encrypting the user data (base64).
    msg_nonce: String,
}

// ─── CLI Definition ─────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "enc_app",
    version,
    about = "Post-quantum hybrid encryption using ML-KEM 768 + AES-256-GCM"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate an ML-KEM 768 keypair and write pk.b64 / sk.b64 to the current directory.
    Keygen,

    /// Encrypt plaintext data using a public key.
    Encrypt {
        /// Path to the public key file (base64-encoded).
        #[arg(long)]
        pk: String,

        /// Plaintext data to encrypt. If omitted, reads from stdin.
        #[arg(long)]
        data: Option<String>,

        /// Optional path to write the encrypted JSON output. Defaults to stdout.
        #[arg(long, short)]
        output: Option<String>,
    },

    /// Decrypt an encrypted JSON payload using a secret key.
    Decrypt {
        /// Path to the secret key file (base64-encoded).
        #[arg(long)]
        sk: String,

        /// Path to the encrypted JSON file. If omitted, reads from stdin.
        #[arg(long, short)]
        input: Option<String>,
    },

    /// Run a self-test: keygen → encrypt → decrypt roundtrip.
    Demo,

    /// Start the HTTP server with web UI.
    Server {
        /// Port to listen on (default: 8080).
        #[arg(long, short, default_value = "8080")]
        port: u16,
    },
}

// ─── Core Logic ─────────────────────────────────────────────────────

/// Encrypt `data` using a fresh AES-256-GCM key, then wrap that key
/// with a KEK derived from an ML-KEM shared secret.
pub fn encrypt_data(data: &str, pk_bytes: &[u8]) -> Result<String> {
    if data.is_empty() {
        return Err(AppError::InvalidInput("data must not be empty".into()));
    }

    // Step 1: Generate a random AES-256 data-encryption key.
    let mut aes_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *aes_key);

    // Step 2: ML-KEM encapsulation → (kem_ciphertext, shared_secret).
    let (kem_ct, shared_secret) = kem::encapsulate_key(pk_bytes)?;

    // Step 3: Derive a key-encryption key (KEK) from the shared secret.
    let kek = crypto::derive_key(&shared_secret)?;

    // Step 4: Encrypt the AES key under the KEK.
    let (enc_aes_key, key_nonce) = crypto::encrypt(&kek, &*aes_key)?;

    // Step 5: Encrypt the user data under the AES key.
    let (ciphertext, msg_nonce) = crypto::encrypt(&aes_key, data.as_bytes())?;

    let payload = EncryptedPayload {
        kem_ct: utils::b64e(&kem_ct),
        enc_aes_key: utils::b64e(&enc_aes_key),
        key_nonce: utils::b64e(&key_nonce),
        ciphertext: utils::b64e(&ciphertext),
        msg_nonce: utils::b64e(&msg_nonce),
    };

    serde_json::to_string_pretty(&payload).map_err(AppError::JsonError)
}

/// Decrypt the JSON envelope using the secret key.
pub fn decrypt_data(json_input: &str, sk_bytes: &[u8]) -> Result<String> {
    let payload: EncryptedPayload =
        serde_json::from_str(json_input).map_err(AppError::JsonError)?;

    let kem_ct = utils::b64d(&payload.kem_ct)?;
    let enc_aes_key = utils::b64d(&payload.enc_aes_key)?;
    let key_nonce_vec = utils::b64d(&payload.key_nonce)?;
    let ciphertext = utils::b64d(&payload.ciphertext)?;
    let msg_nonce_vec = utils::b64d(&payload.msg_nonce)?;

    // Validate nonce lengths.
    let key_nonce: [u8; 12] = key_nonce_vec.try_into().map_err(|v: Vec<u8>| {
        AppError::InvalidNonceLength {
            expected: 12,
            actual: v.len(),
        }
    })?;
    let msg_nonce: [u8; 12] = msg_nonce_vec.try_into().map_err(|v: Vec<u8>| {
        AppError::InvalidNonceLength {
            expected: 12,
            actual: v.len(),
        }
    })?;

    // Step 1: Decapsulate to recover the shared secret.
    let shared_secret = kem::decapsulate_key(&kem_ct, sk_bytes)?;

    // Step 2: Derive KEK from the shared secret.
    let kek = crypto::derive_key(&shared_secret)?;

    // Step 3: Decrypt the AES key.
    let aes_key_vec = Zeroizing::new(crypto::decrypt(&kek, &enc_aes_key, &key_nonce)?);
    let aes_key: Zeroizing<[u8; 32]> = {
        let len = aes_key_vec.len();
        let arr: [u8; 32] = (*aes_key_vec).clone().try_into().map_err(|_| {
            AppError::InvalidKeyLength {
                expected: 32,
                actual: len,
            }
        })?;
        Zeroizing::new(arr)
    };

    // Step 4: Decrypt the message.
    let plaintext = crypto::decrypt(&aes_key, &ciphertext, &msg_nonce)?;

    String::from_utf8(plaintext).map_err(AppError::Utf8Error)
}

// ─── Subcommand Handlers ────────────────────────────────────────────

fn cmd_keygen() -> Result<()> {
    let (pk, sk) = kem::keygen();
    fs::write("pk.b64", utils::b64e(&pk))?;
    fs::write("sk.b64", utils::b64e(&sk))?;
    eprintln!("✔ Keypair written to pk.b64 and sk.b64");
    Ok(())
}

fn cmd_encrypt(pk_path: &str, data: Option<String>, output: Option<String>) -> Result<()> {
    let pk_b64 = fs::read_to_string(pk_path)
        .map_err(|e| AppError::InvalidInput(format!("cannot read public key file '{pk_path}': {e}")))?;
    let pk = utils::b64d(pk_b64.trim())?;

    let plaintext = match data {
        Some(d) => d,
        None => {
            eprintln!("Reading plaintext from stdin (end with Ctrl+D)...");
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let json_out = encrypt_data(&plaintext, &pk)?;

    match output {
        Some(path) => {
            fs::write(&path, &json_out)?;
            eprintln!("✔ Encrypted payload written to {path}");
        }
        None => println!("{json_out}"),
    }

    Ok(())
}

fn cmd_decrypt(sk_path: &str, input: Option<String>) -> Result<()> {
    let sk_b64 = fs::read_to_string(sk_path)
        .map_err(|e| AppError::InvalidInput(format!("cannot read secret key file '{sk_path}': {e}")))?;
    let sk = utils::b64d(sk_b64.trim())?;

    let json_input = match input {
        Some(path) => fs::read_to_string(&path)
            .map_err(|e| AppError::InvalidInput(format!("cannot read input file '{path}': {e}")))?,
        None => {
            eprintln!("Reading encrypted JSON from stdin (end with Ctrl+D)...");
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let plaintext = decrypt_data(&json_input, &sk)?;
    println!("{plaintext}");

    Ok(())
}

fn cmd_demo() -> Result<()> {
    println!("═══ ML-KEM 768 + AES-256-GCM  Demo ═══\n");

    // Generate keypair.
    let (pk, sk) = kem::keygen();
    println!("✔ Keypair generated (pk: {} bytes, sk: {} bytes)", pk.len(), sk.len());

    let data = r#"{"name":"Alice","amount":100}"#;
    println!("  Plaintext : {data}");

    // Encrypt.
    let encrypted = encrypt_data(data, &pk)?;
    println!("\n✔ Encrypted payload:\n{encrypted}");

    // Decrypt.
    let decrypted = decrypt_data(&encrypted, &sk)?;
    println!("\n✔ Decrypted : {decrypted}");

    assert_eq!(data, decrypted, "roundtrip mismatch");
    println!("\n✔ Roundtrip verification passed.");

    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen => cmd_keygen(),
        Commands::Encrypt { pk, data, output } => cmd_encrypt(&pk, data, output),
        Commands::Decrypt { sk, input } => cmd_decrypt(&sk, input),
        Commands::Demo => cmd_demo(),
        Commands::Server { port } => {
            if let Err(e) = server::run_server(port).await {
                eprintln!("Server error: {e}");
                std::process::exit(1);
            }
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ─── Integration Tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_roundtrip() {
        let (pk, sk) = kem::keygen();
        let data = "Hello, post-quantum world! 🌍";
        let encrypted = encrypt_data(data, &pk).expect("encrypt_data failed");
        let decrypted = decrypt_data(&encrypted, &sk).expect("decrypt_data failed");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_roundtrip_large_payload() {
        let (pk, sk) = kem::keygen();
        let data = "A".repeat(100_000);
        let encrypted = encrypt_data(&data, &pk).expect("encrypt_data failed");
        let decrypted = decrypt_data(&encrypted, &sk).expect("decrypt_data failed");
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_empty_data_rejected() {
        let (pk, _) = kem::keygen();
        let result = encrypt_data("", &pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (pk1, _sk1) = kem::keygen();
        let (_pk2, sk2) = kem::keygen();
        let data = "secret message";
        let encrypted = encrypt_data(data, &pk1).expect("encrypt_data failed");
        // Decrypting with a different secret key should fail.
        let result = decrypt_data(&encrypted, &sk2);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (pk, sk) = kem::keygen();
        let encrypted = encrypt_data("test", &pk).expect("encrypt_data failed");

        let mut payload: EncryptedPayload =
            serde_json::from_str(&encrypted).expect("deserialize");
        // Tamper with the ciphertext.
        let mut ct_bytes = utils::b64d(&payload.ciphertext).unwrap();
        ct_bytes[0] ^= 0xFF;
        payload.ciphertext = utils::b64e(&ct_bytes);
        let tampered = serde_json::to_string(&payload).unwrap();

        let result = decrypt_data(&tampered, &sk);
        assert!(result.is_err(), "tampered ciphertext must be rejected");
    }
}