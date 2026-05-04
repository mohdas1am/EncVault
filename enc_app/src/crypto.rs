use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::{AppError, Result};

/// Derive a 256-bit AES key from a shared secret using HKDF-SHA256.
/// The returned key is wrapped in `Zeroizing` for automatic secure erasure.
pub fn derive_key(shared_secret: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"aes-key-wrapping", &mut *key)
        .map_err(|e| AppError::KeyDerivationFailed(e.to_string()))?;
    Ok(key)
}

/// Encrypt plaintext using AES-256-GCM with a random nonce.
/// Returns (ciphertext_with_tag, nonce).
pub fn encrypt(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| AppError::AesEncryptionFailed(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|e| AppError::AesEncryptionFailed(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext using AES-256-GCM.
pub fn decrypt(aes_key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(aes_key)
        .map_err(|e| AppError::AesDecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| AppError::AesDecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_roundtrip() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);

        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let (ct, nonce) = encrypt(&key, plaintext).expect("encrypt failed");
        let recovered = decrypt(&key, &ct, &nonce).expect("decrypt failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_aes_decrypt_wrong_key_fails() {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        OsRng.fill_bytes(&mut key1);
        OsRng.fill_bytes(&mut key2);

        let (ct, nonce) = encrypt(&key1, b"secret").expect("encrypt failed");
        let result = decrypt(&key2, &ct, &nonce);
        assert!(result.is_err(), "decrypt with wrong key must fail");
    }

    #[test]
    fn test_derive_key_deterministic() {
        let secret = b"test-shared-secret-material-1234";
        let k1 = derive_key(secret).expect("derive failed");
        let k2 = derive_key(secret).expect("derive failed");
        assert_eq!(*k1, *k2, "same input must produce same derived key");
    }
}