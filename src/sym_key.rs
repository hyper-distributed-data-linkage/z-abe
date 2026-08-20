use aes_gcm::{
    aead::{generic_array, Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Error, Key, Nonce,
};
use generic_array::typenum::U12;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymKeyError {
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("Failed to encrypt content: {0}")]
    FailedToEncryptContent(Error),
    #[error("Failed to decrypt content: {0}")]
    FailedToDecryptContent(Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SymKey {
    #[serde(with = "serde_bytes")]
    pub key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>,
}

impl Default for SymKey {
    fn default() -> Self {
        Self::new()
    }
}

impl SymKey {
    pub fn new() -> Self {
        let key = Aes256Gcm::generate_key(OsRng);
        let nonce = Aes256Gcm::generate_nonce(OsRng);

        Self {
            key: key.to_vec(),
            nonce: nonce.to_vec(),
        }
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.key))
    }

    fn nonce(&self) -> Nonce<U12> {
        Nonce::<U12>::from_slice(&self.nonce).to_owned()
    }

    pub fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, SymKeyError> {
        self.cipher()
            .encrypt(&self.nonce(), content)
            .map_err(SymKeyError::FailedToEncryptContent)
    }

    pub fn decrypt(&self, encrypted_content: &[u8]) -> Result<Vec<u8>, SymKeyError> {
        self.cipher()
            .decrypt(&self.nonce(), encrypted_content)
            .map_err(SymKeyError::FailedToDecryptContent)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SymKeyError> {
        Ok(postcard::to_allocvec(&self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SymKeyError> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sym_key() {
        let sym_key = SymKey::new();
        let content = b"Hello, world!";
        let encrypted_content = sym_key.encrypt(content).unwrap();

        let decrypted_content = sym_key.decrypt(&encrypted_content).unwrap();
        assert_eq!(content, decrypted_content.as_slice());
    }

    #[test]
    fn test_sym_key_serialization() {
        let key = SymKey::new();
        let bytes = key.to_bytes().unwrap();
        let key2 = SymKey::from_bytes(&bytes).unwrap();
        assert_eq!(key, key2);
    }
}
