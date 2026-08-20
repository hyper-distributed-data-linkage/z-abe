use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::sym_key::{SymKey, SymKeyError};

#[derive(Error, Debug)]
#[error(transparent)]
pub struct ContentKeyError(#[from] SymKeyError);

#[derive(Clone, Debug, PartialEq, Default)]
pub struct ContentKey(SymKey);

impl ContentKey {
    pub fn new() -> Self {
        Self(SymKey::new())
    }

    pub fn encrypt(&self, content: &[u8]) -> Result<Vec<u8>, ContentKeyError> {
        self.0.encrypt(content).map_err(ContentKeyError)
    }

    pub fn decrypt(&self, encrypted_content: &[u8]) -> Result<Vec<u8>, ContentKeyError> {
        self.0.decrypt(encrypted_content).map_err(ContentKeyError)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ContentKeyError> {
        self.0.to_bytes().map_err(ContentKeyError)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContentKeyError> {
        SymKey::from_bytes(bytes).map(Self).map_err(ContentKeyError)
    }

    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.0.key);
        hasher.update(&self.0.nonce);
        let hash = hasher.finalize();
        format!("{:02x}", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_key_hash() {
        let key1 = ContentKey::new();
        let key2 = ContentKey::new();

        let hash1 = key1.id();
        let hash2 = key2.id();
        println!("hash1: {}", hash1);
        println!("hash2: {}", hash2);
        assert_ne!(hash1, hash2);

        let hash1_again = key1.id();
        assert_eq!(hash1, hash1_again);
    }
}
