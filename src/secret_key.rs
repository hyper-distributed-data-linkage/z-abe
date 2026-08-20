use rabe::schemes::ac17::{
    cp_decrypt, cp_keygen, Ac17CpCiphertext, Ac17CpSecretKey, Ac17MasterKey,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

use crate::content_key::ContentKey;

#[derive(Error, Debug)]
pub enum SecretKeyError {
    #[error("Content key error: {0}")]
    ContentKeyError(#[from] crate::content_key::ContentKeyError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("Failed to decrypt content key: {0}")]
    FailedToDecryptContentKey(rabe::error::RabeError),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretKey {
    key: Ac17CpSecretKey,
}

impl SecretKey {
    pub fn new(msk: &Ac17MasterKey, attributes: &[&str]) -> Self {
        debug!("Creating SecretKey. attributes: {:?}", attributes);
        let sk = cp_keygen(msk, attributes).unwrap();
        Self { key: sk }
    }

    pub fn decrypt(&self, encrypted_content_key: &[u8]) -> Result<ContentKey, SecretKeyError> {
        debug!("Decrypting SecretKey");
        let ct: Ac17CpCiphertext = postcard::from_bytes(encrypted_content_key)?;
        let plaintext =
            cp_decrypt(&self.key, &ct).map_err(SecretKeyError::FailedToDecryptContentKey)?;
        debug!("policy: {:?}", &ct.policy);
        Ok(ContentKey::from_bytes(&plaintext)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, SecretKeyError> {
        Ok(postcard::to_allocvec(&self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SecretKeyError> {
        Ok(postcard::from_bytes(bytes)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ckl::ContentKeyLock;
    use rabe::{schemes::ac17::setup, utils::policy::pest::PolicyLanguage};

    #[test]
    fn test_secret_key() {
        // Attribute Authority
        let (pk, msk) = setup();
        let secret_key = SecretKey::new(&msk, &["A", "B"]);

        // Producer
        let content_key = ContentKey::new();
        let policy = String::from(r#""A" and "B""#);
        let encrypted_content_key =
            ContentKeyLock::encrypt(&pk, &policy, &content_key, PolicyLanguage::HumanPolicy)
                .unwrap();

        // Consumer
        let decrypted_content_key = secret_key.decrypt(&encrypted_content_key).unwrap();
        assert_eq!(content_key, decrypted_content_key);
    }

    #[test]
    fn test_secret_key_serialization() {
        let (_pk, msk) = setup();
        let key = SecretKey::new(&msk, &["A", "B"]);
        let bytes = key.to_bytes().unwrap();
        let key2 = SecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(key, key2);
    }
}
