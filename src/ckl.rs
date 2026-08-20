use rabe::{
    schemes::ac17::{cp_encrypt, Ac17PublicKey},
    utils::policy::pest::PolicyLanguage,
};
use thiserror::Error;

use crate::content_key::ContentKey;

#[derive(Error, Debug)]
pub enum ContentKeyLockError {
    #[error("Content key error: {0}")]
    ContentKeyError(#[from] crate::content_key::ContentKeyError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("Failed to encrypt content key: {0}")]
    FailedToEncryptContentKey(rabe::error::RabeError),
}

pub struct ContentKeyLock;

impl ContentKeyLock {
    pub fn encrypt(
        pk: &Ac17PublicKey,
        policy: &str,
        content_key: &ContentKey,
        language: PolicyLanguage,
    ) -> Result<Vec<u8>, ContentKeyLockError> {
        let plaintext = content_key.to_bytes()?;
        let cp = cp_encrypt(pk, policy, &plaintext, language)
            .map_err(ContentKeyLockError::FailedToEncryptContentKey)?;
        Ok(postcard::to_allocvec(&cp)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::secret_key::SecretKey;

    use super::*;
    use rabe::schemes::ac17::{cp_decrypt, cp_keygen, setup, Ac17CpCiphertext, Ac17CpSecretKey};

    #[test]
    #[ignore]
    fn test_ac17_cp() {
        let (pk, msk) = setup();
        let plaintext = String::from("our plaintext!").into_bytes();
        let policy = String::from(r#""A" and "B""#);
        let ct: Ac17CpCiphertext =
            cp_encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
        let sk: Ac17CpSecretKey = cp_keygen(&msk, &["A", "B"]).unwrap();
        assert_eq!(cp_decrypt(&sk, &ct).unwrap(), plaintext);
    }

    #[test]
    fn test_content_key_lock() {
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
}
