use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use thiserror::Error;
use tracing::debug;

use crate::{payload::EncryptedSymSecretKeyPair, secret_key::SecretKey, sym_key::SymKey};

#[derive(Error, Debug)]
pub enum SecretKeyLockError {
    #[error("Secret key error: {0}")]
    SecretKeyError(#[from] crate::secret_key::SecretKeyError),
    #[error("Sym key error: {0}")]
    SymKeyError(#[from] crate::sym_key::SymKeyError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
    #[error("Failed to encrypt secret key")]
    FailedToEncryptSecretKey,
    #[error("Failed to decrypt secret key")]
    FailedToDecryptSecretKey,
}

pub struct SecretKeyLock;

impl SecretKeyLock {
    pub fn encrypt(
        rsa_public_key: &Rsa<Public>,
        sym_key: &SymKey,
        secret_key: &SecretKey,
    ) -> Result<EncryptedSymSecretKeyPair, SecretKeyLockError> {
        debug!("Encrypting SecretKeyLock");
        let secret_key = secret_key.to_bytes()?;
        let encrypted_secret_key = sym_key.encrypt(&secret_key)?;
        let sym_key_bytes = sym_key.to_bytes()?;

        let mut encrypted_sym_key = vec![0; rsa_public_key.size() as usize];
        let len = rsa_public_key.public_encrypt(
            &sym_key_bytes,
            &mut encrypted_sym_key,
            Padding::PKCS1,
        )?;
        encrypted_sym_key.truncate(len);

        Ok(EncryptedSymSecretKeyPair {
            encrypted_sym_key,
            encrypted_secret_key,
        })
    }

    pub fn decrypt(
        rsa_private_key: &Rsa<Private>,
        encrypted_sym_secret_key_pair: &EncryptedSymSecretKeyPair,
    ) -> Result<SecretKey, SecretKeyLockError> {
        debug!("Decrypting SecretKeyLock");
        let EncryptedSymSecretKeyPair {
            encrypted_sym_key,
            encrypted_secret_key,
        } = encrypted_sym_secret_key_pair;

        let mut decrypted_sym_key = vec![0; rsa_private_key.size() as usize];
        let len = rsa_private_key.private_decrypt(
            encrypted_sym_key,
            &mut decrypted_sym_key,
            Padding::PKCS1,
        )?;
        decrypted_sym_key.truncate(len);

        let sym_key = SymKey::from_bytes(&decrypted_sym_key)?;
        let decrypted_secret_key = sym_key.decrypt(encrypted_secret_key)?;
        Ok(SecretKey::from_bytes(&decrypted_secret_key)?)
    }
}

#[cfg(test)]
mod test {
    use rabe::schemes::ac17::setup;

    use super::*;

    #[test]
    fn test_secret_key_lock() {
        // Consumer
        let private_key = Rsa::generate(2048).unwrap();
        let public_key_der = private_key.public_key_to_der_pkcs1().unwrap();

        // Attribute Authority
        let public_key = Rsa::public_key_from_der_pkcs1(&public_key_der).unwrap();
        let (_pk, msk) = setup();
        let secret_key = SecretKey::new(&msk, &["A", "B"]);
        let sym_key = SymKey::new();
        let encrypted_sym_secret_key_pair =
            SecretKeyLock::encrypt(&public_key, &sym_key, &secret_key).unwrap();

        // Consumer
        let decrypted_secret_key =
            SecretKeyLock::decrypt(&private_key, &encrypted_sym_secret_key_pair).unwrap();
        assert_eq!(secret_key, decrypted_secret_key);
    }
}
