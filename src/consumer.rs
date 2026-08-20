use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};
use zenoh::bytes::ZBytes;
use zenoh::Session;

use crate::ckl::ContentKeyLockError;
use crate::config::*;
use crate::content_key::{ContentKey, ContentKeyError};
use crate::payload::{EncryptedSymSecretKeyPair, PayloadWithHeader};
use crate::secret_key::{SecretKey, SecretKeyError};
use crate::skl::{SecretKeyLock, SecretKeyLockError};

#[derive(Error, Debug)]
pub enum ConsumerError {
    #[error("Zenoh error: {0}")]
    ZenohError(#[from] zenoh::Error),
    #[error("Content key error: {0}")]
    ContentKeyError(#[from] ContentKeyError),
    #[error("Content key lock error: {0}")]
    ContentKeyLockError(#[from] ContentKeyLockError),
    #[error("Secret key error: {0}")]
    SecretKeyError(#[from] SecretKeyError),
    #[error("Secret key lock error: {0}")]
    SecretKeyLockError(#[from] SecretKeyLockError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
    #[error("Content key store error: {0}")]
    ContentKeyStoreError(String),
    #[error("No CK-ID found in header")]
    NoCkIdFound,
    #[error("No producer prefix found in header")]
    NoProducerPrefixFound,
    #[error("No content key found")]
    NoContentKeyFound,
}

#[derive(Clone, Debug)]
pub struct Consumer<S: ContentKeyStore> {
    session: Session,
    content_key_store: Arc<S>,
    rsa_private_key: Rsa<Private>,
}

impl<S: ContentKeyStore> Consumer<S> {
    pub fn new(session: Session, content_key_store: Arc<S>, rsa_private_key: Rsa<Private>) -> Self {
        Self {
            session,
            content_key_store,
            rsa_private_key,
        }
    }

    pub async fn get_secret_key(&self) -> Result<Option<SecretKey>, ConsumerError> {
        let public_key_der = self.rsa_private_key.public_key_to_der_pkcs1()?;
        debug!(
            ">> Preparing to send inquiry. key:'{}'",
            ATTRIBUTE_AUTHORITY_SK_KEY_EXPR
        );
        let replies = self
            .session
            .get(ATTRIBUTE_AUTHORITY_SK_KEY_EXPR)
            .payload(&public_key_der)
            .await?;

        while let Ok(reply) = replies.recv_async().await {
            if let Ok(sample) = reply.result() {
                let encrypted_sym_secret_key_pair: EncryptedSymSecretKeyPair =
                    postcard::from_bytes(&sample.payload().to_bytes())?;
                let secret_key =
                    SecretKeyLock::decrypt(&self.rsa_private_key, &encrypted_sym_secret_key_pair)?;
                return Ok(Some(secret_key));
            }
        }
        Ok(None)
    }

    pub async fn get_content_key(
        &self,
        payload: &ZBytes,
        secret_key: &SecretKey,
    ) -> Result<Option<ContentKey>, ConsumerError> {
        let payload_with_header: PayloadWithHeader = postcard::from_bytes(&payload.to_bytes())?;
        let PayloadWithHeader { header, body: _ } = payload_with_header;
        let ck_id = header.get(HEADER_CK_ID).ok_or(ConsumerError::NoCkIdFound)?;

        debug!("content key ID: {}", ck_id);

        let ck_opt = self.content_key_store.get_key(ck_id).await?;
        match ck_opt {
            Some(content_key) => {
                debug!("Reading CK from internal store");
                Ok(Some(content_key))
            }
            None => {
                let producer_prefix = header
                    .get(HEADER_PRODUCER_PREFIX)
                    .ok_or(ConsumerError::NoProducerPrefixFound)?;
                self.fetch_content_key(producer_prefix, ck_id, secret_key)
                    .await
            }
        }
    }

    pub async fn fetch_content_key(
        &self,
        producer_prefix: &str,
        ck_id: &str,
        secret_key: &SecretKey,
    ) -> Result<Option<ContentKey>, ConsumerError> {
        if let Some(ck) = self.content_key_store.get_key(ck_id).await? {
            debug!("Content key already cached. CK ID: {}", ck_id);
            return Ok(Some(ck));
        }

        let replies = self
            .session
            .get(format!("{}/CK/{}", producer_prefix, ck_id))
            .await?;

        while let Ok(reply) = replies.recv_async().await {
            if let Ok(sample) = reply.result() {
                let encrypted_content_key = sample.payload().to_bytes();
                debug!("Content key fetched. CK ID: {}", ck_id);
                let content_key = secret_key.decrypt(&encrypted_content_key)?;
                debug!("Content key decrypted. CK ID: {}", ck_id);
                self.content_key_store
                    .set_key(ck_id, content_key.clone())
                    .await?;
                debug!("Content key cached. CK ID: {}", ck_id);
                return Ok(Some(content_key));
            }
        }
        warn!("Content key not found for ck_id: {}", ck_id);
        Ok(None)
    }

    pub async fn decrypt(
        &self,
        payload: &ZBytes,
        secret_key: &SecretKey,
    ) -> Result<ZBytes, ConsumerError> {
        let content_key = self
            .get_content_key(payload, secret_key)
            .await?
            .ok_or(ConsumerError::NoContentKeyFound)?;

        // Decrypt the content using the content key
        let payload_with_header: PayloadWithHeader = postcard::from_bytes(&payload.to_bytes())?;
        let PayloadWithHeader {
            header: _,
            body: encrypted_content,
        } = payload_with_header;
        let decrypted_content = content_key.decrypt(&encrypted_content)?;

        debug!("Decrypted content with ck: {}", content_key.id());

        Ok(ZBytes::from(decrypted_content))
    }

    pub fn extract_next_ck_id(&self, payload: &ZBytes) -> Option<String> {
        let payload_with_header: PayloadWithHeader =
            postcard::from_bytes(&payload.to_bytes()).ok()?;
        payload_with_header
            .header
            .get(HEADER_NEXT_CK_ID)
            .map(|id| id.to_string())
    }
}

#[async_trait]
pub trait ContentKeyStore {
    async fn get_key(&self, ck_id: &str) -> Result<Option<ContentKey>, ConsumerError>;
    async fn set_key(&self, ck_id: &str, content_key: ContentKey) -> Result<(), ConsumerError>;
}

#[derive(Default, Clone, Debug)]
pub struct InMemoryContentKeyStore {
    inner: Arc<ArcSwap<HashMap<String, ContentKey>>>,
}

impl InMemoryContentKeyStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }
}

#[async_trait]
impl ContentKeyStore for InMemoryContentKeyStore {
    async fn get_key(&self, ck_id: &str) -> Result<Option<ContentKey>, ConsumerError> {
        let map_arc = self.inner.load();
        Ok(map_arc.get(ck_id).cloned())
    }

    async fn set_key(&self, ck_id: &str, content_key: ContentKey) -> Result<(), ConsumerError> {
        let k = ck_id.to_string();
        self.inner.rcu(|cur| {
            let mut next = (**cur).clone();
            next.insert(k.clone(), content_key.clone());
            Arc::new(next)
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_content_key_store() {
        let content_key_store = InMemoryContentKeyStore::new();
        let ck_id = "b3eb7c78c3c0198bcaae9dee69905c5d1f6ed9ac1a08380fa3a5185c5a3270ba"; // gitleaks:allow
        let content_key = ContentKey::new();

        content_key_store
            .set_key(ck_id, content_key.clone())
            .await
            .unwrap();

        assert_eq!(
            content_key_store.get_key(ck_id).await.unwrap(),
            Some(content_key)
        );
    }

    /// Helper to build a PayloadWithHeader serialized as ZBytes
    fn build_encrypted_payload(
        content_key: &ContentKey,
        plaintext: &[u8],
        producer_prefix: &str,
        next_ck_id: Option<&str>,
    ) -> ZBytes {
        let encrypted_body = content_key.encrypt(plaintext).unwrap();
        let mut header = HashMap::new();
        header.insert(HEADER_CK_ID.to_string(), content_key.id());
        header.insert(
            HEADER_PRODUCER_PREFIX.to_string(),
            producer_prefix.to_string(),
        );
        if let Some(id) = next_ck_id {
            header.insert(HEADER_NEXT_CK_ID.to_string(), id.to_string());
        }
        let payload = PayloadWithHeader {
            header,
            body: encrypted_body,
        };
        ZBytes::from(postcard::to_allocvec(&payload).unwrap())
    }

    /// Helper to create a Consumer with an InMemoryContentKeyStore
    async fn create_test_consumer() -> (
        Consumer<InMemoryContentKeyStore>,
        Arc<InMemoryContentKeyStore>,
    ) {
        let config = zenoh::Config::default();
        let session = zenoh::open(config).await.unwrap();
        let store = Arc::new(InMemoryContentKeyStore::new());
        let rsa_key = Rsa::generate(2048).unwrap();
        let consumer = Consumer::new(session, Arc::clone(&store), rsa_key);
        (consumer, store)
    }

    /// Helper to create a dummy SecretKey for tests that only need the cache-hit path
    fn create_test_secret_key() -> SecretKey {
        let (_pk, msk) = rabe::schemes::ac17::setup();
        SecretKey::new(&msk, &["A"])
    }

    /// get_secret_key returns Ok(None) when no Attribute Authority is available
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_secret_key() {
        let (consumer, _store) = create_test_consumer().await;
        let result = consumer.get_secret_key().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    /// get_content_key returns a cached content key without fetching from producer
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_content_key_cache_hit() {
        let (consumer, store) = create_test_consumer().await;
        let ck = ContentKey::new();
        let secret_key = create_test_secret_key();

        // Pre-populate the cache
        store.set_key(&ck.id(), ck.clone()).await.unwrap();

        let payload = build_encrypted_payload(&ck, b"hello", "producer", None);
        let result = consumer
            .get_content_key(&payload, &secret_key)
            .await
            .unwrap();
        assert_eq!(result, Some(ck));
    }

    /// fetch_and_cache_content_key returns the cached key if already present
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_fetch_and_cache_content_key_cache_hit() {
        let (consumer, store) = create_test_consumer().await;
        let ck = ContentKey::new();
        let ck_id = ck.id();
        let secret_key = create_test_secret_key();

        // Pre-populate the cache
        store.set_key(&ck_id, ck.clone()).await.unwrap();

        let result = consumer
            .fetch_content_key("producer", &ck_id, &secret_key)
            .await
            .unwrap();
        assert_eq!(result, Some(ck));
    }

    /// decrypt correctly decrypts a payload encrypted with a known content key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_decrypt() {
        let (consumer, store) = create_test_consumer().await;
        let ck = ContentKey::new();
        let secret_key = create_test_secret_key();
        let plaintext = b"test data for decryption";

        // Pre-populate the cache so decrypt can find the content key
        store.set_key(&ck.id(), ck.clone()).await.unwrap();

        let encrypted_payload = build_encrypted_payload(&ck, plaintext, "producer", None);
        let decrypted = consumer
            .decrypt(&encrypted_payload, &secret_key)
            .await
            .unwrap();
        assert_eq!(decrypted.to_bytes().as_ref(), plaintext);
    }

    /// extract_next_ck_id extracts the next CK ID from the payload header
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_extract_next_ck_id() {
        let (consumer, _store) = create_test_consumer().await;
        let ck = ContentKey::new();
        let next_id = "next-ck-id-12345";

        let payload = build_encrypted_payload(&ck, b"data", "producer", Some(next_id));
        let extracted = consumer.extract_next_ck_id(&payload);
        assert_eq!(extracted, Some(next_id.to_string()));
    }
}
