use arc_swap::ArcSwap;
use async_trait::async_trait;
use rabe::schemes::ac17::Ac17PublicKey;
use rabe::utils::policy::pest::PolicyLanguage;
use std::collections::HashMap;
use std::str::Utf8Error;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use zenoh::bytes::ZBytes;
use zenoh::Session;

use crate::ckl::{ContentKeyLock, ContentKeyLockError};
use crate::config::*;
use crate::content_key::{ContentKey, ContentKeyError};
use crate::payload::PayloadWithHeader;

#[derive(Error, Debug)]
pub enum ProducerError {
    #[error("Zenoh error: {0}")]
    ZenohError(#[from] zenoh::Error),
    #[error("Content key error: {0}")]
    ContentKeyError(#[from] ContentKeyError),
    #[error("Content key not found error: {0}")]
    ContentKeyNotFoundError(String),
    #[error("Content key lock error: {0}")]
    ContentKeyLockError(#[from] ContentKeyLockError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("Utf8Error error: {0}")]
    Utf8Error(#[from] Utf8Error),
}

#[derive(Clone, Debug)]
pub struct Producer<S: ContentKeyStore> {
    session: Session,
    content_key_store: Arc<S>,
    producer_prefix: String,
}

impl<S: ContentKeyStore> Producer<S> {
    pub fn new(session: Session, content_key_store: Arc<S>, producer_prefix: &str) -> Self {
        Self {
            session,
            content_key_store,
            producer_prefix: producer_prefix.to_string(),
        }
    }

    pub(crate) async fn generate_content_key(
        &self,
        topic: &str,
    ) -> Result<(String, ContentKey), ProducerError> {
        debug!("Generate CK");
        let content_key = ContentKey::new();
        let ck_id = content_key.id();
        self.content_key_store
            .add_ck(&ck_id, topic, content_key.clone())
            .await?;
        Ok((ck_id, content_key))
    }

    pub async fn get_content_key(&self, ck_id: &str) -> Result<ContentKey, ProducerError> {
        let content_key = match self.content_key_store.get_ck(ck_id).await? {
            Some((_, content_key)) => content_key,
            None => return Err(ProducerError::ContentKeyNotFoundError(ck_id.to_string())),
        };
        Ok(content_key)
    }

    pub async fn get_current_content_key(&self, topic: &str) -> Result<ContentKey, ProducerError> {
        if let Some((_ck_id, content_key)) = self.content_key_store.get_current_ck(topic).await? {
            return Ok(content_key);
        }
        Err(ProducerError::ContentKeyNotFoundError(format!(
            "No current content key found for topic '{}'. Call initialize_content_key first.",
            topic
        )))
    }

    pub fn encrypt<IntoZBytes>(
        &self,
        payload: IntoZBytes,
        content_key: &ContentKey,
        next_ck_id: Option<String>,
    ) -> Result<ZBytes, ProducerError>
    where
        IntoZBytes: Into<ZBytes>,
    {
        let payload: ZBytes = payload.into();
        let encrypted_payload = content_key.encrypt(&payload.to_bytes())?;

        let mut header = HashMap::new();
        header.insert(HEADER_CK_ID.to_string(), content_key.id());
        header.insert(
            HEADER_PRODUCER_PREFIX.to_string(),
            self.producer_prefix.clone(),
        );
        if let Some(next_id) = next_ck_id {
            header.insert(HEADER_NEXT_CK_ID.to_string(), next_id);
        }

        let payload = PayloadWithHeader {
            header,
            body: encrypted_payload,
        };

        Ok(ZBytes::from(postcard::to_allocvec(&payload)?))
    }

    pub async fn handle_content_key_query(&self) -> Result<(), ProducerError> {
        info!("Handling content key query");
        let queryable_key_expr = format!("{}/CK/*", self.producer_prefix);
        info!(">> Waiting for queries on ('{}')...", queryable_key_expr);

        let queryable = self
            .session
            .declare_queryable(&queryable_key_expr)
            .complete(true)
            .await?;

        while let Ok(query) = queryable.recv_async().await {
            let query_key_expr = query.key_expr();

            debug!(">> Received query ('{}')", query_key_expr.as_str());

            // Ignore query that contains wildcards
            if query_key_expr.is_wild() {
                continue;
            }

            // Get public key from attribute authority
            let abe_public_key = match self.get_public_key_from_attribute_authority().await? {
                Some(pk) => pk,
                None => {
                    warn!("Failed to get public key from attribute authority");
                    continue;
                }
            };

            debug!(">> Public key: {:?}", abe_public_key);

            let ck_id = query_key_expr
                .as_str()
                .strip_prefix(format!("{}/CK/", self.producer_prefix).as_str())
                .unwrap()
                .to_string();

            if let Some((topic, content_key)) = self.content_key_store.get_ck(&ck_id).await? {
                debug!(">> ContentKey: {:?}  ContentKey ID: {}", content_key, ck_id);

                // Get policy from access manager
                let policy = match self.get_policy_from_access_manager(&topic).await? {
                    Some(policy) => policy,
                    None => {
                        warn!("Failed to get policy from access manager, topic: {}", topic);
                        continue;
                    }
                };

                debug!(">> Policy: {:?}", policy);

                let encrypted_content_key = ContentKeyLock::encrypt(
                    &abe_public_key,
                    &policy,
                    &content_key,
                    PolicyLanguage::HumanPolicy,
                )?;
                query.reply(query_key_expr, encrypted_content_key).await?;
            } else {
                error!("Content key not found, CK ID: {}", ck_id);
            }
        }
        Ok(())
    }

    pub async fn get_public_key_from_attribute_authority(
        &self,
    ) -> Result<Option<Ac17PublicKey>, ProducerError> {
        debug!(
            ">> Preparing to send inquiry. key:'{}'",
            ATTRIBUTE_AUTHORITY_PK_KEY_EXPR
        );
        let replies = self.session.get(ATTRIBUTE_AUTHORITY_PK_KEY_EXPR).await?;

        while let Ok(reply) = replies.recv_async().await {
            if let Ok(sample) = reply.result() {
                let abe_public_key = sample.payload().to_bytes();
                let abe_public_key: Ac17PublicKey = postcard::from_bytes(&abe_public_key)?;
                return Ok(Some(abe_public_key));
            }
        }
        Ok(None)
    }

    pub async fn get_policy_from_access_manager(
        &self,
        topic: &str,
    ) -> Result<Option<String>, ProducerError> {
        let key_expr = format!("{}{}", ACCESS_MANAGER_POLICY_KEY_EXPR_PREFIX, topic);
        debug!(">> Preparing to send inquiry. key:'{}'", &key_expr);
        let replies = self.session.get(&key_expr).await?;

        while let Ok(reply) = replies.recv_async().await {
            if let Ok(sample) = reply.result() {
                let policy: String = sample.payload().try_to_string()?.into();
                return Ok(Some(policy));
            }
        }
        Ok(None)
    }

    pub async fn initialize_content_key(
        &self,
        topic: &str,
    ) -> Result<(String, ContentKey), ProducerError> {
        let (new_ck_id, new_ck) = self.generate_content_key(topic).await?;
        self.content_key_store
            .set_current_ck(topic, new_ck.clone())
            .await?;
        debug!(
            "Current CK has been initialized. New current CK ID: {:?}",
            new_ck_id
        );
        Ok((new_ck_id, new_ck))
    }

    pub async fn get_next_content_key(
        &self,
        topic: &str,
    ) -> Result<Option<(String, ContentKey)>, ProducerError> {
        let store = &self.content_key_store;
        store.get_next_ck(topic).await
    }

    pub async fn prepare_next_content_key(
        &self,
        topic: &str,
    ) -> Result<(String, ContentKey), ProducerError> {
        let (new_next_ck_id, new_next_ck) = self.generate_content_key(topic).await?;
        self.content_key_store
            .set_next_ck(topic, new_next_ck.clone())
            .await?;
        debug!(
            "Next CK has been updated. New next CK ID: {:?}",
            new_next_ck_id
        );
        Ok((new_next_ck_id, new_next_ck))
    }

    pub async fn rotate_content_key(&self, topic: &str) -> Result<(), ProducerError> {
        let store = &self.content_key_store;
        let (new_ck_id, new_ck) = match store.get_next_ck(topic).await? {
            Some(ck) => ck,
            None => {
                error!("No next content key found for topic '{}'", topic);
                return Err(ProducerError::ContentKeyNotFoundError(topic.to_string()));
            }
        };
        store.set_current_ck(topic, new_ck).await?;
        debug!(
            "Current CK has been updated. New current CK ID: {:?}",
            new_ck_id
        );

        store.remove_next_ck(topic).await?;

        Ok(())
    }
}

#[async_trait]
pub trait ContentKeyStore {
    async fn get_ck(&self, ck_id: &str) -> Result<Option<(String, ContentKey)>, ProducerError>;
    async fn add_ck(
        &self,
        ck_id: &str,
        topic: &str,
        content_key: ContentKey,
    ) -> Result<(), ProducerError>;
    async fn get_current_ck(
        &self,
        topic: &str,
    ) -> Result<Option<(String, ContentKey)>, ProducerError>;
    async fn set_current_ck(
        &self,
        topic: &str,
        content_key: ContentKey,
    ) -> Result<(), ProducerError>;
    async fn get_next_ck(&self, topic: &str)
        -> Result<Option<(String, ContentKey)>, ProducerError>;
    async fn set_next_ck(&self, topic: &str, content_key: ContentKey) -> Result<(), ProducerError>;
    async fn remove_next_ck(&self, topic: &str) -> Result<(), ProducerError>;
}

#[derive(Default, Clone, Debug)]
pub struct InMemoryContentKeyStore {
    /// A map of CK ID (content key ID) to their associated topic and content key.
    keys: Arc<ArcSwap<HashMap<String, (String, ContentKey)>>>,

    /// Current content keys. The keys of the map are topic names, and the values are the content keys.
    current_cks: Arc<ArcSwap<HashMap<String, (String, ContentKey)>>>,

    /// Next content keys. The keys of the map are topic names, and the values are the content keys.
    next_cks: Arc<ArcSwap<HashMap<String, (String, ContentKey)>>>,
}

impl InMemoryContentKeyStore {
    pub fn new() -> Self {
        InMemoryContentKeyStore {
            keys: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            current_cks: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            next_cks: Arc::new(ArcSwap::from_pointee(HashMap::new())),
        }
    }
}

#[async_trait]
impl ContentKeyStore for InMemoryContentKeyStore {
    async fn get_ck(&self, ck_id: &str) -> Result<Option<(String, ContentKey)>, ProducerError> {
        let map_arc = self.keys.load();
        Ok(map_arc.get(ck_id).cloned())
    }

    async fn add_ck(
        &self,
        ck_id: &str,
        topic: &str,
        content_key: ContentKey,
    ) -> Result<(), ProducerError> {
        let k = ck_id.to_string();
        let t = topic.to_string();
        self.keys.rcu(|cur| {
            let mut next = (**cur).clone();
            next.insert(k.clone(), (t.clone(), content_key.clone()));
            Arc::new(next)
        });
        Ok(())
    }

    async fn get_current_ck(
        &self,
        topic: &str,
    ) -> Result<Option<(String, ContentKey)>, ProducerError> {
        let map_arc = self.current_cks.load();
        Ok(map_arc.get(topic).cloned())
    }

    async fn set_current_ck(
        &self,
        topic: &str,
        content_key: ContentKey,
    ) -> Result<(), ProducerError> {
        let t = topic.to_string();
        let hash = content_key.id();
        self.current_cks.rcu(move |cur| {
            let mut next = (**cur).clone();
            next.insert(t.clone(), (hash.clone(), content_key.clone()));
            Arc::new(next)
        });
        Ok(())
    }

    async fn get_next_ck(
        &self,
        topic: &str,
    ) -> Result<Option<(String, ContentKey)>, ProducerError> {
        let map_arc = self.next_cks.load();
        Ok(map_arc.get(topic).cloned())
    }

    async fn set_next_ck(&self, topic: &str, content_key: ContentKey) -> Result<(), ProducerError> {
        let t = topic.to_string();
        let hash = content_key.id();
        self.next_cks.rcu(move |cur| {
            let mut next = (**cur).clone();
            next.insert(t.clone(), (hash.clone(), content_key.clone()));
            Arc::new(next)
        });
        Ok(())
    }

    async fn remove_next_ck(&self, topic: &str) -> Result<(), ProducerError> {
        let t = topic.to_string();
        self.next_cks.rcu(move |cur| {
            let mut next = (**cur).clone();
            next.remove(&t);
            Arc::new(next)
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::content_key;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_content_key_store() {
        let content_key_store = InMemoryContentKeyStore::new();
        let topic = "example/test/topic";
        let content_key = content_key::ContentKey::new();
        let ck_id = content_key.id();

        content_key_store
            .add_ck(&ck_id, topic, content_key.clone())
            .await
            .unwrap();

        assert_eq!(
            (topic.to_string(), content_key.clone()),
            content_key_store.get_ck(&ck_id).await.unwrap().unwrap()
        );

        assert_eq!(
            (topic.to_string(), content_key),
            content_key_store.get_ck(&ck_id).await.unwrap().unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_producer_encrypt() {
        let config = zenoh::Config::default();
        let session = zenoh::open(config).await.unwrap();
        let content_key_store = Arc::new(InMemoryContentKeyStore::new());
        let producer_prefix = "example";

        let producer = Producer::new(session, Arc::clone(&content_key_store), producer_prefix);

        let topic = "example/test/topic";
        let plaintext = "plaintext";

        producer.initialize_content_key(topic).await.unwrap();
        let content_key = producer.get_current_content_key(topic).await.unwrap();
        let encrypted_content = producer.encrypt(plaintext, &content_key, None).unwrap();
        assert!(!encrypted_content.is_empty());

        let stored_key = content_key_store.get_ck(&content_key.id()).await.unwrap();
        assert!(stored_key.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_public_key() {
        let config = zenoh::Config::default();
        let session = zenoh::open(config).await.unwrap();
        let content_key_store = Arc::new(InMemoryContentKeyStore::new());
        let producer_prefix = "example";

        let producer = Producer::new(session, Arc::clone(&content_key_store), producer_prefix);

        let result = producer.get_public_key_from_attribute_authority().await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_policy() {
        let config = zenoh::Config::default();
        let session = zenoh::open(config).await.unwrap();
        let content_key_store = Arc::new(InMemoryContentKeyStore::new());
        let producer_prefix = "example";

        let producer = Producer::new(session, Arc::clone(&content_key_store), producer_prefix);

        let topic = "example/test/topic";
        let result = producer.get_policy_from_access_manager(topic).await;
        assert!(result.is_ok());
    }

    /// Basic round-trip: set_current_ck then get_current_ck returns the same content key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_set_and_get_current_ck() {
        let store = InMemoryContentKeyStore::new();
        let ck = ContentKey::new();
        let expected_hash = ck.id();

        store
            .set_current_ck("test/topic", ck.clone())
            .await
            .unwrap();

        let (retrieved_id, retrieved_ck) =
            store.get_current_ck("test/topic").await.unwrap().unwrap();
        assert_eq!(retrieved_id, expected_hash);
        assert_eq!(retrieved_ck, ck);
    }

    /// Basic round-trip: set_next_ck then get_next_ck returns the same content key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_set_and_get_next_ck() {
        let store = InMemoryContentKeyStore::new();
        let ck = ContentKey::new();
        let expected_hash = ck.id();

        store.set_next_ck("test/topic", ck.clone()).await.unwrap();

        let (retrieved_id, retrieved_ck) = store.get_next_ck("test/topic").await.unwrap().unwrap();
        assert_eq!(retrieved_id, expected_hash);
        assert_eq!(retrieved_ck, ck);
    }

    /// remove_next_ck only removes next_ck and does not affect current_ck
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_remove_next_ck_preserves_current_ck() {
        let store = InMemoryContentKeyStore::new();
        let current_ck = ContentKey::new();
        let next_ck = ContentKey::new();

        store
            .set_current_ck("test", current_ck.clone())
            .await
            .unwrap();
        store.set_next_ck("test", next_ck).await.unwrap();

        store.remove_next_ck("test").await.unwrap();

        assert!(store.get_next_ck("test").await.unwrap().is_none());
        let (_, retrieved_current) = store.get_current_ck("test").await.unwrap().unwrap();
        assert_eq!(retrieved_current, current_ck);
    }

    /// Helper to create a Producer with an InMemoryContentKeyStore
    async fn create_test_producer() -> (
        Producer<InMemoryContentKeyStore>,
        Arc<InMemoryContentKeyStore>,
    ) {
        let config = zenoh::Config::default();
        let session = zenoh::open(config).await.unwrap();
        let store = Arc::new(InMemoryContentKeyStore::new());
        let producer = Producer::new(session, Arc::clone(&store), "test-prefix");
        (producer, store)
    }

    /// generate_content_key creates a new content key and stores it in the store
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_generate_content_key() {
        let (producer, store) = create_test_producer().await;
        let topic = "test/topic";

        let (ck_id, content_key) = producer.generate_content_key(topic).await.unwrap();

        let stored = store.get_ck(&ck_id).await.unwrap();
        assert!(stored.is_some());
        let (stored_topic, stored_ck) = stored.unwrap();
        assert_eq!(stored_topic, topic);
        assert_eq!(stored_ck, content_key);
    }

    /// get_content_key retrieves a previously stored content key by its ID
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_content_key() {
        let (producer, _store) = create_test_producer().await;
        let topic = "test/topic";

        let (ck_id, expected_ck) = producer.generate_content_key(topic).await.unwrap();

        let retrieved_ck = producer.get_content_key(&ck_id).await.unwrap();
        assert_eq!(retrieved_ck, expected_ck);
    }

    /// initialize_content_key generates a content key, stores it, and sets it as the current key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_initialize_content_key() {
        let (producer, store) = create_test_producer().await;
        let topic = "test/topic";

        let (ck_id, ck) = producer.initialize_content_key(topic).await.unwrap();

        // Verify it is set as the current content key
        let current = store.get_current_ck(topic).await.unwrap();
        assert!(current.is_some());
        let (current_id, current_ck) = current.unwrap();
        assert_eq!(current_id, ck_id);
        assert_eq!(current_ck, ck);
    }

    /// get_next_content_key returns None when no next key has been prepared
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_get_next_content_key() {
        let (producer, _store) = create_test_producer().await;
        let topic = "test/topic";

        let result = producer.get_next_content_key(topic).await.unwrap();
        assert!(result.is_none());
    }

    /// prepare_content_key generates a new content key and sets it as the next key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_prepare_next_content_key() {
        let (producer, store) = create_test_producer().await;
        let topic = "test/topic";

        let (next_ck_id, next_ck) = producer.prepare_next_content_key(topic).await.unwrap();

        // Verify the next content key is stored
        let stored_next = store.get_next_ck(topic).await.unwrap();
        assert!(stored_next.is_some());
        let (stored_id, stored_ck) = stored_next.unwrap();
        assert_eq!(stored_id, next_ck_id);
        assert_eq!(stored_ck, next_ck);
    }

    /// rotate_content_key promotes the next key to current and removes the next key
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_rotate_content_key() {
        let (producer, store) = create_test_producer().await;
        let topic = "test/topic";

        // Initialize a current key and prepare a next key
        producer.initialize_content_key(topic).await.unwrap();
        let (_next_ck_id, next_ck) = producer.prepare_next_content_key(topic).await.unwrap();

        // Rotate: next becomes current
        producer.rotate_content_key(topic).await.unwrap();

        let current = store.get_current_ck(topic).await.unwrap();
        assert!(current.is_some());
        let (_current_id, current_ck) = current.unwrap();
        assert_eq!(current_ck, next_ck);

        // Next key should be removed
        let next = store.get_next_ck(topic).await.unwrap();
        assert!(next.is_none());
    }
}
