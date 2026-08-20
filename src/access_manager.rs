use crate::config::*;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info};
use zenoh::{key_expr::keyexpr, Session};

#[derive(Error, Debug)]
pub enum AccessManagerError {
    #[error("Zenoh error: {0}")]
    ZenohError(#[from] zenoh::Error),
    #[error("Policy store error: {0}")]
    PolicyStoreError(String),
}

#[derive(Clone, Debug)]
pub struct AccessManager<S: PolicyStore> {
    session: Session,
    policy_store: S,
}

impl<S: PolicyStore> AccessManager<S> {
    pub fn new(session: Session, policy_store: S) -> Self {
        Self {
            session,
            policy_store,
        }
    }

    pub async fn handle_policy_query(&self) -> Result<(), AccessManagerError> {
        info!("Handling policy query");
        let queryable_key_expr = keyexpr::new(ACCESS_MANAGER_POLICY_KEY_EXPR)?;
        info!(">> Waiting for queries on ('{}')...", queryable_key_expr);

        let queryable = self
            .session
            .declare_queryable(queryable_key_expr)
            .complete(true)
            .await?;

        while let Ok(query) = queryable.recv_async().await {
            let query_key_expr = query.key_expr();
            // Ignore query that contains wildcards
            if query_key_expr.is_wild() {
                continue;
            }

            let topic = query_key_expr
                .as_str()
                .strip_prefix(ACCESS_MANAGER_POLICY_KEY_EXPR_PREFIX)
                .unwrap()
                .to_string();

            if let Some(policy) = self.policy_store.get_policy(&topic).await? {
                debug!("Policy for topic {} is '{}'", topic, policy);
                query.reply(queryable_key_expr, policy).await?;
            } else {
                debug!("No policy found for topic {}", topic);
            }
        }

        Ok(())
    }
}

#[async_trait]
pub trait PolicyStore {
    async fn get_policy(&self, topic: &str) -> Result<Option<String>, AccessManagerError>;
    async fn set_policy(&self, topic: &str, policy: &str) -> Result<(), AccessManagerError>;
}

#[derive(Default, Clone, Debug)]
pub struct InMemoryPolicyStore(Arc<RwLock<HashMap<String, String>>>);

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }
}

#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn get_policy(&self, topic: &str) -> Result<Option<String>, AccessManagerError> {
        let map = self.0.read().await;
        Ok(map.get(topic).cloned())
    }

    async fn set_policy(&self, topic: &str, policy: &str) -> Result<(), AccessManagerError> {
        let mut map = self.0.write().await;
        map.insert(topic.to_string(), policy.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_policy_store() {
        let policy_store = InMemoryPolicyStore::new();
        let topic = "example/test/topic";
        let policy = r#""A" and "B""#;

        policy_store.set_policy(topic, policy).await.unwrap();

        assert_eq!(
            policy_store.get_policy(topic).await.unwrap(),
            Some(policy.to_string())
        );
    }
}
