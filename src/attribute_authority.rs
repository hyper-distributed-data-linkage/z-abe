use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openssl::rsa::Rsa;
use rabe::schemes::ac17::{Ac17MasterKey, Ac17PublicKey};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use zenoh::key_expr::keyexpr;
use zenoh::Session;

use crate::config::*;
use crate::secret_key::{SecretKey, SecretKeyError};
use crate::skl::{SecretKeyLock, SecretKeyLockError};
use crate::sym_key::SymKey;
use tracing::{debug, info};

#[derive(Error, Debug)]

pub enum AttributeAuthorityError {
    #[error("Zenoh error: {0}")]
    ZenohError(#[from] zenoh::Error),
    #[error("Secret key error: {0}")]
    SecretKeyError(#[from] SecretKeyError),
    #[error("Secret key lock error: {0}")]
    SecretKeyLockError(#[from] SecretKeyLockError),
    #[error("Postcard error: {0}")]
    PostcardError(#[from] postcard::Error),
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
    #[error("Attribute store error: {0}")]
    AttributeStoreError(String),
}

#[derive(Clone, Debug)]
pub struct AttributeAuthority<S: AttributeStore> {
    session: Session,
    attribute_store: S,
    abe_public_key: Arc<RwLock<Ac17PublicKey>>,
    abe_master_key: Arc<RwLock<Ac17MasterKey>>,
}

impl<S: AttributeStore> AttributeAuthority<S> {
    pub fn new(
        session: Session,
        attribute_store: S,
        abe_public_key: Ac17PublicKey,
        abe_master_key: Ac17MasterKey,
    ) -> Self {
        Self {
            session,
            attribute_store,
            abe_public_key: Arc::new(RwLock::new(abe_public_key)),
            abe_master_key: Arc::new(RwLock::new(abe_master_key)),
        }
    }

    pub async fn update_abe_keys(
        &self,
        abe_public_key: Ac17PublicKey,
        abe_master_key: Ac17MasterKey,
    ) {
        *self.abe_public_key.write().await = abe_public_key;
        *self.abe_master_key.write().await = abe_master_key;
    }

    pub async fn handle_public_key_query(&self) -> Result<(), AttributeAuthorityError> {
        info!("Handling public key query");
        let queryable_key_expr = keyexpr::new(ATTRIBUTE_AUTHORITY_PK_KEY_EXPR)?;
        info!(">> Waiting for queries on ('{}')...", queryable_key_expr);

        let queryable = self
            .session
            .declare_queryable(queryable_key_expr)
            .complete(true)
            .await?;

        while let Ok(query) = queryable.recv_async().await {
            info!("Received query");
            let query_key_expr = query.key_expr();
            // Ignore query that contains wildcards
            if query_key_expr.is_wild() {
                continue;
            }
            debug!("payload: {:?}", query.payload());

            let abe_public_key = self.abe_public_key.read().await;
            let abe_public_key = postcard::to_allocvec(&*abe_public_key)?;
            query.reply(queryable_key_expr, abe_public_key).await?;
        }
        Ok(())
    }

    pub async fn handle_secret_key_query(&self) -> Result<(), AttributeAuthorityError> {
        info!("Handling secret key query");
        let queryable_key_expr = keyexpr::new(ATTRIBUTE_AUTHORITY_SK_KEY_EXPR)?;
        info!(">> Waiting for queries on ('{}')...", queryable_key_expr);

        let queryable = self
            .session
            .declare_queryable(queryable_key_expr)
            .complete(true)
            .await?;

        while let Ok(query) = queryable.recv_async().await {
            info!("Received query");
            let query_key_expr = query.key_expr();
            // Ignore query that contains wildcards
            if query_key_expr.is_wild() {
                continue;
            }

            if let Some(payload) = query.payload() {
                let rsa_public_key = Rsa::public_key_from_der_pkcs1(&payload.to_bytes())?;
                let der_bytes = rsa_public_key.public_key_to_der_pkcs1()?;
                let der_base64 = STANDARD.encode(&der_bytes);
                debug!("Query: {}", der_base64);
                let attributes = self.attribute_store.get_attributes(&der_base64).await?;
                if let Some(attributes) = attributes {
                    let attributes = attributes.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
                    debug!("Attributes: {:?}", attributes);
                    let abe_master_key = self.abe_master_key.read().await;
                    let secret_key = SecretKey::new(&abe_master_key, &attributes);
                    let sym_key = SymKey::new();
                    let encrypted_sym_secret_key_pair =
                        SecretKeyLock::encrypt(&rsa_public_key, &sym_key, &secret_key)?;
                    query
                        .reply(
                            queryable_key_expr,
                            postcard::to_allocvec(&encrypted_sym_secret_key_pair)?,
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
pub trait AttributeStore {
    async fn get_attributes(
        &self,
        rsa_public_key: &str,
    ) -> Result<Option<Vec<String>>, AttributeAuthorityError>;
    async fn set_attributes(
        &self,
        rsa_public_key: &str,
        attributes: &[&str],
    ) -> Result<(), AttributeAuthorityError>;
}

#[derive(Default, Clone, Debug)]
pub struct InMemoryAttributeStore(Arc<RwLock<HashMap<String, Vec<String>>>>);

impl InMemoryAttributeStore {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }
}

#[async_trait]
impl AttributeStore for InMemoryAttributeStore {
    async fn get_attributes(
        &self,
        rsa_public_key: &str,
    ) -> Result<Option<Vec<String>>, AttributeAuthorityError> {
        let map = self.0.read().await;
        Ok(map.get(rsa_public_key).cloned())
    }

    async fn set_attributes(
        &self,
        rsa_public_key: &str,
        attributes: &[&str],
    ) -> Result<(), AttributeAuthorityError> {
        let mut map = self.0.write().await;
        map.insert(
            rsa_public_key.to_string(),
            attributes.iter().map(ToString::to_string).collect(),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_attribute_store() {
        let attribute_store = InMemoryAttributeStore::new();
        let rsa_public_key = "MIIBCgKCAQEA3FbQry/I5hv6NgwXVLkPClr5c0o3Gv9nbps1jcRhDW/Y/ZHiNVX6y+hT/69CqbyKLCqq6TnbzatK4bvx4RWfFySkKxKl6yOajwGhvIVZsamZ+rJND4SH5l7gNOED7Ztmb671wDaSrZ+iCQ3GJQwm2muZ3XQoZ3r55y159I4yDe2fnf/rcxHOQMUxBWPAcKz9TJkFxJYmDjGhbHh8nG9pdcsh8lwK+lECpFgiWRA/zy3wCMevmPL2fz4sqJgGGLHVtmfuohdecCWCBY5SrwioFxr+3lpT+72nwaRaLgnDoGCyK4aTWXvnHC3pnK2OYP2VfK4UwS5ON51CjlVx+4tsYQIDAQAB";
        let attributes = vec!["a", "b"];

        attribute_store
            .set_attributes(rsa_public_key, &attributes)
            .await
            .unwrap();

        assert_eq!(
            attribute_store
                .get_attributes(rsa_public_key)
                .await
                .unwrap(),
            Some(attributes.iter().map(ToString::to_string).collect())
        );
    }

    #[test]
    #[ignore]
    fn test_rsa_public_key_base64() {
        let rsa_private_key = Rsa::generate(2048).unwrap();
        let der_bytes = rsa_private_key.public_key_to_der_pkcs1().unwrap();
        let der_base64 = STANDARD.encode(&der_bytes);
        let pem_bytes = rsa_private_key.public_key_to_pem().unwrap();
        let pem_string = String::from_utf8(pem_bytes).unwrap();
        println!("PEM: \n{}", pem_string);
        println!("DER Base64: \n{}", der_base64);

        assert!(pem_string
            .replace("-----BEGIN RSA PUBLIC KEY-----", "")
            .replace("-----END RSA PUBLIC KEY-----", "")
            .replace("\n", "")
            .contains(&der_base64));
    }
}
