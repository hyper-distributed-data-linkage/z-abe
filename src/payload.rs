use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PayloadWithHeader {
    pub header: HashMap<String, String>,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncryptedSymSecretKeyPair {
    #[serde(with = "serde_bytes")]
    pub encrypted_sym_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub encrypted_secret_key: Vec<u8>,
}
