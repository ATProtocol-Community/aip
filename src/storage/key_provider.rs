//! Key provider trait and in-memory implementation for ATProtocol identity operations.

use anyhow::Result;
use async_trait::async_trait;
use atproto_identity::key::KeyData;
use std::collections::HashMap;

/// Trait for providing cryptographic keys by identifier.
///
/// This trait defines the interface for key providers that can retrieve private keys
/// by their identifier. Implementations must be thread-safe to support concurrent access.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Retrieves a private key by its identifier.
    ///
    /// # Arguments
    /// * `key_id` - The identifier of the key to retrieve
    ///
    /// # Returns
    /// * `Ok(Some(KeyData))` - If the key was found and successfully retrieved
    /// * `Ok(None)` - If no key exists for the given identifier
    /// * `Err(anyhow::Error)` - If an error occurred during key retrieval
    async fn get_private_key_by_id(&self, key_id: &str) -> Result<Option<KeyData>>;
}

#[derive(Clone)]
pub struct SimpleKeyProvider {
    keys: HashMap<String, KeyData>,
}

impl Default for SimpleKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SimpleKeyProvider {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }
}

#[async_trait]
impl KeyProvider for SimpleKeyProvider {
    async fn get_private_key_by_id(&self, key_id: &str) -> anyhow::Result<Option<KeyData>> {
        Ok(self.keys.get(key_id).cloned())
    }
}
