use serde::{Deserialize, Serialize};
pub(crate) const MAX_SP_NODE_LENGTH: usize = 532;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    pub address_hash: String,
    pub account_proof: Vec<String>,
    pub storage_key: String,
    pub storage_proof: Vec<String>,
    pub key_ptrs: Vec<usize>,
    pub account_key_ptrs: Vec<usize>,
}