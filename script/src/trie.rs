use serde::{Deserialize, Serialize};
pub(crate) const MAX_SP_NODE_LENGTH: usize = 532;
pub(crate) const VALUE_LEN: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    pub key: String,
    pub proof: Vec<String>,
    pub key_ptrs: Vec<usize>,
}