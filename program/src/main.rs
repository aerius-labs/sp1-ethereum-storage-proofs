//! A simple program to be proven inside the zkVM.

#![no_main]

use alloy_primitives::{ hex, Keccak256 };
use rlp::Rlp;
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageProof {
    pub address_hash: String,
    pub account_proof: Vec<String>,
    pub storage_key: String,
    pub storage_proof: Vec<String>,
    pub key_ptrs: Vec<usize>,
    pub account_key_ptrs: Vec<usize>,
}

pub fn main() {
    // Read storage key
    let sp = sp1_zkvm::io::read::<StorageProof>();

    // Verify storage proof
    let storage_root = sp1_zkvm::io::read::<String>();
    let mut current_hash = storage_root.clone();

    let key_ptrs = sp.key_ptrs;
    let account_key_ptrs = sp.account_key_ptrs;

    let depth_sp = sp.storage_proof.len();
    let depth_ap = sp.account_proof.len();

    let key_nibbles = sp.storage_key.chars().map(|x| x.to_digit(16).unwrap() as usize).collect::<Vec<_>>();
    let account_key_nibbles = sp.address_hash.chars().map(|x| x.to_digit(16).unwrap() as usize).collect::<Vec<_>>();

    for (i, p) in sp.storage_proof.iter().enumerate() {
        let bytes = hex::decode(&p).expect("Decoding proof failed");

        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();

        assert_eq!(&hex::encode(res), &current_hash);

        let decoded_list = Rlp::new(&bytes);
        assert!(decoded_list.is_list());

        if i < depth_sp - 1 {
            let nibble = key_nibbles[key_ptrs[i]];
            current_hash = hex::encode(decoded_list.iter().collect::<Vec<_>>()[nibble].data().unwrap());
        } else {
            // verify value
            let leaf_node = decoded_list.iter().collect::<Vec<_>>();
            assert_eq!(leaf_node.len(), 2);
            let value_decoded = Rlp::new(leaf_node[1].data().unwrap());
            assert!(value_decoded.is_data());
            let value = hex::encode(value_decoded.data().unwrap());

            sp1_zkvm::io::write(&value);
        }
    }

    let mut state_root: String = "".to_string();
    let mut current_hash: String = "".to_string();
    for (i, p) in sp.account_proof.iter().enumerate() {
        let bytes = hex::decode(&p).expect("Decoding proof failed");

        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();

        if i == 0 {
            state_root = hex::encode(res);
        } else {
            assert_eq!(&hex::encode(res), &current_hash);
        }

        let decoded_list = Rlp::new(&bytes);
        assert!(decoded_list.is_list());

        if i < depth_ap - 1 {
            let nibble = account_key_nibbles[account_key_ptrs[i]];
            current_hash = hex::encode(decoded_list.iter().collect::<Vec<_>>()[nibble].data().unwrap());
        } else {
            // verify value
            let leaf_node = decoded_list.iter().collect::<Vec<_>>();
            assert_eq!(leaf_node.len(), 2);
            let value_decoded = Rlp::new(leaf_node[1].data().unwrap());
            assert!(value_decoded.is_list());

            assert_eq!(storage_root, hex::encode(value_decoded.iter().collect::<Vec<_>>()[2].data().unwrap()));
            sp1_zkvm::io::write(&state_root);
        }
    }

    sp1_zkvm::io::write(&true);
}
