//! A simple program to be proven inside the zkVM.

#![no_main]

use alloy_primitives::{ hex, Keccak256 };
use rlp::Rlp;
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct StorageProof {
    pub key: String,
    pub proof: Vec<String>,
    pub key_ptrs: Vec<usize>,
}

pub fn main() {
    // Read storage key
    let sp = sp1_zkvm::io::read::<StorageProof>();

    // Verify storage proof
    let mut current_hash = sp1_zkvm::io::read::<String>();

    let key_ptrs = sp.key_ptrs;

    let depth = sp.proof.len();

    let key_nibbles = sp.key.chars().map(|x| x.to_digit(16).unwrap() as usize).collect::<Vec<_>>();

    for (i, p) in sp.proof.iter().enumerate() {
        let bytes = hex::decode(&p).expect("Decoding proof failed");

        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();

        assert_eq!(&hex::encode(res), &current_hash);

        let decoded_list = Rlp::new(&bytes);

        if i < depth - 1 {
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

    sp1_zkvm::io::write(&true);
}
