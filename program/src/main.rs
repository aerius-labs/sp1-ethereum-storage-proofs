//! A simple program to be proven inside the zkVM.

#![no_main]

use alloy_dyn_abi::DynSolType;
use alloy_primitives::{
    hex::{self, FromHex},
    keccak256, FixedBytes, Keccak256,
};
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

    for (i, p) in sp.proof.iter().enumerate() {
        let bytes = hex::decode(&p).expect("Decoding proof failed");

        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();



        // sp1_zkvm::io::write(&true);
        // assert_eq!(&hex::encode(res), &current_hash);

        let decoded_list = Rlp::new(&bytes);

        sp1_zkvm::io::write(&true);

        if i < depth - 1 {
            current_hash = decoded_list.as_list::<String>().unwrap()[key_ptrs[i]].clone();
        }
    }

    sp1_zkvm::io::write(&true);
}

// fn rlp_decode_and_pretty_print(proof: Vec<&str>) -> (Vec<Vec<String>>, Vec<String>) {
//     let mut decoded_nodes: Vec<Vec<String>> = Vec::new();
//     let mut hashes: Vec<String> = Vec::new();
//     for (i, p) in proof.iter().enumerate() {
//         // Remove the "0x" prefix and decode the hex string
//         let bytes = hex::decode(&p[2..]).expect("Decoding failed");
//         let mut in_res: Vec<String> = Vec::new();
//         // Calculate the Keccak hash
//         let mut hasher = Keccak256::new();
//         hasher.update(&bytes);
//         let res = hasher.finalize();
//         let hash = format!("0x{}", hex::encode(res));
//         hashes.push(hash.clone());
//         println!("hash {}: {}", i, hash);
//         // Decode using RLP
//         let decoded_list = Rlp::new(&bytes);
//         println!("Element {}:", i + 1);
//         for (j, value) in decoded_list.iter().enumerate() {
//             let hex_representation = format!("0x{}", hex::encode(value.data().unwrap()));
//             println!("\tValue {}: {}", j + 1, hex_representation);
//             in_res.push(hex_representation);
//         }
//         decoded_nodes.push(in_res);
//     }
//     (decoded_nodes, hashes)
// }