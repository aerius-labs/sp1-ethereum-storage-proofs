mod trie;
mod utils;

use sp1_core::{SP1Prover, SP1Stdin, SP1Verifier};
use crate::utils::{Block, get_storage_proof};

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    let eth_address = "0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb";
    let storage_key = "0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7";
    let block_number = Block::Latest;

    let trie_proof = get_storage_proof(eth_address, storage_key, block_number);

    println!("hash: {:?}", trie_proof.1);

    let mut stdin = SP1Stdin::new();
    let start = std::time::Instant::now();
    stdin.write(&trie_proof.0);
    stdin.write(&trie_proof.1);

    let mut proof = SP1Prover::prove(ELF, stdin).expect("proving failed");
    let end = std::time::Instant::now();

    println!("Proof generation time: {:?}", end.duration_since(start));

    let value = proof.stdout.read::<bool>();
    assert_eq!(value, true);

    let start = std::time::Instant::now();
    // Verify proof.
    SP1Verifier::verify(ELF, &proof).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");
    let end = std::time::Instant::now();
    println!("Verification time: {:?}", end.duration_since(start));

    println!("succesfully generated and verified proof for the program!");

}
