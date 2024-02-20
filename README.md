# SP1 Ethereum Storage Proofs

This project demonstrates how to generate a zero-knowledge (zk) proof of a storage slot from the Ethereum mainnet using Succinct's SP1 zkVM. The SP1 zkVM is a versatile tool for creating and verifying zk proofs for various applications, including blockchain data verification without revealing the underlying data. This guide will walk you through setting up the project, installing dependencies, and running the program to generate and verify zk proofs for Ethereum storage slots.

## Getting Started

### Prerequisites
* Rust Nightly: The project is built with Rust's nightly compiler due to certain unstable features. Make sure you have Rust and the nightly toolchain installed.
* SP1 Prover Installation: The SP1 Prover from Succinct Labs is required to generate zk proofs. Follow the installation instructions from [Succinct's documentation](https://succinctlabs.github.io/sp1/) to set up the SP1 Prover on your system.

### Installation
1. Clone the Repository
    - Start by cloning this repository to your local machine.
  ```bash
    git clone https://github.com/aerius-labs/sp1-ethereum-storage-proofs.git
  ```

2. Switch to Rust Nightly
    -Navigate into the project directory and switch to Rust's nightly compiler.
  ```bash
    cd sp1-ethereum-storage-proofs
    rustup override set nightly
  ```

3. Build the zkVM program
  ```bash
  cd program
  cargo prove build
  ```

4. Run prover
  ```
  cd script
  RUST_LOG=info cargo run --release
  ```

## Usage 

To generate and verify a zk proof for an Ethereum storage slot, you need the Ethereum address, the storage key, and the block number. The main function in main.rs demonstrates how to generate a zk proof for a specified storage slot.

1. Configure Input Parameters
    - Open main.rs and set the eth_address, storage_key, and block_number to the Ethereum address, storage key, and block number for which you want to generate a zk proof.
```rust 
let eth_address = "0x...";
let storage_key = "0x...";
let block_number = Block::Latest; // Or Block::Number(u64)
```

2. Run the Program
    - Execute the program to generate and verify the zk proof.
```bash
cargo run --release
```
The program will output the proof generation and verification times, indicating successful execution.

## Understanding the Code

The project includes several key components:

- `get_storage_proof`: This function fetches the storage proof from the Ethereum mainnet using the Alchemy API. It constructs a JSON-RPC request to retrieve the proof and parses the response.

- `rlp_decode_and_pretty_print`, odd_to_even_hex, calculate_node_lengths_sans_trailing_zeros, split_key_at_branches: These utility functions decode the RLP-encoded proof, adjust hex string formats, calculate node lengths, and split keys at branches, respectively, to prepare the proof for SP1's zkVM.

- SP1Prover and SP1Verifier: These structures from the sp1_core crate are used to generate and verify zk proofs, respectively, using the SP1 zkVM.

- `StorageProof`: A custom data structure to encapsulate the storage proof, including the key, proof nodes, and key pointers necessary for zk proof generation.

## Benchmarks
Number of levels to storage root - 5

| Hardware | Proof gen | Proof verification |
-----------|-----------|--------------------|
| Apple silicon M1 | 6.1 s | 500 ms         |
| AMD Ryzen 9 5900X | 5.3 s | 405 ms        |

## Additional Information

For more details on SP1 zkVM and its capabilities, refer to the [Succinct Labs documentation](https://succinctlabs.github.io/sp1/). This documentation provides comprehensive guidance on working with the SP1 Prover and Verifier, alongside other advanced features of the SP1 zkVM.
