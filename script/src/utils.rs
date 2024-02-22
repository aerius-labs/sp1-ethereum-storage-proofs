use rlp::Rlp;
use std::process::Command;

use crate::trie::{MAX_SP_NODE_LENGTH, StorageProof};
use serde_json::Value;
use sha3::{Digest, Keccak256};

extern crate hex;
extern crate serde_json;

pub enum Block {
    Latest,
    Number(u64),
}

pub fn get_storage_proof(
    eth_address: &str,
    storage_key: &str,
    block_number: Block,
) -> (StorageProof, String) {
    let bn = match block_number {
        Block::Latest => "latest".to_string(),
        Block::Number(n) => format!("0x{:x}", n),
    };

    let data_string = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getProof","params":["{}",[{}],"{}"],"id":1}}"#,
        eth_address,
        format!("\"{}\"", storage_key),
        bn
    );

    let output = Command::new("curl")
        .arg("-X")
        .arg("POST")
        .arg("https://eth-mainnet.g.alchemy.com/v2/4km9U2L-ODSqptpYnzDYu3mBWQ6yd7Ww")
        .arg("-d")
        .arg(data_string)
        .output()
        .expect("Failed to execute command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: Value = serde_json::from_str(&stdout).unwrap();

    // Extract the storage proofs
    let storage_proof_value = parsed["result"]["storageProof"].clone();
    let storage_proof = storage_proof_value.as_array().unwrap()[0].clone();

    let account_proof_vaue = parsed["result"]["accountProof"].clone();
    let account_proof = account_proof_vaue.as_array().unwrap().clone();

    let storage_hash = parsed["result"]["storageHash"].as_str().unwrap();
    let storage_hash = &storage_hash[2..];

    let key = storage_proof["key"].as_str().unwrap();
    let key_bytes = hex::decode(odd_to_even_hex(&key[2..])).unwrap();
    println!("key: {:?}", key);
    let mut hasher = Keccak256::new();
    hasher.update(&key_bytes);
    let result = hasher.finalize();
    let key_hash_bytes = result.to_vec();
    let key_hash = hex::encode(key_hash_bytes);
    println!("hashed key: {:?}", key_hash);

    let proof = storage_proof["proof"].as_array().unwrap();

    let path_as_str = proof
        .iter()
        .map(|element| {
            let element = element.as_str().unwrap();
            element
        })
        .collect::<Vec<&str>>();

    let (decoded, _hashes) = rlp_decode_and_pretty_print(path_as_str.clone());
    let key_as_str = hex::encode(key.clone());
    let key_ptrs = split_key_at_branches(key_as_str.as_str(), &decoded);
    println!("key_slices: {:?}", key_ptrs);

    let address_bytes = hex::decode(odd_to_even_hex(&eth_address[2..])).unwrap();
    println!("address: {:?}", eth_address);
    let mut hasher = Keccak256::new();
    hasher.update(&address_bytes);
    let result = hasher.finalize();
    let address_hash_bytes = result.to_vec();
    let address_hash = hex::encode(address_hash_bytes);
    println!("hashed key: {:?}", address_hash);

    let account_path_as_str = account_proof
        .iter()
        .map(|element| {
            let element = element.as_str().unwrap();
            element
        })
        .collect::<Vec<&str>>();

    let (decoded, _hashes) = rlp_decode_and_pretty_print(account_path_as_str.clone());
    let account_key_as_str = hex::encode(key.clone());
    let account_key_ptrs = split_key_at_branches(account_key_as_str.as_str(), &decoded);
    println!("account_key_slices: {:?}", account_key_ptrs);

    let proof_bytes = proof
        .iter()
        .map(|element| {
            let element = element.as_str().unwrap();
            let mut element = hex::decode(odd_to_even_hex(&element[2..])).unwrap();
            element.resize(MAX_SP_NODE_LENGTH, 0);
            element
        })
        .collect::<Vec<Vec<u8>>>();

    let node_lengths = calculate_node_lengths_sans_trailing_zeros(&proof_bytes);

    let proof = path_as_str.iter().map(|x| x[2..].to_string()).collect::<Vec<String>>();
    let account_proof = account_path_as_str.iter().map(|x| x[2..].to_string()).collect::<Vec<String>>();

    println!("proof: {:?}", proof);
    println!("node_lengths: {:?}", node_lengths);

    let value_short = storage_proof["value"].as_str().unwrap();
    let value_short = odd_to_even_hex(&value_short[2..]);

    println!("value: {:?}", value_short);

    (
        StorageProof {
            address_hash: address_hash.to_string(),
            account_proof,
            storage_key: key_hash.to_string(),
            storage_proof: proof,
            key_ptrs,
            account_key_ptrs
        },
        storage_hash.to_owned()
    )

}

fn odd_to_even_hex(hex: &str) -> String {
    if hex.len() % 2 == 0 {
        hex.to_string()
    } else {
        format!("0{}", hex)
    }
}

fn rlp_decode_and_pretty_print(proof: Vec<&str>) -> (Vec<Vec<String>>, Vec<String>) {
    let mut decoded_nodes: Vec<Vec<String>> = Vec::new();
    let mut hashes: Vec<String> = Vec::new();
    for (i, p) in proof.iter().enumerate() {
        // Remove the "0x" prefix and decode the hex string
        let bytes = hex::decode(&p[2..]).expect("Decoding failed");
        let mut in_res: Vec<String> = Vec::new();
        // Calculate the Keccak hash
        let mut hasher = Keccak256::new();
        hasher.update(&bytes);
        let res = hasher.finalize();
        let hash = format!("0x{}", hex::encode(res));
        hashes.push(hash.clone());
        println!("hash {}: {}", i, hash);
        // Decode using RLP
        let decoded_list = Rlp::new(&bytes);
        println!("Element {}:", i + 1);
        for (j, value) in decoded_list.iter().enumerate() {
            let hex_representation = format!("0x{}", hex::encode(value.data().unwrap()));
            println!("\tValue {}: {}", j + 1, hex_representation);
            in_res.push(hex_representation);
        }
        decoded_nodes.push(in_res);
    }
    (decoded_nodes, hashes)
}

pub fn calculate_node_lengths_sans_trailing_zeros(nodes: &[Vec<u8>]) -> Vec<usize> {
    let mut node_lengths: Vec<usize> = vec![];
    nodes.iter().for_each(|node| {
        let mut node_length = node.len();
        while node_length > 0 && node[node_length - 1] == 0 {
            node_length -= 1;
        }
        node_lengths.push(node_length);
    });

    node_lengths
}

fn split_key_at_branches(key: &str, path: &Vec<Vec<String>>) -> Vec<usize> {
    let mut result = Vec::new();
    let mut key_index = 0;

    for (i, level) in path.iter().enumerate() {
        let mut current_slice = String::new();

        // println!("level {}: {:?}", i, level.len());
        // println!("key_index: {}", key_index);

        if level.len() > 2 {
            // Branch node
            current_slice.push_str(&key[key_index..key_index + 1]);
            result.push(key_index);
            key_index += 1;
        } else if i != path.len() - 1 && level.len() == 2 {
            // Extension node
            let extension = &level[0][2..]; // Removing the "0x" prefix
            // rlp decode the extension
            let bytes = hex::decode(extension).expect("Decoding failed");
            let decoded: String = rlp::decode(&bytes).expect("Decoding failed");
            current_slice.push_str(&decoded);
            result.push(key_index);
            key_index += decoded.len();
        } else if i == path.len() - 1 && level.len() == 2 {
            // Leaf node
            current_slice.push_str(&key[key_index..]);
            result.push(key_index);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use crate::utils::{Block, get_storage_proof, rlp_decode_and_pretty_print, split_key_at_branches};
    use anyhow::Result;
    use rlp::Rlp;
    use sha3::{Digest, Keccak256};
    use hex;

    #[test]
    fn test_branch_split() -> Result<()> {
        let key = "0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7";
        let mut keccak = Keccak256::new();
        keccak.update(&hex::decode(&key[2..]).unwrap());
        let res = keccak.finalize();
        let key_hash = hex::encode(res);
        println!("key hash: {}", key_hash);
        let path = [
            "0xf90211a0d4685523e01e980b1b15d593ef92a29892200b5d17e90f73993b8e48e3ec9a95a003f511a02bb79c930a03fec8e45bc4e565c2f5c2b90f52cc80c767093709464fa0d41ebc458f8d7414b77b42f2eed10415b4fa909cee9307fb501cfe9c2fec279ea0b23482112d497f931e5666641e3c014aab48b3564305d13faafca89390af2d66a0a22495f1ac26ed51c08f0b205b4a22ed361631866f0223f2a7612d10f2da1aa8a0d23fc4baca54bf532faa572b55622e40f873652c2b009a6ab8e06f29938a2e59a0f1ad7ab771e65d865eb5d1ee1b77c9cb910948461295b5641106f9187f7038efa0a99aafc3ec45c268f5b1146ffae78242d15e52b06a54f3d5fe9a15bf509caa91a005c3571519c40841e1fcb6c952a5bf9b76ffd0d59f7dccfec5122f445e8624ada04626e7701acc68de8fd0445ee304972a14959da40f590f8fb20c654b9b1bea5ca0a68db0617f5b4c6cdb530ed14366c16cdba3fb9016703b744a24197223636fe5a0d9e294b08bf26233e15498659a650e2983d1c1059e7ef385c634656f0528f12ca03420511341a2c3fdc2070e74190e436d95c078a580bb932305fb2fbbe5ab5c9ca0a0fe187c8edcf62afb18bf29bea69b5488b26dcbe0f8204cd08b5662f052a00fa07dd0e8bb2f5b617b770995d61f4d99c567f18ad30fd3f9ad3082b88181f136a8a032c255b3531196dd5a31ebf1f404bbb6b90bb29653da9a832d2ccc9dcb21dd8b80",
            "0xf90211a066aac6f5a978c9e665e5b96d883eb80d0e1f011f8f80c9b1bd8cc88f391e53d1a09f1e43a0ba666e17f4e8110975f41c8be4420648f031550a4451d155ea4111aaa0ce2228dd7cb87eb5aed542d89fbbf9eee90c1ba5aaf19ee29dce7b619d041674a0890e6c2cf4624136625643b3154674c397e0b08effd788fc27fcb18926ba5cb0a0dc890ad9cf16560b060cd50a93d4244849feb05f1689018320ca9574601c8d6ea0f924f6d0a26d2a61bb234723e7e55291e2b1f4a3241a5510e76d04a0491b9449a03a840866532e46f6dd33260dfe292c5bff75039959739f797ab93cba556f354da01b9c0e99aa504904e8f7416d71fa0d4998e7a304b757b91e8810193833c80d6ca0f7900ec7f53f2c541b1a78f11287c8f289dd8c421273fd608418cc499ccf0404a0ada8e0a618ebfa284edbc4af8d391a587a987f3d4678c028b2efc8e8ac4c999ba066ddcfb5915268482b9ee3cf1eea53901c0c330990874e4209ac768f9d5dd853a0d0711e509cf79f2bd6f1b90e705d684f5c8e3f9cc0ff1e02d4f8081b90ab1248a071c7ee1b33f6728766477a69ad8bd9f7ca0c4458c2e83c026d642d22ee86df64a009bf0423dfe0066180db1691dad70751399fa5edca86806c7c8dfd1c4622a9b4a08eba45bf77f2eaf1f10a33161839a6d4f51ac0064e23a536eff7b3b43e4c7ea4a0260e99a040e70b7a27ee00868f70fb2993b53a233da888352858aa4a7f781a3680",
            "0xf90211a02f4ea6d48dfaf65990a0b2bbaf4896f2c52e53e97b87b4332c7c18f636b5dd13a028b1ec20afe5399857f2dc0a87ceabd2a48b89f4c5b490f9f9a8c5a7f97e8e5ca006adc06451c399170d1fc5f377890aafba61ccfbe6c53dffc8eaff55d9c4f3e1a04c1a4950b3ffe3afc91ec936e45e428b89d31e125fce160f003d629ac1a851bba074d3e762114776c8b7d8e931c2e1a85f8b0f07d2a13f58fcfdf7f7ecf09a5ddfa0fc73976a1116deee277d1e6b8b2b3a5f6d49e8b3919c7a4b139464263ec77bdea0d13c9b7c09da7b3ffb6efd23e1211c18a6cdf9838cbd3334eea36d44cc957c9aa08bc12fa996ba4ec4c0183a37ebef86539bca71eac2e2e13b8b5a3569c8505b0ba057dc2540a00930a63b5083c3c226aa83abbbb8ccff45e1d0815d081a162bfdfba000a42dee911b03cc329f00e6ec61a6b9977e866d6cb6c07a9231c5cbcdadd7f3a0b9be4ea998b0cc465e1089a94fc165c047dda678c18cf78896f632c2467f704da02e50c8f770a6e610f8b339d084bd2e5742314b9c5c412ffdcf053baed85c9ff0a015f78e31dc3a16f53d45671c02f16a8a3e3d4fa4d4ede524f0a4be786a81761fa089bccb4fc0828f1e3f81cd4f49c55786fe5af6b454ae380eee5c0c8af3c60a50a0661c68c9542fc76626f522b3eec3807d5616a90d212ae9cbf216017980e0f98fa0931ed5b398df16ad539db32202bc7e15f1029bfc71b2ccad33818e4894cda40980",
            "0xf8d1808080a09bdb004d9b1e7f3e5f86fbdc9856f21f9dcb07a44c42f5de8eec178514d279df80a01f50e7ee4b847bceba7fb3f01fdafe949327b8aec724ff106bcb40749031a0098080a02b44776d99642c66e34eaccf146329beea4c6e96b3b6ddc9c32d51b784c4954180a00f8f2c713a079d09bfa73a8cdd1bdd3e4ff0b51fb17994af6b52edd77efa894b80a0bebb7a7c17a816c67b7084abfe93c5ee283e69f4303a35b185b98fe97cff0eaaa000bc3930843cc34573210bdb92bfecc32db5bbd2a713cb497f1a8d1b936e6dcc808080",
            "0xe21ba089c052492200484eca92e22fb5818f7a40e4513f6bcf48c8e9c216cbd49cd453",
            "0xf851a0bdf8d474c3279b73b2a86db9496f68daa1f418dff55a25c1a76031be0e603cf78080808080808080a0935117feec98c461b9860cc69df695460bfef3fc08e33e47c07ad409b2e7cc6d80808080808080",
            "0xf59e2032d5a5fa3a5b6544566ee46a0f6b8fe8b1375ec878dc3be6580b0784959594b88f61e6fbda83fbfffabe364112137480398018",
        ].to_vec();
        let (decoded, _hashes) = rlp_decode_and_pretty_print(path);
        let key_slices = split_key_at_branches(&key_hash, &decoded);
        println!("key_slices: {:?}", key_slices);

        Ok(())
    }

    #[test]
    fn test_proof_verify() -> Result<()> {
        let eth_address = "0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb";
        let storage_key = "0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7";
        let block_number = Block::Latest;

        let trie_proof = get_storage_proof(eth_address, storage_key, block_number);
        let sp = trie_proof.0;
        let mut current_hash = trie_proof.1.clone();

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

                println!("value: {:?}", value);
            }
        }

        let mut state_root: String;
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

                assert_eq!(trie_proof.1, hex::encode(value_decoded.iter().collect::<Vec<_>>()[2].data().unwrap()));
            }
        }

        Ok(())
    }
}