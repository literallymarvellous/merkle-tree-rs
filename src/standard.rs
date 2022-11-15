use core::panic;
use ethers::{
    abi::{self, Token},
    types::{Address, Bytes, U256},
    utils::{hex, keccak256},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};

use crate::core::{
    get_multi_proof, get_proof, make_merkle_tree, process_multi_proof, process_proof,
    render_merkle_tree, MultiProof,
};

pub fn standard_leaf_hash(values: Vec<String>, types: &[String]) -> Bytes {
    let mut tokens: Vec<Token> = Vec::new();
    for (i, t) in types.iter().enumerate() {
        match t.as_str() {
            "address" => {
                let address = Address::from_str(&values[i]).unwrap();
                tokens.push(Token::Address(address));
            }
            "uint" | "uint256" => {
                let uint = U256::from_dec_str(&values[i]).unwrap();
                tokens.push(Token::Uint(uint));
            }
            "string" => {
                tokens.push(Token::String(values[i].clone()));
            }
            _ => panic!("Invalid type"),
        }
    }
    Bytes::from(keccak256(keccak256(Bytes::from(abi::encode(&tokens)))))
}

pub fn check_bounds<T>(values: &[T], index: usize) {
    if index >= values.len() {
        panic!("Index out of range")
    }
}

#[allow(dead_code)]
struct HashedValues {
    value: Vec<String>,
    value_index: usize,
    hash: Bytes,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
struct Values {
    value: Vec<String>,
    tree_index: usize,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct StandardMerkleTreeData {
    format: String,
    tree: Vec<String>,
    values: Vec<Values>,
    leaf_encoding: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StandardMerkleTree {
    hash_lookup: HashMap<String, usize>,
    tree: Vec<Bytes>,
    values: Vec<Values>,
    leaf_encoding: Vec<String>,
}

pub enum LeafType {
    Number(usize),
    LeafBytes(Vec<String>),
}

impl StandardMerkleTree {
    fn new(tree: Vec<Bytes>, values: &[Values], leaf_encode: &[String]) -> Self {
        let mut hash_lookup = HashMap::new();
        values.iter().enumerate().for_each(|(i, v)| {
            hash_lookup.insert(
                hex::encode(standard_leaf_hash(v.value.clone(), leaf_encode)),
                i,
            );
        });

        Self {
            hash_lookup,
            tree,
            values: values.to_vec(),
            leaf_encoding: leaf_encode.to_vec(),
        }
    }

    pub fn of(values: Vec<Vec<String>>, leaf_encode: &[String]) -> Self {
        let mut hashed_values: Vec<HashedValues> = values
            .iter()
            .enumerate()
            .map(|(i, v)| HashedValues {
                value: (*v).to_vec(),
                value_index: i,
                hash: standard_leaf_hash(v.clone(), leaf_encode),
            })
            .collect();

        hashed_values.sort_by(|a, b| a.hash.cmp(&b.hash));

        let tree = make_merkle_tree(hashed_values.iter().map(|v| v.hash.clone()).collect());

        let mut indexed_values: Vec<Values> = values
            .iter()
            .map(|v| Values {
                value: (*v).to_vec(),
                tree_index: 0,
            })
            .collect();
        hashed_values.iter().enumerate().for_each(|(i, v)| {
            indexed_values[v.value_index].tree_index = tree.len() - i - 1;
        });

        Self::new(tree, &indexed_values, leaf_encode)
    }

    pub fn load(data: StandardMerkleTreeData) -> StandardMerkleTree {
        if data.format != "standard-v1" {
            panic!("Unknown format");
        }

        let tree = data
            .tree
            .iter()
            .map(|leaf| Bytes::from(hex::decode(leaf.split_at(2).1).unwrap()))
            .collect();

        Self::new(tree, &data.values, &data.leaf_encoding)
    }

    pub fn dump(&self) -> StandardMerkleTreeData {
        StandardMerkleTreeData {
            format: "standard-v1".to_owned(),
            tree: self
                .tree
                .iter()
                .map(|leaf| format!("0x{}", hex::encode(leaf)))
                .collect(),
            values: self.values.clone(),
            leaf_encoding: self.leaf_encoding.clone(),
        }
    }

    pub fn render(&self) -> String {
        render_merkle_tree(&self.tree)
    }

    pub fn root(&self) -> String {
        format!("0x{}", hex::encode(&self.tree[0]))
    }

    pub fn validate(&self) {
        (0..self.values.len()).for_each(|i| self.validate_value(i))
    }

    pub fn leaf_hash(&self, leaf: &[String]) -> String {
        format!(
            "0x{}",
            hex::encode(standard_leaf_hash(leaf.to_vec(), &self.leaf_encoding))
        )
    }

    pub fn leaf_lookup(&self, leaf: &[String]) -> usize {
        let binding = self.leaf_hash(leaf);
        let leaf_hash = binding.split_at(2).1;

        *self
            .hash_lookup
            .get(leaf_hash)
            .expect("Leaf is not in tree")
    }

    pub fn get_proof(&self, leaf: LeafType) -> Vec<String> {
        let value_index = match leaf {
            LeafType::Number(i) => i,
            LeafType::LeafBytes(v) => self.leaf_lookup(&v),
        };
        self.validate_value(value_index);

        // rebuild tree index and generate proof
        let value = self.values.get(value_index).unwrap();
        let proof = get_proof(self.tree.clone(), value.tree_index);

        // check proof
        let hash = self.tree.get(value.tree_index).unwrap();
        let implied_root = process_proof(hash.clone(), &proof);

        if !implied_root.eq(self.tree.get(0).unwrap()) {
            panic!("Unable to prove value")
        }

        proof
            .iter()
            .map(|p| format!("0x{}", hex::encode(p)))
            .collect()
    }

    pub fn get_multi_proof(&self, leaves: &[LeafType]) -> MultiProof<Vec<String>, String> {
        let value_indices: Vec<usize> = leaves
            .iter()
            .map(|leaf| match leaf {
                LeafType::Number(i) => *i,
                LeafType::LeafBytes(v) => self.leaf_lookup(v),
            })
            .collect();

        value_indices.iter().for_each(|i| self.validate_value(*i));

        // rebuild tree indices and generate proof
        let mut indices: Vec<usize> = value_indices
            .iter()
            .map(|i| self.values.get(*i).unwrap().tree_index)
            .collect();
        let multi_proof = get_multi_proof(self.tree.clone(), &mut indices);

        // check proof
        let implied_root = process_multi_proof(&multi_proof);
        if !implied_root.eq(self.tree.get(0).unwrap()) {
            panic!("Unable to prove value")
        }

        let leaves: Vec<Vec<String>> = multi_proof
            .leaves
            .iter()
            .map(|leaf| {
                let index = *self.hash_lookup.get(&hex::encode(leaf)).unwrap();
                self.values.get(index).unwrap().value.clone()
            })
            .collect();

        let proof = multi_proof
            .proof
            .iter()
            .map(|p| format!("0x{}", hex::encode(p)))
            .collect();

        MultiProof {
            leaves,
            proof,
            proof_flags: multi_proof.proof_flags,
        }
    }

    fn validate_value(&self, index: usize) {
        check_bounds(&self.values, index);
        let value = self.values.get(index).unwrap();
        check_bounds(&self.tree, value.tree_index);
        let leaf = standard_leaf_hash(value.value.clone(), &self.leaf_encoding);
        if !leaf.eq(self.tree.get(value.tree_index).unwrap()) {
            panic!("Merkle tree does not contain the expected value")
        }
    }
}

impl Iterator for StandardMerkleTree {
    type Item = Vec<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.values.is_empty() {
            let v = self.values.remove(0);
            Some(v.value)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn characters(s: &str) -> (Vec<Vec<String>>, StandardMerkleTree) {
        let l: Vec<Vec<String>> = s.chars().map(|c| vec![c.to_string()]).collect();
        let t = StandardMerkleTree::of(l.clone(), &["string".to_string()]);
        (l, t)
    }

    #[test]
    fn test_standard_leaf_hash() {
        let values = vec![
            "0x1111111111111111111111111111111111111111".to_string(),
            "5000000000000000000".to_string(),
        ];
        let hash = standard_leaf_hash(values, &["address".to_string(), "uint".to_string()]);
        let expected_hash: Bytes = [
            235, 2, 196, 33, 207, 164, 137, 118, 230, 109, 251, 41, 18, 7, 69, 144, 158, 163, 160,
            248, 67, 69, 108, 38, 60, 248, 241, 37, 52, 131, 226, 131,
        ]
        .into();

        assert_eq!(hash, expected_hash)
    }

    #[test]
    fn test_of() {
        let values = vec![
            vec![
                "0x1111111111111111111111111111111111111111".to_string(),
                "5000000000000000000".to_string(),
            ],
            vec![
                "0x2222222222222222222222222222222222222222".to_string(),
                "2500000000000000000".to_string(),
            ],
        ];

        let merkle_tree =
            StandardMerkleTree::of(values, &["address".to_string(), "uint256".to_string()]);
        let expected_tree = vec![
            "0xd4dee0beab2d53f2cc83e567171bd2820e49898130a22622b10ead383e90bd77",
            "0xeb02c421cfa48976e66dfb29120745909ea3a0f843456c263cf8f1253483e283",
            "0xb92c48e9d7abe27fd8dfd6b5dfdbfb1c9a463f80c712b66f3a5180a090cccafc",
        ];

        assert_eq!(merkle_tree.dump().tree, expected_tree);
    }

    #[test]
    fn test_validate() {
        let (_, t) = characters("abcdef");
        t.validate();
    }

    #[test]
    fn test_get_proof() {
        let (_, t) = characters("abcdef");

        for (i, v) in t.clone().enumerate() {
            let proof = t.get_proof(LeafType::Number(i));
            let proof2 = t.get_proof(LeafType::LeafBytes(v));

            assert_eq!(proof, proof2);
        }
    }

    #[test]
    fn test_get_multi_proof() {
        let (l, t) = characters("abcdef");

        let leaves_array = vec![
            vec![],
            vec![0, 1],
            vec![0, 1, 5],
            vec![1, 3, 4, 5],
            vec![0, 2, 4, 5],
            vec![0, 1, 2, 3, 4, 5],
        ];

        leaves_array.iter().for_each(|ids| {
            let leaves: Vec<LeafType> = ids.iter().map(|i| LeafType::Number(*i)).collect();
            let proof = t.get_multi_proof(&leaves);
            let leaves: Vec<LeafType> = ids
                .iter()
                .map(|i| LeafType::LeafBytes(l[*i].clone()))
                .collect();
            let proof2 = t.get_multi_proof(&leaves);

            assert_eq!(proof, proof2);
        })
    }

    #[test]
    fn test_render() {
        let (_, t) = characters("abc");

        println!("{:?}", t.tree);

        let expected = "0) 0xf2129b5a697531ef818f644564a6552b35c549722385bc52aa7fe46c0b5f46b1
├─ 1) 0xfa914d99a18dc32d9725b3ef1c50426deb40ec8d0885dac8edcc5bfd6d030016
│  ├─ 3) 0x9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c
│  └─ 4) 0x19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681
└─ 2) 0x9cf5a63718145ba968a01c1d557020181c5b252f665cf7386d370eddb176517b";

        assert_eq!(t.render(), expected);
    }

    #[test]
    fn test_dump_load() {
        let (_, t) = characters("abcdef");
        let t2 = StandardMerkleTree::load(t.dump());

        t2.validate();
        assert_eq!(t, t2);
    }

    #[test]
    fn test_root() {
        let (_, t) = characters("abc");
        assert_eq!(
            t.root(),
            "0xf2129b5a697531ef818f644564a6552b35c549722385bc52aa7fe46c0b5f46b1"
        )
    }

    #[test]
    #[should_panic = "Index out of range"]
    fn test_out_of_bounds_panic() {
        let (_, t) = characters("a");
        t.get_proof(LeafType::Number(1));
    }

    #[test]
    #[should_panic = "Unknown format"]
    fn test_unrecognized_tree_dump() {
        StandardMerkleTree::load(StandardMerkleTreeData {
            format: "nonstandard".to_string(),
            tree: Vec::new(),
            values: Vec::new(),
            leaf_encoding: Vec::new(),
        });
    }

    #[test]
    #[should_panic = "Merkle tree does not contain the expected value"]
    fn test_malformed_tree_dump() {
        let zero = format!("0x{}", hex::encode(Bytes::from(vec![0u8; 32])));
        let t = StandardMerkleTree::load(StandardMerkleTreeData {
            format: "standard-v1".to_string(),
            tree: vec![zero],
            values: vec![Values {
                value: vec!['0'.to_string()],
                tree_index: 0,
            }],
            leaf_encoding: vec!["uint256".to_string()],
        });

        t.get_proof(LeafType::Number(0));
    }

    #[test]
    #[should_panic = "Unable to prove value"]
    fn test_malformed_tree_dump2() {
        let zero_bytes = Bytes::from(vec![0u8; 32]);
        let zero = format!("0x{}", hex::encode(zero_bytes.clone()));
        let keccak_zero = format!("0x{}", hex::encode(keccak256(keccak256(zero_bytes))));

        let t = StandardMerkleTree::load(StandardMerkleTreeData {
            format: "standard-v1".to_string(),
            tree: vec![zero.clone(), zero, keccak_zero],
            values: vec![Values {
                value: vec!['0'.to_string()],
                tree_index: 2,
            }],
            leaf_encoding: vec!["uint256".to_string()],
        });

        t.get_proof(LeafType::Number(0));
    }
}
