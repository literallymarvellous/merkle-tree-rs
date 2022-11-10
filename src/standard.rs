use core::panic;
use ethers::{
    abi::{self, Token},
    types::{Address, Bytes, U256},
    utils::{hex, keccak256},
};
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
            _ => panic!("Invalid type"),
        }
    }
    Bytes::from(keccak256(keccak256(Bytes::from(abi::encode(&tokens)))))
}

pub fn check_bounds<T>(values: &[T], index: usize) {
    if index > values.len() {
        panic!("Index out of range")
    }
}

struct HashedValues {
    value: Vec<String>,
    value_index: usize,
    hash: Bytes,
}

#[derive(Debug, PartialEq, Clone)]
struct Values {
    value: Vec<String>,
    tree_index: usize,
}

#[derive(PartialEq, Debug)]
pub struct StandardMerkleTreeData {
    format: String,
    tree: Vec<String>,
    values: Vec<Values>,
    leaf_encoding: Vec<String>,
}

#[derive(Debug)]
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
            panic!("Unknow format");
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
        *self
            .hash_lookup
            .get(&self.leaf_hash(leaf))
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
                let index = *self
                    .hash_lookup
                    .get(&format!("0x{}", hex::encode(leaf)))
                    .unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_standard_merkle_tree() {
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
}
