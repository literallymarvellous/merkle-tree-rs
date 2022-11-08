use std::{collections::HashMap, str::FromStr};
use crate::standard::abi::Uint;
use ethers::{types::{Bytes, Address, H256}, utils::{keccak256, hex}, abi::{AbiEncode, self, Token}};

pub fn standard_leaf_hash(values: &[&str], types: Vec<&str>) -> Bytes {
  let mut tokens: Vec<Token> = Vec::new();
  for (i, t) in types.iter().enumerate() {
    match *t {
      "address" => {
        let address = Address::from_str(values[i]).unwrap();
        tokens.push(Token::Address(address));
      },
      "uint" => {
        let uint = values[i].parse::<u32>().unwrap();
        tokens.push(Token::Uint(uint.into()));
      },
      _ => panic!("Invalid type")
    }
  }
  Bytes::from(keccak256(keccak256(Bytes::from(abi::encode(&tokens)))))
}


#[derive(Debug, PartialEq)]
struct Values<T> {
  value: T,
  tree_index: usize,
}

#[derive(PartialEq, Debug)]
struct StandardMerkleData<T> {
  format: String,
  tree: Vec<String>,
  values: Vec<Values<T>>,
  leaf_encoding: Vec<String>
}

#[derive(Debug)]
struct StandardMerkle {
  hash_lookup: HashMap<String, i32>
}

impl StandardMerkle {
  pub fn new<T>(tree: Vec<Bytes>, values: Vec<Values<T>>, leaf_encoding: Vec<String>) -> Self {
    todo!()
  }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_leaf_hash() {
      let values = vec!["0x1111111111111111111111111111111111111111", "500000"];
      let hash = standard_leaf_hash(&values, ["address", "uint"].to_vec());
      let expected_hash: Bytes = [
          216, 216, 136, 162, 127,  51,  67,  81,
          33,  75, 117,  98,  82, 151, 252,   6,
          11,  48, 123,  23, 134, 189,  35, 111,
          220, 209, 138, 188,  90,  54, 135,  77
        ].into();
      
      assert_eq!(hash, expected_hash)
    }
}