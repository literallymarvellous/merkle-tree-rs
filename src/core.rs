use std::error::Error;

use ethers::{types::Bytes, utils::keccak256};
use anyhow::{Result, anyhow, Ok};

pub fn hash_pair(a: &Bytes, b: &Bytes) -> Bytes {
  let mut s = [a.clone(), b.clone()];
  s.sort_by(|a, b| a.cmp(b));
  let bytes = s.concat();
  Bytes::from(keccak256(bytes))
}

pub fn left_child_index(i: usize) -> usize {
  2 * i + 1
}

pub fn right_child_index(i: usize) -> usize {
  2 * i + 2
}

pub fn parent_index(i: usize) -> Result<usize> {
  if i > 0 {
    Ok(i - 1 / 2)
  } else {
    Err(anyhow!("Root has no parent"))
  }
}

pub fn sibling_index(i: i32) -> Result<usize> {
  if i > 0 {
    let r = i - (-1i32) ^ (i % 2);
    Ok(r as usize)
  } else {
    Err(anyhow!("Root has no sibling"))
  }
}

pub fn is_tree_node(tree: &[Bytes], i: usize) -> bool {
  i < tree.len()
}

pub fn is_internal_node(tree: &[Bytes], i: usize) -> bool {
  is_tree_node(tree, left_child_index(i))
}

pub fn is_leaf_node(tree: &[Bytes], i: usize) -> bool {
  is_tree_node(tree, i) && !is_internal_node(tree, i)
}

pub fn is_valid_merkle_node(node: &Bytes) -> bool {
  node.len() == 32
}

pub fn check_tree_node(tree: &[Bytes], i: usize) -> Result<()> {
  if is_tree_node(tree, i) {
    Ok(())
  } else {
    Err(anyhow!("Index is not in tree"))
  }
}

pub fn check_internal_node(tree: &[Bytes], i: usize) -> Result<()> {
  if is_internal_node(tree, i) {
    Ok(())
  } else {
    Err(anyhow!("Index is not in tree"))
  }
}

pub fn check_leaf_node(tree: &[Bytes], i: usize) -> Result<()> {
  if is_leaf_node(tree, i) {
    Ok(())
  } else {
    Err(anyhow!("Index is not in tree"))
  }
}

pub fn check_valid_merkle_node(node: &Bytes) {
  if is_valid_merkle_node(node) == false {
    panic!("Index is not in tree")
  }
}

pub fn make_merkle_tree(leaves: Vec<Bytes>) -> Vec<Bytes> {
  leaves.iter().for_each(check_valid_merkle_node);

  if leaves.len() == 0 { 
    panic!("Expected non-zero number of leaves") 
  };

  let tree_length = 2 * leaves.len() - 1;
  let mut tree: Vec<Bytes> = vec![Bytes::from([0]); tree_length];

  leaves.iter()
      .enumerate()
      .for_each(|(i, v)| tree[tree_length - 1 - i] = v.clone());

  for i in (0..tree_length - leaves.len()).rev() {
    let left_child = &tree[left_child_index(i)];
    let right_child = &tree[right_child_index(i)];
      tree[i] = hash_pair(left_child, right_child);
  }
  
  tree
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_pair() {
      let a = Bytes::from([1, 2, 3, 4]);
      let b = Bytes::from([2, 3, 5, 8]);
      let c = Bytes::from([5, 6, 7, 8, 9, 10]);
      let d = Bytes::from([0, 2, 3, 4]);

      let bytes = hash_pair(&a,&c);
      let bytes2 = hash_pair(&b,&d);
      let result = Bytes::from([
          157, 164, 23, 177, 133, 189, 185,  36,
          130,  79, 11,   7, 190,  14, 240, 222,
          55, 123, 39, 238, 169, 228, 138, 102,
            8,  45, 64, 166,   3, 143,  48,  92
        ]);
      let result2 = Bytes::from([
          233,  88, 165, 147,  77, 183, 162, 199,
          170, 207,  58,  67, 225, 101, 161,  93,
          18, 143,   7, 211, 166,  76, 248, 229,
          224, 113,  67,  52, 237, 131, 198,  96
        ]);

      assert_eq!(bytes, result);
      assert_eq!(bytes2, result2);
    }

    #[test]
    fn test_make_merkle_tree() {
      let byte = Bytes::from([
          157, 164, 23, 177, 133, 189, 185,  36,
          130,  79, 11,   7, 190,  14, 240, 222,
          55, 123, 39, 238, 169, 228, 138, 102,
            8,  45, 64, 166,   3, 143,  48,  92
        ]);
      let byte2 = Bytes::from([
          233,  88, 165, 147,  77, 183, 162, 199,
          170, 207,  58,  67, 225, 101, 161,  93,
          18, 143,   7, 211, 166,  76, 248, 229,
          224, 113,  67,  52, 237, 131, 198,  96
        ]);
        let byte3 = Bytes::from([
          15, 164, 23, 177, 133, 189, 185,  36,
          130,  179, 11,   37, 19,  14, 240, 222,
          25, 13, 39, 28, 169, 28, 138, 102,
          28,  45, 64, 166, 30, 143,  108,  92
        ]);
      let byte4 = Bytes::from([
          233,  80, 165, 147,  77, 183, 162, 199,
          17, 207,  58,  7, 225, 101, 161,  93,
          18, 143,   70, 211, 166,  76, 208, 229,
          24, 100,  67,  52, 237, 111, 198,  96
        ]);

      let leaves = vec![byte, byte2, byte3, byte4];

      let tree = make_merkle_tree(leaves);

      let expected_tree = [
          Bytes::from( [
            115, 209, 118, 200,   5,  4,  69,  77,
            194,  99, 240, 121,  27, 47, 159, 212,
            239, 185,  42,   0, 241, 72,  77, 142,
            45,  32,  88, 158,   8, 61,  44,  11
          ]),
          Bytes::from( [
            206,   8, 250, 120, 108, 113,  57, 176,
            105,  92,  78, 166, 155,  96, 168, 176,
            157,  57,  37, 199, 165,   0, 152,  41,
            72, 109, 244, 215,  70, 159, 202, 146
          ]),
          Bytes::from( [
            230,  18, 175, 174, 238, 192,  61, 110,
            232,   8,  30,  90,  33, 224, 209,  91,
            37,  85, 171, 114,  56, 219, 231, 210,
            62, 217, 230,  42,  18,  28, 139, 203
          ]),
          Bytes::from( [
            233,  80, 165, 147,  77, 183, 162, 199,
            17, 207,  58,   7, 225, 101, 161,  93,
            18, 143,  70, 211, 166,  76, 208, 229,
            24, 100,  67,  52, 237, 111, 198,  96
          ]),
          Bytes::from( [
            15, 164, 23, 177, 133, 189, 185,  36,
            130, 179, 11,  37,  19,  14, 240, 222,
            25,  13, 39,  28, 169,  28, 138, 102,
            28,  45, 64, 166,  30, 143, 108,  92
          ]),
          Bytes::from( [
            233,  88, 165, 147,  77, 183, 162, 199,
            170, 207,  58,  67, 225, 101, 161,  93,
            18, 143,   7, 211, 166,  76, 248, 229,
            224, 113,  67,  52, 237, 131, 198,  96
          ]),
          Bytes::from( [
            157, 164, 23, 177, 133, 189, 185,  36,
            130,  79, 11,   7, 190,  14, 240, 222,
            55, 123, 39, 238, 169, 228, 138, 102,
            8,  45, 64, 166,   3, 143,  48,  92
          ])
        ];

      assert_eq!(tree, expected_tree);
    }

}