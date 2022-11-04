use std::error::Error;

use ethers::{types::Bytes, utils::keccak256};
use anyhow::{Result, anyhow, Ok};

pub fn hash_pair(a: Bytes, b: Bytes) -> [u8; 32] {
  let mut s = [a, b];
  s.sort_by(|a, b| a.cmp(b));
  let bytes = s.concat();
  keccak256(bytes)
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
  isTreeNode(tree, left_child_index(i))
}

pub fn is_leaf_node(tree: &[Bytes], i: usize) -> bool {
  isTreeNode(tree, i) && !isInternalNode(tree, i)
}

pub fn is_validmerkle_node(node: Bytes) -> bool {
  node.len() == 32
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

      let bytes = hash_pair(a, c);
      let bytes2 = hash_pair(b, d);
      let result = [
          157, 164, 23, 177, 133, 189, 185,  36,
          130,  79, 11,   7, 190,  14, 240, 222,
          55, 123, 39, 238, 169, 228, 138, 102,
            8,  45, 64, 166,   3, 143,  48,  92
        ];
      let result2 = [
          233,  88, 165, 147,  77, 183, 162, 199,
          170, 207,  58,  67, 225, 101, 161,  93,
          18, 143,   7, 211, 166,  76, 248, 229,
          224, 113,  67,  52, 237, 131, 198,  96
        ];

      assert_eq!(bytes, result);
      assert_eq!(bytes2, result2);
    }

}