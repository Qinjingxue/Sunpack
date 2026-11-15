//! ENC GOST 28147-89 TestSbox: rotated shared tables and interleaved blocks.
//! S-box/key ordering adapted from RustCrypto magma 0.9.0.
//! Copyright (c) 2017 Artyom Pavlov. MIT: licenses/magma-license.txt.
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Gost {
    keys: [u32; 8],
}
const SBOX: [[u8; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
];
// The S-box is fixed, not key-dependent. Share this 4 KiB read-only table
// across every stream instead of expanding or retaining a table per password.
static TABLES: [[u32; 256]; 4] = make_tables();
const fn make_tables() -> [[u32; 256]; 4] {
    let mut tables = [[0; 256]; 4];
    let mut row = 0;
    while row < 4 {
        let mut byte = 0;
        while byte < 256 {
            let value =
                SBOX[row * 2][byte & 15] as u32 | (SBOX[row * 2 + 1][byte >> 4] as u32) << 4;
            tables[row][byte] = (value << (row * 8)).rotate_left(11);
            byte += 1;
        }
        row += 1;
    }
    tables
}
#[inline(always)]
fn g(word: u32, key: u32) -> u32 {
    let value = word.wrapping_add(key);
    TABLES[0][(value & 255) as usize]
        ^ TABLES[1][((value >> 8) & 255) as usize]
        ^ TABLES[2][((value >> 16) & 255) as usize]
        ^ TABLES[3][(value >> 24) as usize]
}
impl Gost {
    pub(super) fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut keys = [0; 8];
        // ENC's per-word reversal before upstream big-endian loading is LE.
        for (dst, src) in keys.iter_mut().zip(key.chunks_exact(4)) {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }
        Self { keys }
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 8, 0);
        let n = bytes.len() / 32 * 32;
        let (bulk, tail) = bytes.split_at_mut(n);
        for group in bulk.chunks_exact_mut(32) {
            self.encrypt_batch::<4>(group);
        }
        match tail.len() {
            0 => (),
            8 => self.encrypt_batch::<1>(tail),
            16 => self.encrypt_batch::<2>(tail),
            24 => self.encrypt_batch::<3>(tail),
            _ => unreachable!(),
        }
    }
    #[inline(always)]
    fn encrypt_batch<const N: usize>(&self, bytes: &mut [u8]) {
        let mut left = [0u32; N];
        let mut right = [0u32; N];
        for (i, block) in bytes.chunks_exact(8).enumerate() {
            // Reversing the whole upstream block also swaps its two words.
            right[i] = u32::from_le_bytes(block[..4].try_into().unwrap());
            left[i] = u32::from_le_bytes(block[4..].try_into().unwrap());
        }
        macro_rules! pair {
            ($a:expr,$b:expr) => {
                for i in 0..N {
                    left[i] ^= g(right[i], self.keys[$a]);
                }
                for i in 0..N {
                    right[i] ^= g(left[i], self.keys[$b]);
                }
            };
        }
        for _ in 0..3 {
            pair!(0, 1);
            pair!(2, 3);
            pair!(4, 5);
            pair!(6, 7);
        }
        pair!(7, 6);
        pair!(5, 4);
        pair!(3, 2);
        pair!(1, 0);
        for (i, block) in bytes.chunks_exact_mut(8).enumerate() {
            block[..4].copy_from_slice(&left[i].to_le_bytes());
            block[4..].copy_from_slice(&right[i].to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::cipher::{Block, BlockEncrypt, KeyInit};
    #[test]
    fn interleaved_groups_and_all_tails_match_upstream() {
        let mut seed = 0x3521_a917u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..24 {
            let key: [u8; 32] = std::array::from_fn(|_| next());
            let cipher = Gost::new(&key);
            let mut adapted_key = key;
            for word in adapted_key.chunks_exact_mut(4) {
                word.reverse();
            }
            let reference = ::magma::Gost89Test::new_from_slice(&adapted_key).unwrap();
            for blocks in 0..=33 {
                let prefix = blocks % 32;
                let mut actual: Vec<u8> = (0..prefix + blocks * 8 + 7).map(|_| next()).collect();
                let mut expected = actual.clone();
                for block in expected[prefix..prefix + blocks * 8].chunks_exact_mut(8) {
                    let mut b = Block::<::magma::Gost89Test>::default();
                    b.copy_from_slice(block);
                    b.reverse();
                    reference.encrypt_block(&mut b);
                    b.reverse();
                    block.copy_from_slice(&b);
                }
                cipher.encrypt(&mut actual[prefix..prefix + blocks * 8]);
                assert_eq!(actual, expected);
            }
        }
    }
}
