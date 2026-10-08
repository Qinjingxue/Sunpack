//! ENC Twofish-256: expand keyed S-box/MDS tables once, shared by all CTR slices.
//! Key schedule and q permutations adapted from RustCrypto twofish 0.7.1.
//! Copyright (c) 2017 Alexander Krotov. MIT license: licenses/twofish-license.txt.
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Twofish {
    tables: [[u32; 256]; 4],
    keys: [u32; 40],
}

const QBOX: [[[u8; 16]; 4]; 2] = [
    [
        [8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
        [14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
        [11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
        [13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
    ],
    [
        [2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
        [1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
        [4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
        [11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
    ],
];
const QORD: [[usize; 5]; 4] = [
    [1, 1, 0, 0, 1],
    [0, 1, 1, 0, 0],
    [0, 0, 0, 1, 1],
    [1, 0, 1, 1, 0],
];
const RS: [[u8; 8]; 4] = [
    [0x01, 0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e],
    [0xa4, 0x56, 0x82, 0xf3, 0x1e, 0xc6, 0x68, 0xe5],
    [0x02, 0xa1, 0xfc, 0xc1, 0x47, 0xae, 0x3d, 0x19],
    [0xa4, 0x55, 0x87, 0x5a, 0x58, 0xdb, 0x9e, 0x03],
];

const fn gf_mult(mut a: u8, mut b: u8, polynomial: u8) -> u8 {
    let mut result = 0;
    while a != 0 {
        if a & 1 != 0 {
            result ^= b;
        }
        a >>= 1;
        b = (b << 1) ^ if b & 0x80 != 0 { polynomial } else { 0 };
    }
    result
}
const fn q(which: usize, x: u8) -> u8 {
    let (a, b) = (x >> 4, x & 15);
    let a2 = QBOX[which][0][(a ^ b) as usize];
    let b2 = QBOX[which][1][((a ^ (b << 3 | b >> 1) ^ (a << 3)) & 15) as usize];
    let a4 = QBOX[which][2][(a2 ^ b2) as usize];
    let b4 = QBOX[which][3][((a2 ^ (b2 << 3 | b2 >> 1) ^ (a2 << 3)) & 15) as usize];
    (b4 << 4) | a4
}
// Public, key-independent tables are computed at compile time. No per-decoder
// allocation or global initialization; runtime setup only expands the keyed q chain.
static Q: [[u8; 256]; 2] = {
    let mut result = [[0; 256]; 2];
    let mut x = 0;
    while x < 256 {
        result[0][x] = q(0, x as u8);
        result[1][x] = q(1, x as u8);
        x += 1;
    }
    result
};
static MDS: [[u32; 256]; 4] = {
    let mut result = [[0; 256]; 4];
    let mut x = 0;
    while x < 256 {
        let a = x as u8;
        let b = gf_mult(a, 0x5b, 0x69);
        let c = gf_mult(a, 0xef, 0x69);
        result[0][x] = u32::from_le_bytes([a, b, c, c]);
        result[1][x] = u32::from_le_bytes([c, c, b, a]);
        result[2][x] = u32::from_le_bytes([b, c, a, c]);
        result[3][x] = u32::from_le_bytes([b, a, c, b]);
        x += 1;
    }
    result
};

fn h(x: u32, key: &[u8; 32], offset: usize) -> u32 {
    let mut result = 0;
    for (column, mut value) in x.to_le_bytes().into_iter().enumerate() {
        for stage in 0..4 {
            value =
                Q[QORD[column][stage]][value as usize] ^ key[(6 - 2 * stage + offset) * 4 + column];
        }
        value = Q[QORD[column][4]][value as usize];
        result ^= MDS[column][value as usize];
    }
    result
}
impl Twofish {
    pub(super) fn new(key: &[u8]) -> Self {
        let key: &[u8; 32] = key.try_into().expect("ENC uses Twofish-256");
        let mut cipher = Self {
            tables: [[0; 256]; 4],
            keys: [0; 40],
        };
        for index in 0..20 {
            let a = h(0x01010101 * (2 * index), key, 0);
            let b = h(0x01010101 * (2 * index + 1), key, 1).rotate_left(8);
            let sum = a.wrapping_add(b);
            cipher.keys[2 * index as usize] = sum;
            cipher.keys[2 * index as usize + 1] = sum.wrapping_add(b).rotate_left(9);
        }
        let mut s = Zeroizing::new([0u8; 16]);
        for (index, part) in key.chunks_exact(8).enumerate() {
            for row in 0..4 {
                for (value, coefficient) in part.iter().zip(RS[row]) {
                    s[4 * index + row] ^= gf_mult(*value, coefficient, 0x4d);
                }
            }
        }
        for column in 0..4 {
            for value in 0..256 {
                let mut keyed = Q[QORD[column][0]][value];
                for stage in 1..5 {
                    keyed = Q[QORD[column][stage]][(keyed ^ s[4 * (stage - 1) + column]) as usize];
                }
                cipher.tables[column][value] = MDS[column][keyed as usize];
            }
        }
        cipher
    }
    #[inline(always)]
    fn g(&self, value: u32) -> u32 {
        let b = value.to_le_bytes();
        self.tables[0][b[0] as usize]
            ^ self.tables[1][b[1] as usize]
            ^ self.tables[2][b[2] as usize]
            ^ self.tables[3][b[3] as usize]
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 16, 0);
        for group in bytes.chunks_exact_mut(128) {
            self.encrypt_group::<8>(group);
        }
        let n = bytes.len() / 128 * 128;
        let tail = &mut bytes[n..];
        match tail.len() / 16 {
            0 => (),
            1 => self.encrypt_group::<1>(tail),
            2 => self.encrypt_group::<2>(tail),
            3 => self.encrypt_group::<3>(tail),
            4 => self.encrypt_group::<4>(tail),
            5 => self.encrypt_group::<5>(tail),
            6 => self.encrypt_group::<6>(tail),
            7 => self.encrypt_group::<7>(tail),
            _ => unreachable!(),
        }
    }
    #[inline(always)]
    fn encrypt_group<const N: usize>(&self, bytes: &mut [u8]) {
        let mut states = [[0u32; 4]; N];
        for (p, block) in states.iter_mut().zip(bytes.chunks_exact(16)) {
            for (i, word) in block.chunks_exact(4).enumerate() {
                p[i] = u32::from_le_bytes(word.try_into().unwrap()) ^ self.keys[i];
            }
        }
        for round in 0..8 {
            let k = 4 * round + 8;
            for p in &mut states {
                let t1 = self.g(p[1].rotate_left(8));
                let t0 = self.g(p[0]).wrapping_add(t1);
                p[2] = (p[2] ^ t0.wrapping_add(self.keys[k])).rotate_right(1);
                p[3] = p[3].rotate_left(1) ^ t1.wrapping_add(t0).wrapping_add(self.keys[k + 1]);
            }
            for p in &mut states {
                let t1 = self.g(p[3].rotate_left(8));
                let t0 = self.g(p[2]).wrapping_add(t1);
                p[0] = (p[0] ^ t0.wrapping_add(self.keys[k + 2])).rotate_right(1);
                p[1] = p[1].rotate_left(1) ^ t1.wrapping_add(t0).wrapping_add(self.keys[k + 3]);
            }
        }
        for (p, block) in states.into_iter().zip(bytes.chunks_exact_mut(16)) {
            for (i, value) in [p[2], p[3], p[0], p[1]].into_iter().enumerate() {
                block[4 * i..4 * i + 4].copy_from_slice(&(value ^ self.keys[4 + i]).to_le_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher::{BlockEncrypt, KeyInit};
    #[test]
    fn interleaved_groups_and_tails_match_upstream() {
        let mut seed = 0x731d_936bu32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..16 {
            let key: [u8; 32] = std::array::from_fn(|_| next());
            let cipher = Twofish::new(&key);
            let reference = ::twofish::Twofish::new_from_slice(&key).unwrap();
            for count in 0..=33 {
                let prefix = count * 3 % 32;
                let mut bytes: Vec<u8> = (0..prefix + count * 16 + 7).map(|_| next()).collect();
                let mut expected = bytes.clone();
                for block in expected[prefix..prefix + count * 16].chunks_exact_mut(16) {
                    reference
                        .encrypt_block(cipher::Block::<::twofish::Twofish>::from_mut_slice(block));
                }
                cipher.encrypt(&mut bytes[prefix..prefix + count * 16]);
                assert_eq!(bytes, expected);
            }
        }
    }
}
