//! ENC Blowfish-256/448: interleaved independent blocks with one keyed table.
//! Key expansion and constants adapted from RustCrypto blowfish 0.9.1.
//! Copyright (c) 2006-2009 Graydon Hoare; (c) 2009-2013 Mozilla Foundation.
//! MIT: licenses/blowfish-license.txt.
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
#[path = "blowfish_init.rs"]
mod init;

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Blowfish {
    s: [[u32; 256]; 4],
    p: [u32; 18],
}
impl Blowfish {
    pub(super) fn new(key: &[u8]) -> Self {
        assert!(matches!(key.len(), 32 | 56));
        let mut cipher = Self {
            s: init::S,
            p: init::P,
        };
        let mut pos = 0;
        for word in &mut cipher.p {
            let mut value = 0;
            for _ in 0..4 {
                value = (value << 8) | key[pos] as u32;
                pos = (pos + 1) % key.len();
            }
            *word ^= value;
        }
        let mut lr = Zeroizing::new([0u32; 2]);
        for i in 0..9 {
            let ([l], [r]) = cipher.encrypt_words([lr[0]], [lr[1]]);
            *lr = [l, r];
            cipher.p[2 * i..2 * i + 2].copy_from_slice(&*lr);
        }
        for i in 0..4 {
            for j in 0..128 {
                let ([l], [r]) = cipher.encrypt_words([lr[0]], [lr[1]]);
                *lr = [l, r];
                cipher.s[i][2 * j..2 * j + 2].copy_from_slice(&*lr);
            }
        }
        cipher
    }
    #[inline(always)]
    fn f(&self, x: u32) -> u32 {
        let a = self.s[0][(x >> 24) as usize];
        let b = self.s[1][((x >> 16) & 255) as usize];
        let c = self.s[2][((x >> 8) & 255) as usize];
        let d = self.s[3][(x & 255) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }
    #[inline(always)]
    fn encrypt_words<const N: usize>(
        &self,
        mut left: [u32; N],
        mut right: [u32; N],
    ) -> ([u32; N], [u32; N]) {
        for round in 0..8 {
            for i in 0..N {
                left[i] ^= self.p[2 * round];
                right[i] ^= self.f(left[i]);
            }
            for i in 0..N {
                right[i] ^= self.p[2 * round + 1];
                left[i] ^= self.f(right[i]);
            }
        }
        (right.map(|r| r ^ self.p[17]), left.map(|l| l ^ self.p[16]))
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 8, 0);
        let n = bytes.len() / 64 * 64;
        let (bulk, tail) = bytes.split_at_mut(n);
        for group in bulk.chunks_exact_mut(64) {
            self.encrypt_batch::<8>(group);
        }
        match tail.len() {
            0 => (),
            8 => self.encrypt_batch::<1>(tail),
            16 => self.encrypt_batch::<2>(tail),
            24 => self.encrypt_batch::<3>(tail),
            32 => self.encrypt_batch::<4>(tail),
            40 => self.encrypt_batch::<5>(tail),
            48 => self.encrypt_batch::<6>(tail),
            56 => self.encrypt_batch::<7>(tail),
            _ => unreachable!(),
        }
    }
    #[inline(always)]
    fn encrypt_batch<const N: usize>(&self, bytes: &mut [u8]) {
        let mut left = [0; N];
        let mut right = [0; N];
        for (i, block) in bytes.chunks_exact(8).enumerate() {
            left[i] = u32::from_be_bytes(block[..4].try_into().unwrap());
            right[i] = u32::from_be_bytes(block[4..].try_into().unwrap());
        }
        let (left, right) = self.encrypt_words(left, right);
        for (i, block) in bytes.chunks_exact_mut(8).enumerate() {
            block[..4].copy_from_slice(&left[i].to_be_bytes());
            block[4..].copy_from_slice(&right[i].to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::cipher::{Block, BlockEncrypt, KeyInit};
    #[test]
    fn both_key_sizes_and_interleaved_tails_match_upstream() {
        let mut seed = 0x792b_914du32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for size in [32, 56] {
            for _ in 0..12 {
                let key: Vec<u8> = (0..size).map(|_| next()).collect();
                let cipher = Blowfish::new(&key);
                let reference: ::blowfish::Blowfish =
                    ::blowfish::Blowfish::new_from_slice(&key).unwrap();
                for blocks in 0..=33 {
                    let prefix = blocks * 3 % 32;
                    let mut input: Vec<u8> = (0..prefix + blocks * 8 + 7).map(|_| next()).collect();
                    let mut expected = input.clone();
                    for block in expected[prefix..prefix + blocks * 8].chunks_exact_mut(8) {
                        let mut b = Block::<::blowfish::Blowfish>::default();
                        b.copy_from_slice(block);
                        reference.encrypt_block(&mut b);
                        block.copy_from_slice(&b);
                    }
                    cipher.encrypt(&mut input[prefix..prefix + blocks * 8]);
                    assert_eq!(input, expected);
                }
            }
        }
    }
}
