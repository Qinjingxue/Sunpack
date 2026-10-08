//! ENC Threefish-1024 with zero tweak: four-block AVX2 and scalar tails.
//! Key schedule/constants adapted from RustCrypto threefish 0.5.2.
//! Copyright (c) 2016-2017 Christian Barcenas, Artyom Pavlov.
//! MIT license: licenses/threefish-license.txt.
use std::ops::BitXor;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Threefish {
    keys: [[u64; 16]; 21],
}
const ROT: [[u32; 8]; 8] = [
    [24, 13, 8, 47, 8, 17, 22, 37],
    [38, 19, 10, 55, 49, 18, 23, 52],
    [33, 4, 51, 13, 34, 41, 59, 17],
    [5, 20, 48, 41, 47, 28, 16, 25],
    [41, 9, 37, 31, 12, 47, 44, 30],
    [16, 34, 56, 51, 4, 53, 42, 41],
    [31, 44, 47, 46, 19, 42, 44, 25],
    [9, 48, 35, 52, 23, 31, 37, 20],
];
trait Word: Copy + BitXor<Output = Self> {
    fn splat(value: u64) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn rol(self, bits: u32) -> Self;
}
impl Word for u64 {
    #[inline(always)]
    fn splat(value: u64) -> Self {
        value
    }
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    #[inline(always)]
    fn rol(self, bits: u32) -> Self {
        self.rotate_left(bits)
    }
}
impl Threefish {
    pub(super) fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 128);
        let mut words = Zeroizing::new([0u64; 17]);
        for (dst, src) in words[..16].iter_mut().zip(key.chunks_exact(8)) {
            *dst = u64::from_le_bytes(src.try_into().unwrap());
        }
        words[16] = words[..16].iter().fold(0x1bd1_1bda_a9fc_1a22, |v, k| v ^ k);
        let mut keys = [[0; 16]; 21];
        for (s, row) in keys.iter_mut().enumerate() {
            for (i, value) in row.iter_mut().enumerate() {
                *value = words[(s + i) % 17];
            }
            // Both tweak words and their parity are zero in ENC.
            row[15] = row[15].wrapping_add(s as u64);
        }
        Self { keys }
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 128, 0);
        #[cfg(target_arch = "x86_64")]
        let bytes = if bytes.len() >= 512 && std::is_x86_feature_detected!("avx2") {
            let n = bytes.len() / 512 * 512;
            let (bulk, tail) = bytes.split_at_mut(n);
            // SAFETY: runtime CPU/OS detection and complete groups of four blocks.
            unsafe { avx2::encrypt(&self.keys, bulk) };
            tail
        } else {
            bytes
        };
        #[cfg(target_arch = "aarch64")]
        let bytes = if bytes.len() >= 256 && std::arch::is_aarch64_feature_detected!("neon") {
            let n = bytes.len() / 256 * 256;
            let (bulk, tail) = bytes.split_at_mut(n);
            // SAFETY: detected NEON; complete two-block groups, unaligned loads.
            unsafe { neon::encrypt(&self.keys, bulk) };
            tail
        } else {
            bytes
        };
        self.encrypt_scalar(bytes);
    }
    fn encrypt_scalar(&self, bytes: &mut [u8]) {
        for block in bytes.chunks_exact_mut(128) {
            let mut w = [0; 16];
            for (dst, src) in w.iter_mut().zip(block.chunks_exact(8)) {
                *dst = u64::from_le_bytes(src.try_into().unwrap());
            }
            w = encrypt_words(&self.keys, w);
            for (dst, src) in block.chunks_exact_mut(8).zip(w) {
                dst.copy_from_slice(&src.to_le_bytes());
            }
        }
    }
}
#[inline(always)]
fn round<const R: usize, W: Word>(mut w: [W; 16]) -> [W; 16] {
    macro_rules! mix { ($($j:expr),*) => {$(
        w[2*$j] = w[2*$j].add(w[2*$j+1]);
        w[2*$j+1] = w[2*$j+1].rol(ROT[R][$j]) ^ w[2*$j];
    )*}; }
    mix!(0, 1, 2, 3, 4, 5, 6, 7);
    // Inverse of the upstream scatter permutation; register renaming only.
    [
        w[0], w[9], w[2], w[13], w[6], w[11], w[4], w[15], w[10], w[7], w[12], w[3], w[14], w[5],
        w[8], w[1],
    ]
}
#[inline(always)]
fn add_key<W: Word>(mut w: [W; 16], key: &[u64; 16]) -> [W; 16] {
    for (value, &k) in w.iter_mut().zip(key) {
        *value = value.add(W::splat(k));
    }
    w
}
#[inline(always)]
fn encrypt_words<W: Word>(keys: &[[u64; 16]; 21], mut w: [W; 16]) -> [W; 16] {
    // Unroll each eight-round cycle so every rotate has an immediate count.
    // Keep the ten cycles in a loop to avoid eighty rounds of duplicated code.
    for pair in keys[..20].chunks_exact(2) {
        w = add_key(w, &pair[0]);
        w = round::<0, _>(w);
        w = round::<1, _>(w);
        w = round::<2, _>(w);
        w = round::<3, _>(w);
        w = add_key(w, &pair[1]);
        w = round::<4, _>(w);
        w = round::<5, _>(w);
        w = round::<6, _>(w);
        w = round::<7, _>(w);
    }
    add_key(w, &keys[20])
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use std::arch::x86_64::*;
    #[derive(Clone, Copy)]
    struct V(__m256i);
    impl BitXor for V {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self {
            // SAFETY: V is private, only constructed/used by the AVX2 entry point.
            Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
        }
    }
    impl Word for V {
        #[inline(always)]
        fn splat(value: u64) -> Self {
            Self(unsafe { _mm256_set1_epi64x(value as i64) })
        }
        #[inline(always)]
        fn add(self, rhs: Self) -> Self {
            Self(unsafe { _mm256_add_epi64(self.0, rhs.0) })
        }
        #[inline(always)]
        fn rol(self, bits: u32) -> Self {
            unsafe {
                Self(_mm256_or_si256(
                    _mm256_sll_epi64(self.0, _mm_cvtsi32_si128(bits as i32)),
                    _mm256_srl_epi64(self.0, _mm_cvtsi32_si128((64 - bits) as i32)),
                ))
            }
        }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn transpose([a, b, c, d]: [__m256i; 4]) -> [__m256i; 4] {
        let ab0 = _mm256_unpacklo_epi64(a, b);
        let ab1 = _mm256_unpackhi_epi64(a, b);
        let cd0 = _mm256_unpacklo_epi64(c, d);
        let cd1 = _mm256_unpackhi_epi64(c, d);
        [
            _mm256_permute2x128_si256::<0x20>(ab0, cd0),
            _mm256_permute2x128_si256::<0x20>(ab1, cd1),
            _mm256_permute2x128_si256::<0x31>(ab0, cd0),
            _mm256_permute2x128_si256::<0x31>(ab1, cd1),
        ]
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encrypt(keys: &[[u64; 16]; 21], bytes: &mut [u8]) {
        for group in bytes.chunks_exact_mut(512) {
            let p = group.as_mut_ptr();
            let mut w = [V(_mm256_setzero_si256()); 16];
            for i in 0..4 {
                let offset = i * 32;
                let columns = transpose([
                    _mm256_loadu_si256(p.add(offset).cast()),
                    _mm256_loadu_si256(p.add(offset + 128).cast()),
                    _mm256_loadu_si256(p.add(offset + 256).cast()),
                    _mm256_loadu_si256(p.add(offset + 384).cast()),
                ]);
                for (dst, src) in w[i * 4..i * 4 + 4].iter_mut().zip(columns) {
                    *dst = V(src);
                }
            }
            w = encrypt_words(keys, w);
            for i in 0..4 {
                let rows = transpose([w[i * 4].0, w[i * 4 + 1].0, w[i * 4 + 2].0, w[i * 4 + 3].0]);
                for (block, row) in rows.into_iter().enumerate() {
                    _mm256_storeu_si256(p.add(block * 128 + i * 32).cast(), row);
                }
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[path = "threefish_neon.rs"]
mod neon;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_and_avx2_match_upstream_for_unaligned_groups_and_tails() {
        let mut seed = 0x92f1_038du32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..12 {
            let key: [u8; 128] = std::array::from_fn(|_| next());
            let cipher = Threefish::new(&key);
            let reference = ::threefish::Threefish1024::new_with_tweak(&key, &[0; 16]);
            for blocks in 0..=17 {
                let prefix = blocks * 3 % 32;
                let mut input: Vec<u8> = (0..prefix + blocks * 128 + 7).map(|_| next()).collect();
                let mut expected = input.clone();
                for block in expected[prefix..prefix + blocks * 128].chunks_exact_mut(128) {
                    let mut words = [0u64; 16];
                    for (w, b) in words.iter_mut().zip(block.chunks_exact(8)) {
                        *w = u64::from_le_bytes(b.try_into().unwrap());
                    }
                    reference.encrypt_block_u64(&mut words);
                    for (b, w) in block.chunks_exact_mut(8).zip(words) {
                        b.copy_from_slice(&w.to_le_bytes());
                    }
                }
                let mut scalar = input.clone();
                cipher.encrypt_scalar(&mut scalar[prefix..prefix + blocks * 128]);
                assert_eq!(scalar, expected);
                #[cfg(target_arch = "x86_64")]
                if std::is_x86_feature_detected!("avx2") {
                    let mut direct = input.clone();
                    let bulk = blocks / 4 * 512;
                    unsafe { avx2::encrypt(&cipher.keys, &mut direct[prefix..prefix + bulk]) };
                    cipher.encrypt_scalar(&mut direct[prefix + bulk..prefix + blocks * 128]);
                    assert_eq!(direct, expected);
                }
                cipher.encrypt(&mut input[prefix..prefix + blocks * 128]);
                assert_eq!(input, expected);
            }
        }
    }
}
