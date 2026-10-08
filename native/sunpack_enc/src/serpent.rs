//! ENC Serpent-256: one expanded key for scalar tails and eight-block AVX2.
//! Key schedule and Boolean circuits adapted from RustCrypto serpent 0.6.0.
//! Copyright (c) 2019-2024 The RustCrypto Project Developers
//! Copyright (c) 2019 Jonathan Serra. MIT: licenses/serpent-license.txt.
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Shl};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Serpent {
    keys: [[u32; 4]; 33],
}

trait Word:
    Copy
    + BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
{
    fn splat(value: u32) -> Self;
    fn rol(self, bits: u32) -> Self;
}
impl Word for u32 {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        value
    }
    #[inline(always)]
    fn rol(self, bits: u32) -> Self {
        self.rotate_left(bits)
    }
}

impl Serpent {
    pub(super) fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut words = Zeroizing::new([0u32; 140]);
        // ENC reverses the whole key before standard Serpent key expansion.
        for (dst, src) in words[..8].iter_mut().rev().zip(key.chunks_exact(4)) {
            *dst = u32::from_be_bytes(src.try_into().unwrap());
        }
        for i in 0..132 {
            let n = i + 8;
            words[n] = (words[n - 8]
                ^ words[n - 5]
                ^ words[n - 3]
                ^ words[n - 1]
                ^ 0x9e37_79b9
                ^ i as u32)
                .rotate_left(11);
        }
        let mut keys = [[0; 4]; 33];
        for (i, dst) in keys.iter_mut().enumerate() {
            *dst = sbox(
                (35 - i) % 8,
                words[8 + i * 4..12 + i * 4].try_into().unwrap(),
            );
        }
        Self { keys }
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 16, 0);
        #[cfg(target_arch = "x86_64")]
        let bytes = if bytes.len() >= 128 && std::is_x86_feature_detected!("avx2") {
            let n = bytes.len() / 128 * 128;
            let (bulk, tail) = bytes.split_at_mut(n);
            // SAFETY: runtime CPU/OS detection; the backend receives complete groups.
            unsafe { avx2::encrypt(&self.keys, bulk) };
            tail
        } else {
            bytes
        };
        #[cfg(target_arch = "aarch64")]
        let bytes = if bytes.len() >= 64 && std::arch::is_aarch64_feature_detected!("neon") {
            let n = bytes.len() / 64 * 64;
            let (bulk, tail) = bytes.split_at_mut(n);
            // SAFETY: detected NEON; complete four-block groups, unaligned loads.
            unsafe { neon::encrypt(&self.keys, bulk) };
            tail
        } else {
            bytes
        };
        self.encrypt_scalar(bytes);
    }
    fn encrypt_scalar(&self, bytes: &mut [u8]) {
        for block in bytes.chunks_exact_mut(16) {
            let mut words = [0; 4];
            for (dst, src) in words.iter_mut().rev().zip(block.chunks_exact(4)) {
                *dst = u32::from_be_bytes(src.try_into().unwrap());
            }
            words = encrypt_words(&self.keys, words);
            for (src, dst) in words.iter().rev().zip(block.chunks_exact_mut(4)) {
                dst.copy_from_slice(&src.to_be_bytes());
            }
        }
    }
}

#[inline(always)]
fn linear<W: Word>(mut w: [W; 4]) -> [W; 4] {
    w[0] = w[0].rol(13);
    w[2] = w[2].rol(3);
    w[1] ^= w[0] ^ w[2];
    w[3] = w[3] ^ w[2] ^ (w[0] << 3);
    w[1] = w[1].rol(1);
    w[3] = w[3].rol(7);
    w[0] ^= w[1] ^ w[3];
    w[2] = w[2] ^ w[3] ^ (w[1] << 7);
    w[0] = w[0].rol(5);
    w[2] = w[2].rol(22);
    w
}
#[inline(always)]
fn encrypt_words<W: Word>(keys: &[[u32; 4]; 33], mut w: [W; 4]) -> [W; 4] {
    macro_rules! rounds {
        ($($i:expr),*) => {$(
            for j in 0..4 { w[j] ^= W::splat(keys[$i][j]); }
            w = sbox($i % 8, w);
            if $i != 31 { w = linear(w); }
        )*};
    }
    rounds!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    );
    for j in 0..4 {
        w[j] ^= W::splat(keys[32][j]);
    }
    w
}
#[inline(always)]
fn sbox<W: Word>(index: usize, words: [W; 4]) -> [W; 4] {
    match index {
        0 => sbox_e0(words),
        1 => sbox_e1(words),
        2 => sbox_e2(words),
        3 => sbox_e3(words),
        4 => sbox_e4(words),
        5 => sbox_e5(words),
        6 => sbox_e6(words),
        7 => sbox_e7(words),
        _ => unreachable!(),
    }
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use std::arch::x86_64::*;
    #[derive(Clone, Copy)]
    struct V(__m256i);
    macro_rules! bit_op {
        ($trait:ident, $method:ident, $assign:ident, $assign_method:ident, $intrinsic:ident) => {
            impl $trait for V {
                type Output = Self;
                #[inline(always)]
                fn $method(self, rhs: Self) -> Self {
                    // SAFETY: V is private and is only constructed/used by the AVX2 entry point.
                    Self(unsafe { $intrinsic(self.0, rhs.0) })
                }
            }
            impl $assign for V {
                #[inline(always)]
                fn $assign_method(&mut self, rhs: Self) {
                    *self = self.$method(rhs);
                }
            }
        };
    }
    bit_op!(
        BitXor,
        bitxor,
        BitXorAssign,
        bitxor_assign,
        _mm256_xor_si256
    );
    bit_op!(
        BitAnd,
        bitand,
        BitAndAssign,
        bitand_assign,
        _mm256_and_si256
    );
    bit_op!(BitOr, bitor, BitOrAssign, bitor_assign, _mm256_or_si256);
    impl Not for V {
        type Output = Self;
        #[inline(always)]
        fn not(self) -> Self {
            self ^ Self::splat(u32::MAX)
        }
    }
    impl Shl<u32> for V {
        type Output = Self;
        #[inline(always)]
        fn shl(self, rhs: u32) -> Self {
            Self(unsafe { _mm256_sll_epi32(self.0, _mm_cvtsi32_si128(rhs as i32)) })
        }
    }
    impl Word for V {
        #[inline(always)]
        fn splat(value: u32) -> Self {
            Self(unsafe { _mm256_set1_epi32(value as i32) })
        }
        #[inline(always)]
        fn rol(self, bits: u32) -> Self {
            unsafe {
                Self(_mm256_or_si256(
                    _mm256_sll_epi32(self.0, _mm_cvtsi32_si128(bits as i32)),
                    _mm256_srl_epi32(self.0, _mm_cvtsi32_si128((32 - bits) as i32)),
                ))
            }
        }
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encrypt(keys: &[[u32; 4]; 33], bytes: &mut [u8]) {
        let reverse = _mm256_setr_epi8(
            15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7,
            6, 5, 4, 3, 2, 1, 0,
        );
        for group in bytes.chunks_exact_mut(128) {
            // Four unaligned loads, byte-order adaptation and an in-register
            // transpose. Each vector holds the same word of eight blocks.
            let p = group.as_mut_ptr();
            let a = _mm256_shuffle_epi8(_mm256_loadu_si256(p.cast()), reverse);
            let b = _mm256_shuffle_epi8(_mm256_loadu_si256(p.add(32).cast()), reverse);
            let c = _mm256_shuffle_epi8(_mm256_loadu_si256(p.add(64).cast()), reverse);
            let d = _mm256_shuffle_epi8(_mm256_loadu_si256(p.add(96).cast()), reverse);
            let ab0 = _mm256_unpacklo_epi32(a, b);
            let ab1 = _mm256_unpackhi_epi32(a, b);
            let cd0 = _mm256_unpacklo_epi32(c, d);
            let cd1 = _mm256_unpackhi_epi32(c, d);
            let w = encrypt_words(
                keys,
                [
                    V(_mm256_unpacklo_epi64(ab0, cd0)),
                    V(_mm256_unpackhi_epi64(ab0, cd0)),
                    V(_mm256_unpacklo_epi64(ab1, cd1)),
                    V(_mm256_unpackhi_epi64(ab1, cd1)),
                ],
            );
            let ab0 = _mm256_unpacklo_epi32(w[0].0, w[1].0);
            let cd0 = _mm256_unpackhi_epi32(w[0].0, w[1].0);
            let ab1 = _mm256_unpacklo_epi32(w[2].0, w[3].0);
            let cd1 = _mm256_unpackhi_epi32(w[2].0, w[3].0);
            for (i, v) in [
                _mm256_unpacklo_epi64(ab0, ab1),
                _mm256_unpackhi_epi64(ab0, ab1),
                _mm256_unpacklo_epi64(cd0, cd1),
                _mm256_unpackhi_epi64(cd0, cd1),
            ]
            .into_iter()
            .enumerate()
            {
                _mm256_storeu_si256(p.add(i * 32).cast(), _mm256_shuffle_epi8(v, reverse));
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[path = "serpent_neon.rs"]
mod neon;

#[cfg(test)]
mod tests {
    use super::*;
    use cipher5::{BlockCipherEncrypt, KeyInit};

    #[test]
    fn scalar_and_avx2_match_upstream_with_tails_and_unaligned_slices() {
        let mut seed = 0x7319a953u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..12 {
            let key: [u8; 32] = std::array::from_fn(|_| next());
            let cipher = Serpent::new(&key);
            let mut reversed = key;
            reversed.reverse();
            let reference = <::serpent::Serpent as KeyInit>::new_from_slice(&reversed).unwrap();
            for blocks in 0..=33 {
                let prefix = blocks % 32;
                let mut bytes: Vec<u8> = (0..prefix + blocks * 16 + 7).map(|_| next()).collect();
                let mut expected = bytes.clone();
                for block in expected[prefix..prefix + blocks * 16].chunks_exact_mut(16) {
                    let mut b = cipher5::Block::<::serpent::Serpent>::default();
                    b.copy_from_slice(block);
                    b.reverse();
                    reference.encrypt_block(&mut b);
                    b.reverse();
                    block.copy_from_slice(&b);
                }
                let mut scalar = bytes.clone();
                cipher.encrypt_scalar(&mut scalar[prefix..prefix + blocks * 16]);
                assert_eq!(scalar, expected);
                cipher.encrypt(&mut bytes[prefix..prefix + blocks * 16]);
                assert_eq!(bytes, expected);
                #[cfg(target_arch = "x86_64")]
                if blocks >= 8 && std::is_x86_feature_detected!("avx2") {
                    let count = blocks / 8 * 128;
                    // Force the SIMD entry independently of the runtime dispatcher.
                    let mut direct = scalar.clone();
                    for block in direct[prefix..prefix + count].chunks_exact_mut(16) {
                        let mut b = cipher5::Block::<::serpent::Serpent>::default();
                        b.copy_from_slice(block);
                        b.reverse();
                        use cipher5::BlockCipherDecrypt;
                        reference.decrypt_block(&mut b);
                        b.reverse();
                        block.copy_from_slice(&b);
                    }
                    unsafe { avx2::encrypt(&cipher.keys, &mut direct[prefix..prefix + count]) };
                    assert_eq!(direct, expected);
                }
            }
        }
    }
}
#[inline(always)]
fn sbox_e0<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    t0 ^= w3;
    w2 ^= w1;
    w1 |= w4;
    w1 ^= t0;
    t0 ^= w4;
    w4 ^= w3;
    w3 |= w2;
    w3 ^= t0;
    t0 = !t0;
    t0 |= w2;
    w2 ^= w4;
    w2 ^= t0;
    w4 |= w1;
    w2 ^= w4;
    t0 ^= w4;
    [w2, t0, w3, w1]
}

#[inline(always)]
fn sbox_e1<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    w1 = !w1;
    w3 = !w3;
    let mut t0 = w1;
    w1 &= w2;
    w3 ^= w1;
    w1 |= w4;
    w4 ^= w3;
    w2 ^= w1;
    w1 ^= t0;
    t0 |= w2;
    w2 ^= w4;
    w3 |= w1;
    w3 &= t0;
    w1 ^= w2;
    w2 &= w3;
    w2 ^= w1;
    w1 &= w3;
    t0 ^= w1;
    [w3, t0, w4, w2]
}

#[inline(always)]
fn sbox_e2<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    let mut t0 = w1;
    w1 &= w3;
    w1 ^= w4;
    w3 ^= w2;
    w3 ^= w1;
    w4 |= t0;
    w4 ^= w2;
    t0 ^= w3;
    w2 = w4;
    w4 |= t0;
    w4 ^= w1;
    w1 &= w2;
    t0 ^= w1;
    w2 ^= w4;
    w2 ^= t0;
    t0 = !t0;
    [w3, w4, w2, t0]
}

#[inline(always)]
fn sbox_e3<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    let mut t0 = w1;
    w1 |= w4;
    w4 ^= w2;
    w2 &= t0;
    t0 ^= w3;
    w3 ^= w4;
    w4 &= w1;
    t0 |= w2;
    w4 ^= t0;
    w1 ^= w2;
    t0 &= w1;
    w2 ^= w4;
    t0 ^= w3;
    w2 |= w1;
    w2 ^= w3;
    w1 ^= w4;
    w3 = w2;
    w2 |= w4;
    w1 ^= w2;
    [w1, w3, w4, t0]
}

#[inline(always)]
fn sbox_e4<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    w2 ^= w4;
    w4 = !w4;
    w3 ^= w4;
    w4 ^= w1;
    let mut t0 = w2;
    w2 &= w4;
    w2 ^= w3;
    t0 ^= w4;
    w1 ^= t0;
    w3 &= t0;
    w3 ^= w1;
    w1 &= w2;
    w4 ^= w1;
    t0 |= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    w3 &= w4;
    w1 = !w1;
    t0 ^= w3;
    [w2, t0, w1, w4]
}

#[inline(always)]
fn sbox_e5<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    w1 ^= w2;
    w2 ^= w4;
    w4 = !w4;
    let mut t0 = w2;
    w2 &= w1;
    w3 ^= w4;
    w2 ^= w3;
    w3 |= t0;
    t0 ^= w4;
    w4 &= w2;
    w4 ^= w1;
    t0 ^= w2;
    t0 ^= w3;
    w3 ^= w1;
    w1 &= w4;
    w3 = !w3;
    w1 ^= t0;
    t0 |= w4;
    t0 ^= w3;
    w3 = w1;
    w1 = w2;
    w2 = w4;
    w4 = t0;
    [w1, w2, w3, w4]
}

#[inline(always)]
fn sbox_e6<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    w3 = !w3;
    let mut t0 = w4;
    w4 &= w1;
    w1 ^= t0;
    w4 ^= w3;
    w3 |= t0;
    w2 ^= w4;
    w3 ^= w1;
    w1 |= w2;
    w3 ^= w2;
    t0 ^= w1;
    w1 |= w4;
    w1 ^= w3;
    t0 ^= w4;
    t0 ^= w1;
    w4 = !w4;
    w3 &= t0;
    w4 ^= w3;
    w3 = t0;
    [w1, w2, w3, w4]
}

#[inline(always)]
fn sbox_e7<W: Word>([mut w1, mut w2, mut w3, mut w4]: [W; 4]) -> [W; 4] {
    let mut t0 = w2;
    w2 |= w3;
    w2 ^= w4;
    t0 ^= w3;
    w3 ^= w2;
    w4 |= t0;
    w4 &= w1;
    t0 ^= w3;
    w4 ^= w2;
    w2 |= t0;
    w2 ^= w1;
    w1 |= t0;
    w1 ^= w3;
    w2 ^= t0;
    w3 ^= w2;
    w2 &= w1;
    w2 ^= t0;
    w3 = !w3;
    w3 |= w1;
    t0 ^= w3;
    [t0, w4, w2, w1]
}
