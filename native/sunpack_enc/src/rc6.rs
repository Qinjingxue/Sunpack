//! ENC RC6-32/20/32: eight-block AVX2 and scalar tails.
//! Key expansion/rounds adapted from RustCrypto rc6 0.1.0.
//! Copyright (c) 2017 Damian Czaja. MIT: licenses/rc6-license.txt.
#[cfg(target_arch = "x86_64")]
use super::backend;
use std::ops::BitXor;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Rc6 {
    keys: [u32; 44],
    #[cfg(target_arch = "x86_64")]
    #[zeroize(skip)]
    encrypt: backend::Encrypt<Self>,
}
trait Word: Copy + BitXor<Output = Self> {
    fn splat(value: u32) -> Self;
    fn add(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn rol(self, bits: Self) -> Self;
}
impl Word for u32 {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        value
    }
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        self.wrapping_add(rhs)
    }
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        self.wrapping_mul(rhs)
    }
    #[inline(always)]
    fn rol(self, bits: Self) -> Self {
        self.rotate_left(bits)
    }
}
impl Rc6 {
    pub(super) fn new(key: &[u8]) -> Self {
        assert_eq!(key.len(), 32);
        let mut words = Zeroizing::new([0u32; 8]);
        for (dst, src) in words.iter_mut().zip(key.chunks_exact(4)) {
            *dst = u32::from_le_bytes(src.try_into().unwrap());
        }
        let mut keys = std::array::from_fn(|i| {
            0xb7e1_5163u32.wrapping_add((i as u32).wrapping_mul(0x9e37_79b9))
        });
        let (mut a, mut b) = (0u32, 0u32);
        for n in 0..132 {
            let i = n % 44;
            let j = n % 8;
            a = keys[i].wrapping_add(a).wrapping_add(b).rotate_left(3);
            keys[i] = a;
            b = words[j]
                .wrapping_add(a)
                .wrapping_add(b)
                .rotate_left(a.wrapping_add(b));
            words[j] = b;
        }
        Self {
            keys,
            #[cfg(target_arch = "x86_64")]
            encrypt: backend::capabilities().vector(Self::encrypt_scalar, Self::encrypt_avx2),
        }
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 16, 0);
        #[cfg(target_arch = "x86_64")]
        if bytes.len() >= 128 {
            // SAFETY: immutable backend bound from CPU/OS capabilities.
            unsafe { (self.encrypt)(self, bytes) };
            return;
        }
        #[cfg(target_arch = "aarch64")]
        if bytes.len() >= 64 {
            // SAFETY: Windows ARM64 guarantees NEON; four complete blocks.
            unsafe { self.encrypt_neon(bytes) };
            return;
        }
        // Short proofs need neither padded SIMD lanes nor an indirect call.
        self.encrypt_scalar(bytes);
    }
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_avx2(&self, bytes: &mut [u8]) {
        let n = bytes.len() / 128 * 128;
        let (bulk, tail) = bytes.split_at_mut(n);
        if n != 0 {
            // SAFETY: constructor bound AVX2; complete eight-block groups.
            unsafe { avx2::encrypt(&self.keys, bulk) };
        }
        self.encrypt_scalar(tail);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn encrypt_neon(&self, bytes: &mut [u8]) {
        let n = bytes.len() / 64 * 64;
        let (bulk, tail) = bytes.split_at_mut(n);
        if n != 0 {
            // SAFETY: Windows ARM64 baseline NEON; complete four-block groups.
            unsafe { neon::encrypt(&self.keys, bulk) };
        }
        self.encrypt_scalar(tail);
    }
    fn encrypt_scalar(&self, bytes: &mut [u8]) {
        for block in bytes.chunks_exact_mut(16) {
            let mut words = [0; 4];
            for (dst, src) in words.iter_mut().zip(block.chunks_exact(4)) {
                *dst = u32::from_le_bytes(src.try_into().unwrap());
            }
            for (dst, src) in block
                .chunks_exact_mut(4)
                .zip(encrypt_words(&self.keys, [words])[0])
            {
                dst.copy_from_slice(&src.to_le_bytes());
            }
        }
    }
}
#[inline(always)]
fn encrypt_words<W: Word, const N: usize>(
    keys: &[u32; 44],
    mut states: [[W; 4]; N],
) -> [[W; 4]; N] {
    for state in &mut states {
        state[1] = state[1].add(W::splat(keys[0]));
        state[3] = state[3].add(W::splat(keys[1]));
    }
    for pair in keys[2..42].chunks_exact(2) {
        for state in &mut states {
            let [mut a, b, mut c, d] = *state;
            let t = b.mul(b.add(b).add(W::splat(1))).rol(W::splat(5));
            let u = d.mul(d.add(d).add(W::splat(1))).rol(W::splat(5));
            a = (a ^ t).rol(u).add(W::splat(pair[0]));
            c = (c ^ u).rol(t).add(W::splat(pair[1]));
            *state = [b, c, d, a];
        }
    }
    for state in &mut states {
        state[0] = state[0].add(W::splat(keys[42]));
        state[2] = state[2].add(W::splat(keys[43]));
    }
    states
}

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use std::arch::x86_64::*;
    #[derive(Clone, Copy)]
    struct V(__m256i);
    // V is private; constructed and used only inside the AVX2 entry point.
    impl BitXor for V {
        type Output = Self;
        #[inline(always)]
        fn bitxor(self, rhs: Self) -> Self {
            Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
        }
    }
    impl Word for V {
        #[inline(always)]
        fn splat(value: u32) -> Self {
            Self(unsafe { _mm256_set1_epi32(value as i32) })
        }
        #[inline(always)]
        fn add(self, rhs: Self) -> Self {
            Self(unsafe { _mm256_add_epi32(self.0, rhs.0) })
        }
        #[inline(always)]
        fn mul(self, rhs: Self) -> Self {
            Self(unsafe { _mm256_mullo_epi32(self.0, rhs.0) })
        }
        #[inline(always)]
        fn rol(self, bits: Self) -> Self {
            unsafe {
                let count = _mm256_and_si256(bits.0, _mm256_set1_epi32(31));
                Self(_mm256_or_si256(
                    _mm256_sllv_epi32(self.0, count),
                    _mm256_srlv_epi32(self.0, _mm256_sub_epi32(_mm256_set1_epi32(32), count)),
                ))
            }
        }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn transpose([a, b, c, d]: [__m256i; 4]) -> [__m256i; 4] {
        let ab0 = _mm256_unpacklo_epi32(a, b);
        let ab1 = _mm256_unpackhi_epi32(a, b);
        let cd0 = _mm256_unpacklo_epi32(c, d);
        let cd1 = _mm256_unpackhi_epi32(c, d);
        [
            _mm256_unpacklo_epi64(ab0, cd0),
            _mm256_unpackhi_epi64(ab0, cd0),
            _mm256_unpacklo_epi64(ab1, cd1),
            _mm256_unpackhi_epi64(ab1, cd1),
        ]
    }
    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn encrypt(keys: &[u32; 44], bytes: &mut [u8]) {
        let n = bytes.len() / 256 * 256;
        let (bulk, tail) = bytes.split_at_mut(n);
        for group in bulk.chunks_exact_mut(256) {
            encrypt_batch::<2>(keys, group);
        }
        if !tail.is_empty() {
            encrypt_batch::<1>(keys, tail);
        }
    }
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn encrypt_batch<const N: usize>(keys: &[u32; 44], bytes: &mut [u8]) {
        let mut states = [[V(_mm256_setzero_si256()); 4]; N];
        for (index, state) in states.iter_mut().enumerate() {
            let p = bytes.as_mut_ptr().add(index * 128);
            let columns = transpose(std::array::from_fn(|i| {
                _mm256_loadu_si256(p.add(i * 32).cast())
            }));
            // Independent 4x4 transposes in both 128-bit halves: even/odd blocks.
            *state = columns.map(V);
        }
        // Interleave two eight-block states to hide multiply/rotate latency.
        for (index, words) in encrypt_words(keys, states).into_iter().enumerate() {
            let p = bytes.as_mut_ptr().add(index * 128);
            for (i, row) in transpose(words.map(|v| v.0)).into_iter().enumerate() {
                _mm256_storeu_si256(p.add(i * 32).cast(), row);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[path = "rc6_neon.rs"]
mod neon;

#[cfg(test)]
mod tests {
    use super::*;
    use cipher5::{
        consts::{U20, U32},
        BlockCipherEncrypt,
    };
    #[test]
    fn scalar_and_accelerated_match_upstream_with_unaligned_groups_and_tails() {
        let mut seed = 0x591a_130du32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed as u8
        };
        for _ in 0..24 {
            let key: [u8; 32] = std::array::from_fn(|_| next());
            let cipher = Rc6::new(&key);
            let reference = ::rc6::RC6::<u32, U20, U32>::new(&key.into());
            for blocks in 0..=33 {
                let prefix = blocks * 3 % 32;
                let mut input: Vec<u8> = (0..prefix + blocks * 16 + 7).map(|_| next()).collect();
                let mut expected = input.clone();
                for block in expected[prefix..prefix + blocks * 16].chunks_exact_mut(16) {
                    let mut b = cipher5::Block::<::rc6::RC6<u32, U20, U32>>::default();
                    b.copy_from_slice(block);
                    reference.encrypt_block(&mut b);
                    block.copy_from_slice(&b);
                }
                let mut scalar = input.clone();
                cipher.encrypt_scalar(&mut scalar[prefix..prefix + blocks * 16]);
                assert_eq!(scalar, expected);
                #[cfg(target_arch = "x86_64")]
                if backend::capabilities().avx2 {
                    let mut direct = input.clone();
                    let bulk = blocks / 8 * 128;
                    unsafe { avx2::encrypt(&cipher.keys, &mut direct[prefix..prefix + bulk]) };
                    cipher.encrypt_scalar(&mut direct[prefix + bulk..prefix + blocks * 16]);
                    assert_eq!(direct, expected);
                }
                #[cfg(target_arch = "aarch64")]
                {
                    let mut direct = input.clone();
                    let bulk = blocks / 4 * 64;
                    // Target baseline permits forcing NEON independently of dispatch.
                    unsafe { neon::encrypt(&cipher.keys, &mut direct[prefix..prefix + bulk]) };
                    cipher.encrypt_scalar(&mut direct[prefix + bulk..prefix + blocks * 16]);
                    assert_eq!(direct, expected);
                }
                cipher.encrypt(&mut input[prefix..prefix + blocks * 16]);
                assert_eq!(input, expected);
            }
        }
    }
}
