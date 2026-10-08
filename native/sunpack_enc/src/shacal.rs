//! SHACAL-2. SHA-256 compression without feed-forward on the portable path;
//! SHA-NI/ARMv8 SHA2 run independent blocks with one expanded key schedule.
use super::backend;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct Shacal {
    key: [u8; 64],
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    rounds: [u32; 64],
    #[zeroize(skip)]
    encrypt: backend::Encrypt<Self>,
}
impl Shacal {
    pub(super) fn new(key: &[u8]) -> Self {
        let key: [u8; 64] = key.try_into().unwrap();
        Self {
            key,
            #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
            rounds: expand(&key),
            encrypt: backend::capabilities().sha(
                Self::encrypt_portable,
                #[cfg(target_arch = "x86_64")]
                Self::encrypt_shani,
                #[cfg(target_arch = "aarch64")]
                Self::encrypt_sha2,
            ),
        }
    }
    pub(super) fn encrypt(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len() % 32, 0);
        // SAFETY: immutable backend bound from process CPU/OS capabilities.
        unsafe { (self.encrypt)(self, bytes) };
    }
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_shani(&self, bytes: &mut [u8]) {
        unsafe { x86::encrypt(&self.rounds, bytes) };
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn encrypt_sha2(&self, bytes: &mut [u8]) {
        unsafe { arm::encrypt(&self.rounds, bytes) };
    }
    fn encrypt_portable(&self, bytes: &mut [u8]) {
        for block in bytes.chunks_exact_mut(32) {
            let mut state = [0u32; 8];
            for (dst, src) in state.iter_mut().zip(block.chunks_exact(4)) {
                *dst = u32::from_be_bytes(src.try_into().unwrap());
            }
            let initial = state;
            sha2::compress256(&mut state, &[self.key.into()]);
            for ((value, old), dst) in state.iter().zip(initial).zip(block.chunks_exact_mut(4)) {
                dst.copy_from_slice(&value.wrapping_sub(old).to_be_bytes());
            }
        }
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn expand(key: &[u8; 64]) -> [u32; 64] {
    // The standard SHA-256 round constants (FIPS 180-4).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut words = [0u32; 64];
    for (dst, src) in words.iter_mut().zip(key.chunks_exact(4)) {
        *dst = u32::from_be_bytes(src.try_into().unwrap());
    }
    for i in 16..64 {
        let a = words[i - 15];
        let b = words[i - 2];
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    for (word, k) in words.iter_mut().zip(K) {
        *word = word.wrapping_add(k);
    }
    words
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use std::arch::x86_64::*;

    #[target_feature(enable = "sha,ssse3,sse4.1")]
    pub(super) unsafe fn encrypt(keys: &[u32; 64], bytes: &mut [u8]) {
        let n = bytes.len() / 64 * 64;
        let (bulk, tail) = bytes.split_at_mut(n);
        for group in bulk.chunks_exact_mut(64) {
            batch::<2>(keys, group);
        }
        match tail.len() / 32 {
            1 => batch::<1>(keys, tail),
            _ => (),
        }
    }

    #[inline]
    #[target_feature(enable = "sha,ssse3,sse4.1")]
    unsafe fn batch<const N: usize>(keys: &[u32; 64], bytes: &mut [u8]) {
        let swap = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
        let mut states = [(_mm_setzero_si128(), _mm_setzero_si128()); N];
        for (i, (abef, cdgh)) in states.iter_mut().enumerate() {
            let p = bytes.as_ptr().add(i * 32).cast::<__m128i>();
            let abcd = _mm_shuffle_epi8(_mm_loadu_si128(p), swap);
            let efgh = _mm_shuffle_epi8(_mm_loadu_si128(p.add(1)), swap);
            let cdab = _mm_shuffle_epi32(abcd, 0xb1);
            let efgh = _mm_shuffle_epi32(efgh, 0x1b);
            *abef = _mm_alignr_epi8(cdab, efgh, 8);
            *cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);
        }
        for round in 0..16 {
            let wk = _mm_loadu_si128(keys.as_ptr().add(round * 4).cast());
            for (abef, cdgh) in &mut states {
                *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, wk);
            }
            let wk = _mm_shuffle_epi32(wk, 0x0e);
            for (abef, cdgh) in &mut states {
                *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, wk);
            }
        }
        // SHA instructions do the SHACAL rounds; omit SHA feed-forward.
        for (i, (abef, cdgh)) in states.into_iter().enumerate() {
            let feba = _mm_shuffle_epi32(abef, 0x1b);
            let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
            let abcd = _mm_blend_epi16(feba, dchg, 0xf0);
            let efgh = _mm_alignr_epi8(dchg, feba, 8);
            let p = bytes.as_mut_ptr().add(i * 32).cast::<__m128i>();
            _mm_storeu_si128(p, _mm_shuffle_epi8(abcd, swap));
            _mm_storeu_si128(p.add(1), _mm_shuffle_epi8(efgh, swap));
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    #[test]
    fn shani_groups_and_tails_match_independent_compression() {
        let mut seed = 0x784fa92a55ca137bu64;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        };
        for _ in 0..16 {
            let key = std::array::from_fn::<_, 64, _>(|_| random());
            let cipher = Shacal::new(&key);
            for count in 0..34 {
                let mut expected: Vec<u8> = (0..count * 32 + 13).map(|_| random()).collect();
                let mut actual = expected.clone();
                cipher.encrypt_portable(&mut expected[3..3 + count * 32]);
                cipher.encrypt(&mut actual[3..3 + count * 32]);
                assert_eq!(actual, expected, "{count} unaligned blocks");
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
mod arm {
    use std::arch::aarch64::*;
    #[target_feature(enable = "neon,sha2")]
    pub(super) unsafe fn encrypt(keys: &[u32; 64], bytes: &mut [u8]) {
        let n = bytes.len() / 128 * 128;
        let (bulk, tail) = bytes.split_at_mut(n);
        for group in bulk.chunks_exact_mut(128) {
            batch::<4>(keys, group);
        }
        match tail.len() / 32 {
            1 => batch::<1>(keys, tail),
            2 => batch::<2>(keys, tail),
            3 => batch::<3>(keys, tail),
            _ => (),
        }
    }
    #[inline]
    #[target_feature(enable = "neon,sha2")]
    unsafe fn batch<const N: usize>(keys: &[u32; 64], bytes: &mut [u8]) {
        let mut states = [(vdupq_n_u32(0), vdupq_n_u32(0)); N];
        for (i, state) in states.iter_mut().enumerate() {
            let p = bytes.as_ptr().add(i * 32);
            *state = (
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p))),
                vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(p.add(16)))),
            );
        }
        for round in 0..16 {
            let wk = vld1q_u32(keys.as_ptr().add(round * 4));
            for (ab, ef) in &mut states {
                let previous = *ab;
                *ab = vsha256hq_u32(previous, *ef, wk);
                *ef = vsha256h2q_u32(*ef, previous, wk);
            }
        }
        // SHACAL emits the rounds directly, without SHA's feed-forward.
        for (i, (ab, ef)) in states.into_iter().enumerate() {
            let p = bytes.as_mut_ptr().add(i * 32);
            vst1q_u8(p, vrev32q_u8(vreinterpretq_u8_u32(ab)));
            vst1q_u8(p.add(16), vrev32q_u8(vreinterpretq_u8_u32(ef)));
        }
    }
}
