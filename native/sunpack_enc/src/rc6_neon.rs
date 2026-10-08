//! ARM64 four-lane RC6; reuse the scalar/AVX2 round function and expanded key.
use super::*;
use std::arch::aarch64::*;
#[derive(Clone, Copy)]
struct V(uint32x4_t);
impl BitXor for V {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self(unsafe { veorq_u32(self.0, rhs.0) })
    }
}
impl Word for V {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        Self(unsafe { vdupq_n_u32(value) })
    }
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self(unsafe { vaddq_u32(self.0, rhs.0) })
    }
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        Self(unsafe { vmulq_u32(self.0, rhs.0) })
    }
    #[inline(always)]
    fn rol(self, bits: Self) -> Self {
        unsafe {
            let count = vreinterpretq_s32_u32(vandq_u32(bits.0, vdupq_n_u32(31)));
            Self(vorrq_u32(
                vshlq_u32(self.0, count),
                vshlq_u32(self.0, vsubq_s32(count, vdupq_n_s32(32))),
            ))
        }
    }
}
// V is private and used only under the detected NEON entry point.
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt(keys: &[u32; 44], bytes: &mut [u8]) {
    let n = bytes.len() / 128 * 128;
    let (bulk, tail) = bytes.split_at_mut(n);
    for group in bulk.chunks_exact_mut(128) {
        batch::<2>(keys, group);
    }
    if !tail.is_empty() {
        batch::<1>(keys, tail);
    }
}
#[inline]
#[target_feature(enable = "neon")]
unsafe fn batch<const N: usize>(keys: &[u32; 44], bytes: &mut [u8]) {
    let mut states = [[V(vdupq_n_u32(0)); 4]; N];
    for (index, state) in states.iter_mut().enumerate() {
        let words = vld4q_u32(bytes.as_ptr().add(index * 64).cast());
        *state = [V(words.0), V(words.1), V(words.2), V(words.3)];
    }
    for (index, [a, b, c, d]) in encrypt_words(keys, states).into_iter().enumerate() {
        vst4q_u32(
            bytes.as_mut_ptr().add(index * 64).cast(),
            uint32x4x4_t(a.0, b.0, c.0, d.0),
        );
    }
}
