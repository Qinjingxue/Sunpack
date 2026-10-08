//! ARM64 two-block Threefish-1024; share round permutation and expanded keys.
use super::*;
use std::arch::aarch64::*;
#[derive(Clone, Copy)]
struct V(uint64x2_t);
impl BitXor for V {
    type Output = Self;
    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self {
        Self(unsafe { veorq_u64(self.0, rhs.0) })
    }
}
impl Word for V {
    #[inline(always)]
    fn splat(value: u64) -> Self {
        Self(unsafe { vdupq_n_u64(value) })
    }
    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        Self(unsafe { vaddq_u64(self.0, rhs.0) })
    }
    #[inline(always)]
    fn rol(self, bits: u32) -> Self {
        unsafe {
            Self(vorrq_u64(
                vshlq_u64(self.0, vdupq_n_s64(bits as i64)),
                vshlq_u64(self.0, vdupq_n_s64(bits as i64 - 64)),
            ))
        }
    }
}
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt(keys: &[[u64; 16]; 21], bytes: &mut [u8]) {
    for group in bytes.chunks_exact_mut(256) {
        let p = group.as_mut_ptr();
        let mut words = [V(vdupq_n_u64(0)); 16];
        for i in 0..8 {
            let a = vld1q_u64(p.add(i * 16).cast());
            let b = vld1q_u64(p.add(128 + i * 16).cast());
            words[2 * i] = V(vzip1q_u64(a, b));
            words[2 * i + 1] = V(vzip2q_u64(a, b));
        }
        let words = encrypt_words(keys, words);
        for i in 0..8 {
            vst1q_u64(
                p.add(i * 16).cast(),
                vzip1q_u64(words[2 * i].0, words[2 * i + 1].0),
            );
            vst1q_u64(
                p.add(128 + i * 16).cast(),
                vzip2q_u64(words[2 * i].0, words[2 * i + 1].0),
            );
        }
    }
}
