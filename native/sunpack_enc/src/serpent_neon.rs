//! ARM64 four-block Serpent; share the existing Boolean circuits/key schedule.
use super::*;
use std::arch::aarch64::*;
#[derive(Clone, Copy)]
struct V(uint32x4_t);
macro_rules! bit_op {
    ($trait:ident,$method:ident,$assign:ident,$assign_method:ident,$op:ident) => {
        impl $trait for V {
            type Output = Self;
            #[inline(always)]
            fn $method(self, rhs: Self) -> Self {
                Self(unsafe { $op(self.0, rhs.0) })
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
bit_op!(BitXor, bitxor, BitXorAssign, bitxor_assign, veorq_u32);
bit_op!(BitAnd, bitand, BitAndAssign, bitand_assign, vandq_u32);
bit_op!(BitOr, bitor, BitOrAssign, bitor_assign, vorrq_u32);
impl Not for V {
    type Output = Self;
    #[inline(always)]
    fn not(self) -> Self {
        Self(unsafe { vmvnq_u32(self.0) })
    }
}
impl Shl<u32> for V {
    type Output = Self;
    #[inline(always)]
    fn shl(self, bits: u32) -> Self {
        Self(unsafe { vshlq_u32(self.0, vdupq_n_s32(bits as i32)) })
    }
}
impl Word for V {
    #[inline(always)]
    fn splat(value: u32) -> Self {
        Self(unsafe { vdupq_n_u32(value) })
    }
    #[inline(always)]
    fn rol(self, bits: u32) -> Self {
        unsafe {
            Self(vorrq_u32(
                vshlq_u32(self.0, vdupq_n_s32(bits as i32)),
                vshlq_u32(self.0, vdupq_n_s32(bits as i32 - 32)),
            ))
        }
    }
}
#[inline]
#[target_feature(enable = "neon")]
unsafe fn reverse(value: uint32x4_t) -> uint32x4_t {
    vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(value)))
}
// ENC reverses both word and byte order relative to standard Serpent.
#[target_feature(enable = "neon")]
pub(super) unsafe fn encrypt(keys: &[[u32; 4]; 33], bytes: &mut [u8]) {
    for group in bytes.chunks_exact_mut(64) {
        let words = vld4q_u32(group.as_ptr().cast());
        let [a, b, c, d] = encrypt_words(
            keys,
            [
                V(reverse(words.3)),
                V(reverse(words.2)),
                V(reverse(words.1)),
                V(reverse(words.0)),
            ],
        );
        vst4q_u32(
            group.as_mut_ptr().cast(),
            uint32x4x4_t(reverse(d.0), reverse(c.0), reverse(b.0), reverse(a.0)),
        );
    }
}
