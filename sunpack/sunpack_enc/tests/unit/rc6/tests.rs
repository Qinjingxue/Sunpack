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
