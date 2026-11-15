use super::*;
use cipher5::{BlockCipherEncrypt, KeyInit};

#[test]
fn scalar_and_accelerated_match_upstream_with_tails_and_unaligned_slices() {
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
            if blocks >= 8 && backend::capabilities().avx2 {
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
