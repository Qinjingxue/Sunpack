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
