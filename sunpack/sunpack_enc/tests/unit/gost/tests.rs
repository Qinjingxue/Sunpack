use super::*;
use ::cipher::{Block, BlockEncrypt, KeyInit};
#[test]
fn interleaved_groups_and_all_tails_match_upstream() {
    let mut seed = 0x3521_a917u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed as u8
    };
    for _ in 0..24 {
        let key: [u8; 32] = std::array::from_fn(|_| next());
        let cipher = Gost::new(&key);
        let mut adapted_key = key;
        for word in adapted_key.chunks_exact_mut(4) {
            word.reverse();
        }
        let reference = ::magma::Gost89Test::new_from_slice(&adapted_key).unwrap();
        for blocks in 0..=33 {
            let prefix = blocks % 32;
            let mut actual: Vec<u8> = (0..prefix + blocks * 8 + 7).map(|_| next()).collect();
            let mut expected = actual.clone();
            for block in expected[prefix..prefix + blocks * 8].chunks_exact_mut(8) {
                let mut b = Block::<::magma::Gost89Test>::default();
                b.copy_from_slice(block);
                b.reverse();
                reference.encrypt_block(&mut b);
                b.reverse();
                block.copy_from_slice(&b);
            }
            cipher.encrypt(&mut actual[prefix..prefix + blocks * 8]);
            assert_eq!(actual, expected);
        }
    }
}
