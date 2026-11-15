use super::*;
use cipher::{BlockEncrypt, KeyInit};
#[test]
fn interleaved_groups_and_tails_match_upstream() {
    let mut seed = 0x731d_936bu32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed as u8
    };
    for _ in 0..16 {
        let key: [u8; 32] = std::array::from_fn(|_| next());
        let cipher = Twofish::new(&key);
        let reference = ::twofish::Twofish::new_from_slice(&key).unwrap();
        for count in 0..=33 {
            let prefix = count * 3 % 32;
            let mut bytes: Vec<u8> = (0..prefix + count * 16 + 7).map(|_| next()).collect();
            let mut expected = bytes.clone();
            for block in expected[prefix..prefix + count * 16].chunks_exact_mut(16) {
                reference
                    .encrypt_block(cipher::Block::<::twofish::Twofish>::from_mut_slice(block));
            }
            cipher.encrypt(&mut bytes[prefix..prefix + count * 16]);
            assert_eq!(bytes, expected);
        }
    }
}
