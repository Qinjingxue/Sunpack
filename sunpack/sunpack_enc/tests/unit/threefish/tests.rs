use super::*;
#[test]
fn scalar_and_accelerated_match_upstream_for_unaligned_groups_and_tails() {
    let mut seed = 0x92f1_038du32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed as u8
    };
    for _ in 0..12 {
        let key: [u8; 128] = std::array::from_fn(|_| next());
        let cipher = Threefish::new(&key);
        let reference = ::threefish::Threefish1024::new_with_tweak(&key, &[0; 16]);
        for blocks in 0..=17 {
            let prefix = blocks * 3 % 32;
            let mut input: Vec<u8> = (0..prefix + blocks * 128 + 7).map(|_| next()).collect();
            let mut expected = input.clone();
            for block in expected[prefix..prefix + blocks * 128].chunks_exact_mut(128) {
                let mut words = [0u64; 16];
                for (w, b) in words.iter_mut().zip(block.chunks_exact(8)) {
                    *w = u64::from_le_bytes(b.try_into().unwrap());
                }
                reference.encrypt_block_u64(&mut words);
                for (b, w) in block.chunks_exact_mut(8).zip(words) {
                    b.copy_from_slice(&w.to_le_bytes());
                }
            }
            let mut scalar = input.clone();
            cipher.encrypt_scalar(&mut scalar[prefix..prefix + blocks * 128]);
            assert_eq!(scalar, expected);
            #[cfg(target_arch = "x86_64")]
            if backend::capabilities().avx2 {
                let mut direct = input.clone();
                let bulk = blocks / 4 * 512;
                unsafe { avx2::encrypt(&cipher.keys, &mut direct[prefix..prefix + bulk]) };
                cipher.encrypt_scalar(&mut direct[prefix + bulk..prefix + blocks * 128]);
                assert_eq!(direct, expected);
            }
            cipher.encrypt(&mut input[prefix..prefix + blocks * 128]);
            assert_eq!(input, expected);
        }
    }
}
