use super::*;

#[test]
fn full_pad_refills_match_independent_single_block_counters() {
    for (code, key_len) in [
        (0, 32),
        (1, 32),
        (2, 32),
        (3, 32),
        (4, 32),
        (5, 32),
        (6, 56),
        (7, 128),
        (8, 64),
    ] {
        let key = vec![0x73; key_len];
        let (primitive, size) = Primitive::new(code, &key);
        for tail in [0xf8, 0xff] {
            let mut nonce = vec![0xff; size];
            nonce[size - 1] = tail;
            let mut counter = nonce.clone();
            let mut expected = Vec::new();
            for _ in 0..8197usize.div_ceil(size) {
                let mut block = counter.clone();
                primitive.encrypt(&mut block);
                expected.extend_from_slice(&block);
                for byte in counter.iter_mut().rev() {
                    let (value, carry) = byte.overflowing_add(1);
                    *byte = value;
                    if !carry {
                        break;
                    }
                }
            }
            expected.truncate(8197);
            for chunk in [32, 2047, 2048, 2049, 8197] {
                let mut state = Ctr::new(code, &key, &nonce);
                let mut actual = vec![0; expected.len()];
                for part in actual.chunks_mut(chunk) {
                    state.apply(part);
                }
                assert_eq!(actual, expected, "cipher {code}, chunk {chunk}");
            }
            let mut proof = Ctr::new(code, &key, &nonce);
            proof.apply(&mut [0; 32]);
            assert_eq!(proof.state.available, 32usize.div_ceil(size) * size);
        }
    }
}
