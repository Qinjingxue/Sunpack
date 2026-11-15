use super::*;
#[test]
fn portable_and_accelerated_groups_and_tails_match_compression() {
    let mut seed = 0x784fa92a55ca137bu64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed as u8
    };
    for _ in 0..16 {
        let key = std::array::from_fn::<_, 64, _>(|_| random());
        let cipher = Shacal::new(&key);
        for count in 0..34 {
            let mut expected: Vec<u8> = (0..count * 32 + 13).map(|_| random()).collect();
            let mut actual = expected.clone();
            let input = expected.clone();
            cipher.encrypt_portable(&mut expected[3..3 + count * 32]);
            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("sha")
                && std::arch::is_x86_feature_detected!("ssse3")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                let mut direct = input.clone();
                unsafe { x86::encrypt(&cipher.rounds, &mut direct[3..3 + count * 32]) };
                assert_eq!(direct, expected);
            }
            #[cfg(target_arch = "aarch64")]
            if std::arch::is_aarch64_feature_detected!("sha2") {
                let mut direct = input.clone();
                unsafe { arm::encrypt(&cipher.rounds, &mut direct[3..3 + count * 32]) };
                assert_eq!(direct, expected);
            }
            cipher.encrypt(&mut actual[3..3 + count * 32]);
            assert_eq!(actual, expected, "{count} unaligned blocks");
        }
    }
}
