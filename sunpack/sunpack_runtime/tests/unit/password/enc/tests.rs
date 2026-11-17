use super::*;

#[test]
fn parallel_enc_candidates_preserve_first_match_and_reject_all_wrong() {
    // Real official ENC v4 fixture, 10 MiB / 10 passes. Sixteen executor
    // threads allow four candidate workspaces with four lanes each. The
    // duplicate correct passwords lie in different former static chunks.
    const DATA: &[u8] = include_bytes!("../../../../../sunpack_enc/tests/data/algorithm_0.mov");
    let context = EncPasswordContext {
        probe: PasswordProbe::parse(DATA, DATA.len() as u64).unwrap(),
    };
    let pool = rayon::ThreadPoolBuilder::new().num_threads(16).build().unwrap();
    pool.install(|| {
        let mut candidates: Vec<Arc<str>> = (0..12)
            .map(|index| Arc::from(format!("wrong-{index}")))
            .collect();
        candidates[4] = Arc::from("sunpack-test");
        candidates[9] = Arc::from("sunpack-test");
        let matched = context.verify(&candidates).unwrap();
        assert_eq!(matched.status, "match");
        assert_eq!(matched.matched_index, Some(4));
        assert_eq!(matched.attempts, 5);
        assert_eq!(matched.final_confirmation_required, Some(false));

        let rejected = context.verify(&candidates[..4]).unwrap();
        assert_eq!(rejected.status, "no_match");
        assert_eq!(rejected.matched_index, None);
        assert_eq!(rejected.attempts, 4);
    });
}
