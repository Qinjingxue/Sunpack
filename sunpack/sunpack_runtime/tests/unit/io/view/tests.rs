use super::*;

#[test]
fn view_policy_keeps_independent_rejections_boundaries_and_saved_depths() {
    let policy = ConfiguredViews::parse([Some("apate:+02"), Some("plain"), Some("apate:1")].into_iter()).unwrap();
    let previous = rmp_serde::to_vec(&(true, [1u32, 2])).unwrap();
    assert!(rmp_serde::from_slice::<ConfiguredViews>(&previous).unwrap() == policy);
    assert!(rmp_serde::from_slice::<ConfiguredViews>(&rmp_serde::to_vec(&policy).unwrap()).unwrap() == policy);

    // Evidence for a different method or a physical format must not suppress this one.
    let apate = ViewMethod::Apate.rejection();
    let unrelated = !apate;
    assert!(policy.probes().could_derive(Some(6), unrelated));
    assert!(!policy.probes().could_derive(Some(6), apate));
    assert!(!policy.probes().could_derive(Some(5), 0));

    let view = ReadView { method: ViewMethod::Apate, depth: 1, physical_size: 24, spans: Vec::new() };
    let mut bounds = MaskBoundaries::default();
    for end in [8, 5, 8] {
        bounds.record(Some(&view), end + 1);
        bounds.record(None, end);
    }
    assert_eq!(bounds.ends(None), &[5, 8]);
    assert_eq!(bounds.ends(Some(&view)), &[6, 9]);
}
