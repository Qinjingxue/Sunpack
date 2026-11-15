use super::*;

#[test]
fn dedup_survives_spill_and_index_growth() {
    let mut map = SpillSet::default();
    let suffix = "x".repeat(20_000);
    for index in 0..600 {
        assert!(map.insert(&format!("{index}-{suffix}")).unwrap());
    }
    assert!(map.disk.is_some());
    for index in (0..600).rev() {
        assert!(!map.insert(&format!("{index}-{suffix}")).unwrap());
    }
    let disk = map.disk.as_mut().unwrap();
    assert!(
        !disk
            .find("different-full-key", DiskSet::hash(&format!("0-{suffix}")))
            .unwrap()
            .1
    );
    let mut collision = format!("0-{suffix}");
    collision.pop();
    collision.push('y');
    assert!(
        !disk
            .find(&collision, DiskSet::hash(&format!("0-{suffix}")))
            .unwrap()
            .1
    );
    assert!(map.insert("").unwrap());
    assert!(!map.insert("").unwrap());
}
