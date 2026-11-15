use super::*;

#[test]
fn cache_order_reuses_slots_and_matches_lru_on_hits_and_replacements() {
    // Compare mixed middle/head/tail touches and overwritten values with a
    // simple ordered-list model; also catch leaked eviction slots.
    for limit in [1, 3, 17] {
        let mut cache = CacheOrder::default();
        let mut expected = VecDeque::new();
        for step in 0..512 {
            let key = (step * 7 + step / 3) % (limit * 2 + 1);
            let previous = expected.iter().position(|(old, _)| *old == key)
                .and_then(|index| expected.remove(index));
            if step % 11 == 0 {
                assert_eq!(cache.remove(&key), previous.map(|(_, value)| value));
            } else if step % 3 == 0 {
                assert_eq!(cache.get(&key).copied(), previous.map(|(_, value)| value));
                if let Some(previous) = previous {
                    expected.push_back(previous);
                }
            } else {
                cache.insert(key, step, limit);
                expected.push_back((key, step));
                if expected.len() > limit { expected.pop_front(); }
            }
            let mut actual = Vec::new();
            let mut position = cache.oldest;
            let mut previous = None;
            while let Some(index) = position {
                assert!(actual.len() < limit, "cyclic LRU links");
                let entry = &cache.slots[index];
                assert_eq!(entry.previous, previous);
                assert_eq!(cache.entries.get(&entry.key), Some(&index));
                actual.push((entry.key, entry.value));
                previous = position;
                position = entry.next;
            }
            assert_eq!(cache.newest, previous);
            assert_eq!(actual, expected.iter().copied().collect::<Vec<_>>());
            assert_eq!(cache.entries.len(), expected.len());
            assert_eq!(cache.slots.len(), expected.len());
        }
    }
}
