use std::borrow::Borrow;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

pub(crate) fn trim_map<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.is_empty() {
        map.shrink_to_fit();
    } else if map.capacity() > 256.max(map.len().saturating_mul(4)) {
        map.shrink_to(map.len().saturating_mul(2));
    }
}

pub(crate) fn trim_deque<T>(queue: &mut VecDeque<T>) {
    if queue.is_empty() {
        *queue = VecDeque::new();
    } else if queue.capacity() > 256.max(queue.len().saturating_mul(4)) {
        queue.shrink_to(queue.len().saturating_mul(2));
    }
}

// Slots form an intrusive oldest-to-newest list. A hit changes only links,
// with no key clone, allocation, ordered-tree operation, or growing timestamp.
// Each cache has a fixed positive budget; eviction reuses the oldest slot.
pub(crate) struct CacheOrder<K, V> {
    entries: HashMap<K, usize>,
    slots: Vec<CacheEntry<K, V>>,
    oldest: Option<usize>,
    newest: Option<usize>,
}

struct CacheEntry<K, V> {
    key: K,
    value: V,
    previous: Option<usize>,
    next: Option<usize>,
}

impl<K, V> Default for CacheOrder<K, V> {
    fn default() -> Self {
        Self { entries: HashMap::new(), slots: Vec::new(), oldest: None, newest: None }
    }
}

impl<K: Eq + Hash + Clone, V> CacheOrder<K, V> {
    fn touch(&mut self, index: usize) {
        if self.newest == Some(index) {
            return;
        }
        let previous = self.slots[index].previous;
        let next = self.slots[index].next;
        if let Some(previous) = previous {
            self.slots[previous].next = next;
        } else {
            self.oldest = next;
        }
        if let Some(next) = next {
            self.slots[next].previous = previous;
        }
        if let Some(newest) = self.newest {
            self.slots[newest].next = Some(index);
        }
        self.slots[index].previous = self.newest;
        self.slots[index].next = None;
        self.newest = Some(index);
    }

    pub(crate) fn get(&mut self, key: &K) -> Option<&V> {
        self.get_mut(key).map(|value| &*value)
    }

    pub(crate) fn get_mut<Q: Eq + Hash + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        let index = *self.entries.get(key)?;
        self.touch(index);
        Some(&mut self.slots[index].value)
    }

    pub(crate) fn peek_mut<Q: Eq + Hash + ?Sized>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
    {
        let index = *self.entries.get(key)?;
        Some(&mut self.slots[index].value)
    }

    #[cfg(test)]
    pub(crate) fn peek<Q: Eq + Hash + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        let index = *self.entries.get(key)?;
        Some(&self.slots[index].value)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn insert(&mut self, key: K, value: V, limit: usize) -> Option<(K, V)> {
        if let Some(&index) = self.entries.get(&key) {
            self.slots[index].value = value;
            self.touch(index);
            return None;
        }
        let (index, evicted) = if self.slots.len() == limit {
            let index = self.oldest.unwrap();
            self.entries.remove(&self.slots[index].key);
            let old_key = std::mem::replace(&mut self.slots[index].key, key.clone());
            let old_value = std::mem::replace(&mut self.slots[index].value, value);
            self.touch(index);
            (index, Some((old_key, old_value)))
        } else {
            let index = self.slots.len();
            self.slots.push(CacheEntry { key: key.clone(), value,
                previous: self.newest, next: None });
            if let Some(newest) = self.newest {
                self.slots[newest].next = Some(index);
            } else {
                self.oldest = Some(index);
            }
            self.newest = Some(index);
            (index, None)
        };
        self.entries.insert(key, index);
        evicted
    }
}

#[cfg(test)]
mod tests {
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
                if step % 3 == 0 {
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
}
