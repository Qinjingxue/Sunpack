use std::borrow::Borrow;
use std::collections::{BTreeSet, HashMap, VecDeque};
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

// Reverse-index keys usually belong to one entry. Allocate an ordered set
// only when the key is shared.
pub(crate) enum SmallOrderedSet<T> {
    One(T),
    Many(Box<BTreeSet<T>>),
}

impl<T: Ord + Clone> SmallOrderedSet<T> {
    pub(crate) fn insert(&mut self, value: T) {
        match self {
            Self::One(first) if *first != value => {
                *self = Self::Many(Box::new(BTreeSet::from([first.clone(), value])));
            }
            Self::One(_) => (),
            Self::Many(values) => {
                values.insert(value);
            }
        }
    }

    /// Returns true when the enclosing map entry can be removed.
    pub(crate) fn remove(&mut self, value: &T) -> bool {
        match self {
            Self::One(first) => first == value,
            Self::Many(values) => {
                values.remove(value);
                if values.len() == 1 {
                    *self = Self::One(values.pop_first().unwrap());
                }
                false
            }
        }
    }

    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &T> {
        let (one, many) = match self {
            Self::One(value) => (Some(value), None),
            Self::Many(values) => (None, Some(values.iter())),
        };
        one.into_iter().chain(many.into_iter().flatten())
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
    fn unlink(&mut self, index: usize) {
        let previous = self.slots[index].previous;
        let next = self.slots[index].next;
        if let Some(previous) = previous {
            self.slots[previous].next = next;
        } else {
            self.oldest = next;
        }
        if let Some(next) = next {
            self.slots[next].previous = previous;
        } else {
            self.newest = previous;
        }
    }

    fn touch(&mut self, index: usize) {
        if self.newest == Some(index) {
            return;
        }
        self.unlink(index);
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

    pub(crate) fn remove<Q: Eq + Hash + ?Sized>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
    {
        let index = self.entries.remove(key)?;
        self.unlink(index);
        let removed = self.slots.swap_remove(index);
        // Repair references to the last slot if swap_remove moved it.
        if let Some(moved) = self.slots.get(index) {
            let (previous, next) = (moved.previous, moved.next);
            *self.entries.get_mut::<K>(&moved.key).unwrap() = index;
            if let Some(previous) = previous {
                self.slots[previous].next = Some(index);
            } else {
                self.oldest = Some(index);
            }
            if let Some(next) = next {
                self.slots[next].previous = Some(index);
            } else {
                self.newest = Some(index);
            }
        }
        trim_map(&mut self.entries);
        if self.slots.is_empty() {
            self.slots = Vec::new();
        } else if self.slots.capacity() > 256.max(self.slots.len().saturating_mul(4)) {
            self.slots.shrink_to(self.slots.len().saturating_mul(2));
        }
        Some(removed.value)
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

    pub(crate) fn is_empty(&self) -> bool {
        self.slots.is_empty()
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
#[path = "../tests/unit/collections/tests.rs"]
mod tests;
