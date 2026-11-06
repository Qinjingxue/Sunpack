use std::collections::{HashMap, VecDeque};

pub(crate) fn trim_map<K: Eq + std::hash::Hash, V>(map: &mut HashMap<K, V>) {
    if map.is_empty() {
        *map = HashMap::new();
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
