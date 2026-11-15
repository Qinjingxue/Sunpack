//! Process-local output visibility. Recovery receipts live in the task journal;
//! these reservations end when the final directory inventory is published.
use super::{path_key, NativeWatchState};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub(crate) type OutputReservations = Arc<Mutex<BTreeMap<String, Arc<OutputReservation>>>>;

#[derive(Debug)]
pub(crate) struct OutputReservation {
    pub aliases: Vec<String>,
    identities: Vec<String>,
}

pub(crate) fn find_owned_root(state: &Mutex<BTreeMap<String, Arc<OutputReservation>>>, path: &str) -> Option<String> {
    let key = path_key(path);
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let found = crate::path_keys::path_ancestors(&key)
        .find(|key| data.contains_key(*key)).map(str::to_owned);
    found
}

pub(crate) fn owned_roots(state: &Mutex<BTreeMap<String, Arc<OutputReservation>>>, under: &str) -> Vec<String> {
    let key = path_key(under);
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut paths: Vec<_> = crate::path_keys::path_ancestors(&key)
        .filter(|key| data.contains_key(*key)).map(str::to_owned).collect();
    let prefix = format!("{}\\", key.trim_end_matches('\\'));
    paths.extend(data.range(prefix.clone()..)
        .take_while(|(key, _)| key.starts_with(&prefix)).map(|(key, _)| key.clone()));
    paths
}

pub(crate) fn records(state: &Mutex<BTreeMap<String, Arc<OutputReservation>>>, paths: &[String]) -> BTreeMap<String, Arc<OutputReservation>> {
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut records = BTreeMap::new();
    for path in paths {
        let key = path_key(path);
        if let Some(record) = data.get(&key) {
            for alias in record.aliases.iter() {
                let key = path_key(alias);
                if data.get(&key).is_some_and(|value| Arc::ptr_eq(value, record)) {
                    records.insert(key, Arc::clone(record));
                }
            }
        }
    }
    records
}

pub(crate) fn release(state: &Mutex<BTreeMap<String, Arc<OutputReservation>>>, records: &BTreeMap<String, Arc<OutputReservation>>) {
    let mut data = state.lock().unwrap_or_else(|e| e.into_inner());
    for (key, record) in records {
        if data.get(key).is_some_and(|value| Arc::ptr_eq(value, record)) {
            data.remove(key);
        }
    }
}

pub(crate) fn register(outputs: &OutputReservations, paths: &[String], identities: &[&str]) {
    let record = Arc::new(OutputReservation { aliases: paths.to_vec(),
        identities: identities.iter().map(|value| (*value).to_owned()).collect() });
    let mut data = outputs.lock().unwrap();
    for path in paths { data.insert(path_key(path), Arc::clone(&record)); }
}

impl NativeWatchState {
    #[cfg(test)]
    pub(crate) fn active_output_keys(&self) -> Vec<String> { self.outputs.lock().unwrap().keys().cloned().collect() }

    pub(crate) fn register_output_paths(&self, paths: &[String], identities: &[&str]) {
        register(&self.outputs, paths, identities);
    }

    pub(crate) fn remove_active_output(&self, paths: &[String], identity: &str) {
        let mut data = self.outputs.lock().unwrap();
        for path in paths {
            let key = path_key(path);
            if data.get(&key).is_some_and(|record| record.identities.iter().any(|id| id == identity)) {
                data.remove(&key);
            }
        }
    }

    pub(crate) fn owned_event_records<'a>(&self, paths: impl Iterator<Item = &'a Path>) -> BTreeMap<String, Arc<OutputReservation>> {
        let data = self.outputs.lock().unwrap();
        let mut records = BTreeMap::new();
        for path in paths {
            let key = path_key(&path.to_string_lossy());
            for parent in crate::path_keys::path_ancestors(&key) {
                if let Some(record) = data.get(parent) {
                    records.insert(parent.to_owned(), Arc::clone(record));
                }
            }
        }
        records
    }

    pub(crate) fn owned_event_filter(&self, boundary: &Path, records: BTreeMap<String, Arc<OutputReservation>>) -> Option<OwnedEventFilter> {
        let data = self.outputs.lock().unwrap();
        let owned: HashSet<_> = records.into_iter().filter_map(|(key, record)| {
            data.get(&key).is_some_and(|value| Arc::ptr_eq(value, &record)).then_some(key)
        }).collect();
        (!owned.is_empty()).then(|| OwnedEventFilter { boundary: path_key(&boundary.to_string_lossy()), owned })
    }
}

pub(crate) struct OwnedEventFilter { boundary: String, owned: HashSet<String> }
impl OwnedEventFilter {
    pub(crate) fn contains(&self, path: &Path) -> bool {
        let key = path_key(&path.to_string_lossy());
        key != self.boundary && crate::path_keys::path_ancestors(&key).any(|path| self.owned.contains(path))
    }
}
