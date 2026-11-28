//! Process-local output visibility. Recovery receipts live in the task journal;
//! these reservations end when the final directory inventory is published.
use super::{watch_path_key, NativeWatchState};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub(crate) type ReservationMap = BTreeMap<Arc<str>, Arc<OutputReservation>>;
pub(crate) type OutputReservations = Arc<Mutex<ReservationMap>>;

#[derive(Debug)]
pub(crate) struct OutputReservation {
    aliases: Box<[OutputAlias]>,
    identities: Vec<String>,
}

#[derive(Debug)]
struct OutputAlias {
    key: Arc<str>,
    spelling: Option<Box<str>>,
}

impl OutputReservation {
    pub(crate) fn path(&self, key: &str) -> &str {
        let alias = self.aliases.iter().find(|alias| alias.key.as_ref() == key)
            .expect("registered output alias");
        alias.spelling.as_deref().unwrap_or(&alias.key)
    }
}

pub(crate) fn covers_path(state: &OutputReservations, path: &str) -> bool {
    let key = watch_path_key(path);
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let owned = crate::path_keys::path_ancestors(&key).any(|key| data.contains_key(key));
    owned
}

pub(crate) fn owned_roots(state: &Mutex<ReservationMap>, under: &str) -> Vec<String> {
    let key = watch_path_key(under);
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut paths: Vec<_> = crate::path_keys::path_ancestors(&key)
        .filter(|key| data.contains_key(*key)).map(str::to_owned).collect();
    let prefix = format!("{}\\", key.trim_end_matches('\\'));
    paths.extend(data.range::<str, _>((std::ops::Bound::Included(prefix.as_str()), std::ops::Bound::Unbounded))
        .take_while(|(key, _)| key.starts_with(&prefix)).map(|(key, _)| key.to_string()));
    paths
}

pub(crate) fn records(state: &Mutex<ReservationMap>, paths: &[String]) -> ReservationMap {
    let keys: Vec<_> = paths.iter().map(|path| watch_path_key(path)).collect();
    let data = state.lock().unwrap_or_else(|e| e.into_inner());
    let mut records = ReservationMap::new();
    for key in keys {
        if records.contains_key(key.as_str()) { continue; }
        if let Some(record) = data.get(key.as_str()) {
            for alias in &record.aliases {
                if data.get(&alias.key).is_some_and(|value| Arc::ptr_eq(value, record)) {
                    records.insert(Arc::clone(&alias.key), Arc::clone(record));
                }
            }
        }
    }
    records
}

pub(crate) fn release(state: &Mutex<ReservationMap>, records: &ReservationMap) {
    let mut data = state.lock().unwrap_or_else(|e| e.into_inner());
    for (key, record) in records {
        if data.get(key).is_some_and(|value| Arc::ptr_eq(value, record)) {
            data.remove(key);
        }
    }
}

pub(crate) fn register(outputs: &OutputReservations, paths: &[String], identities: &[&str]) {
    let aliases = paths.iter().map(|path| {
        let key = watch_path_key(path);
        let spelling = (*path != key).then(|| Box::from(path.as_str()));
        OutputAlias { key: Arc::from(key), spelling }
    }).collect();
    let record = Arc::new(OutputReservation { aliases,
        identities: identities.iter().map(|value| (*value).to_owned()).collect() });
    let mut data = outputs.lock().unwrap();
    for alias in &record.aliases { data.insert(Arc::clone(&alias.key), Arc::clone(&record)); }
}

impl NativeWatchState {
    #[cfg(test)]
    pub(crate) fn active_output_keys(&self) -> Vec<String> { self.outputs.lock().unwrap().keys().map(ToString::to_string).collect() }

    pub(crate) fn register_output_paths(&self, paths: &[String], identities: &[&str]) {
        register(&self.outputs, paths, identities);
    }

    pub(crate) fn remove_active_output<'a>(&self, paths: impl Iterator<Item = &'a str>, identity: &str) {
        let mut data = self.outputs.lock().unwrap();
        for path in paths {
            let key = watch_path_key(path);
            if data.get(key.as_str()).is_some_and(|record| record.identities.iter().any(|id| id == identity)) {
                data.remove(key.as_str());
            }
        }
    }

    pub(crate) fn owned_event_records<'a>(&self, paths: impl Iterator<Item = &'a Path>) -> ReservationMap {
        let data = self.outputs.lock().unwrap();
        let mut records = BTreeMap::new();
        if data.is_empty() { return records; }
        for path in paths {
            let key = watch_path_key(&path.to_string_lossy());
            for parent in crate::path_keys::path_ancestors(&key) {
                if let Some((key, record)) = data.get_key_value(parent) {
                    records.entry(Arc::clone(key)).or_insert_with(|| Arc::clone(record));
                }
            }
        }
        records
    }

    pub(crate) fn owned_event_filter(&self, boundary: &Path, records: ReservationMap) -> Option<OwnedEventFilter> {
        if records.is_empty() { return None; }
        let data = self.outputs.lock().unwrap();
        let owned: HashSet<_> = records.into_iter().filter_map(|(key, record)| {
            data.get(&key).is_some_and(|value| Arc::ptr_eq(value, &record)).then_some(key)
        }).collect();
        (!owned.is_empty()).then(|| OwnedEventFilter { boundary: watch_path_key(&boundary.to_string_lossy()), owned })
    }
}

pub(crate) struct OwnedEventFilter { boundary: String, owned: HashSet<Arc<str>> }
impl OwnedEventFilter {
    pub(crate) fn contains(&self, path: &Path) -> bool {
        let key = watch_path_key(&path.to_string_lossy());
        key != self.boundary && crate::path_keys::path_ancestors(&key).any(|path| self.owned.contains(path))
    }
}
