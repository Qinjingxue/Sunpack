mod analysis_native;
mod collections;
mod event_log;
mod failure_report;
mod fast_hash_core;
mod filesystem;
mod formats;
mod io;
mod output_names;
mod password;
mod path_keys;
mod postprocess;
mod relations;
mod scan;
mod wal;
mod watch_journal;
mod watch_store;

mod core;
mod pipeline;
pub mod runtime;

#[cfg(test)]
#[path = "../tests/unit/lib/test_support.rs"]
mod test_support;

#[cfg(all(test, windows))]
#[path = "../../../benchmarks/native/process_memory.rs"]
mod benchmark_process_memory;

#[cfg(all(test, windows))]
#[path = "../../../benchmarks/native/reader/probe.rs"]
mod benchmark_reader;
