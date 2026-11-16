//! Run the production recursive output scan and report benchmark measurements.
use super::{scan_options, CandidateSet, OutputDiscovery, Request};
use crate::benchmark_process_memory::process_memory;
use crate::core::config;
use crate::pipeline::{passwords::AttemptCache, Mode};
use crate::scan::directory::scan_output_inventory_impl;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[test]
#[ignore = "run through benchmarks scan game-tree"]
fn scan() -> Result<(), Box<dyn std::error::Error>> {
    let roots: Vec<PathBuf> = serde_json::from_reader(BufReader::new(io::stdin().lock()))?;
    let config = config::load(&std::env::current_dir()?)?;
    let policy = config.recursive_authorization;
    if !policy.enabled {
        return Err("recursive authorization must be enabled for this benchmark".into());
    }
    let mut request = Request::with_config(roots, Mode::Extract, Arc::new(config));
    request.recursive = true;
    request.max_depth = 2;

    let before = process_memory()?;
    let start = Instant::now();
    let options = scan_options(&request.config)?;
    let candidates = CandidateSet::new(Arc::from([]), None, &AttemptCache::default(), None);
    let mut file_count = 0;
    let mut file_bytes = 0;
    let mut directory_errors = Vec::new();
    let mut outputs = Vec::new();
    for path in &request.inputs {
        let inventory = scan_output_inventory_impl(&path.to_string_lossy());
        file_count += inventory.file_count();
        file_bytes += inventory.total_size();
        let output = OutputDiscovery::prepare(inventory, &options)?;
        directory_errors.extend(output.scan_errors());
        if output.has_files() {
            outputs.push(output);
        }
    }
    let active_roots = outputs.len();
    let preparation = start.elapsed();
    let results = OutputDiscovery::discover_many(outputs, &candidates, &request)?;
    let elapsed = start.elapsed();
    let after = process_memory()?;

    let mut allowed_tasks = Vec::new();
    let mut discovery_errors = Vec::new();
    for scope in results {
        discovery_errors.extend(scope.errors.iter().map(|error| format!("{error:?}")));
        for task in &scope.tasks {
            let mut parts: Vec<_> = task.input_paths().collect();
            parts.sort_unstable();
            parts.dedup();
            allowed_tasks.push((
                task.entry().entry_path.clone(),
                parts.into_iter().map(str::to_owned).collect::<Vec<_>>(),
            ));
        }
    }
    allowed_tasks.sort_unstable();
    let report = serde_json::json!({
        "seconds": elapsed.as_secs_f64(),
        "prepare_seconds": preparation.as_secs_f64(),
        "discover_authorize_seconds": (elapsed - preparation).as_secs_f64(),
        "active_roots": active_roots,
        "file_count": file_count,
        "file_bytes": file_bytes,
        "before_working_set_bytes": before.working_set,
        "before_commit_bytes": before.commit,
        "peak_working_set_bytes": after.peak_working_set,
        "peak_commit_bytes": after.peak_commit,
        "allowed_tasks": allowed_tasks,
        "directory_errors": directory_errors,
        "discovery_errors": discovery_errors,
        "authorization": {
            "byte_ratio_exponent": policy.byte_ratio_exponent,
            "project_ratio_exponent": policy.project_ratio_exponent,
            "minimum_authorization_score": policy.minimum_authorization_score,
        },
    });
    println!("GAME_TREE_BENCH {report}");
    Ok(())
}
