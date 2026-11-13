use crate::io::atomic_file::rename_no_replace;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

pub(crate) type PromotionResult = (
    Vec<(String, String)>,
    Vec<String>,
    Vec<String>,
    String,
    bool,
);

pub(crate) struct NativeBlockedInputPromotion {
    moves: Vec<(PathBuf, PathBuf)>,
    destination: PathBuf,
}

impl NativeBlockedInputPromotion {
    pub(crate) fn new(paths: Vec<String>, destination: PathBuf) -> io::Result<Self> {
        let moves = plan_promotion_moves(paths, &destination)?;
        Ok(Self { moves, destination })
    }

    pub(crate) fn moves(&self) -> &[(PathBuf, PathBuf)] {
        &self.moves
    }

    pub(crate) fn execute(&self, before_move: impl FnOnce() -> io::Result<()>) -> PromotionResult {
        promote_input_files_with_move(
            &self.moves,
            &self.destination,
            before_move,
            move_input_no_replace,
        )
    }
}

fn plan_promotion_moves(
    paths: Vec<String>,
    destination: &Path,
) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    static NEXT_ALIAS: AtomicU64 = AtomicU64::new(0);
    let mut destinations = HashSet::new();
    let mut sources = HashSet::new();
    let mut moves = Vec::new();
    for raw in paths {
        let source = PathBuf::from(raw);
        if !sources.insert(crate::path_keys::path_key(&normalize_path(&source))) {
            continue;
        }
        let Some(name) = source.file_name() else {
            return Err(io::Error::other("input has no basename"));
        };
        if !source.metadata()?.is_file() {
            return Err(io::Error::other(format!(
                "not an input file: {}",
                source.display()
            )));
        }
        let mut target = destination.join(name);
        while target.try_exists()?
            || destinations.contains(&crate::path_keys::path_key(&normalize_path(&target)))
        {
            // Keep the first-dot bucket and every original numeric channel.
            // Alphabetic aliases introduce neither volume numbers nor format hints.
            let mut value = NEXT_ALIAS.fetch_add(1, Ordering::Relaxed);
            let mut suffix = String::from(".__sunpack_");
            loop {
                suffix.push((b'a' + (value & 15) as u8) as char);
                value >>= 4;
                if value == 0 {
                    break;
                }
            }
            let mut alias = name.to_os_string();
            alias.push(suffix);
            target = destination.join(alias);
        }
        destinations.insert(crate::path_keys::path_key(&normalize_path(&target)));
        moves.push((source, target));
    }
    Ok(moves)
}

fn promote_input_files_with_move(
    moves: &[(PathBuf, PathBuf)],
    destination: &Path,
    before_move: impl FnOnce() -> io::Result<()>,
    mut move_file: impl FnMut(&Path, &Path) -> io::Result<()>,
) -> PromotionResult {
    let mut residual = Vec::new();
    let mut removed = Vec::new();
    let mut parents = HashSet::new();
    // Recheck after acquiring publication leases, before the durable intent.
    for (source, target) in moves {
        match target.try_exists() {
            Ok(false) => {}
            Ok(true) => {
                return (
                    residual,
                    removed,
                    Vec::new(),
                    "promotion destination exists".into(),
                    true,
                )
            }
            Err(error) => return (residual, removed, Vec::new(), error.to_string(), false),
        }
        if let Some(parent) = source.parent() {
            parents.insert(parent.to_path_buf());
        }
    }
    if let Err(error) = before_move() {
        return (residual, removed, Vec::new(), error.to_string(), false);
    }
    for (index, (source, target)) in moves.iter().enumerate() {
        if let Err(error) = move_file(source, target) {
            let mut message = error.to_string();
            // Only this prefix moved. Build a residual map only on failed rollback;
            // successful execution reuses the already published move plan.
            for (old, new) in moves[..index].iter().rev() {
                if let Err(rollback) = move_file(new, old) {
                    residual.push((normalize_path(old), normalize_path(new)));
                    message.push_str(&format!("; rollback {}: {}", new.display(), rollback));
                }
            }
            let collision = is_name_collision(&error) && residual.is_empty();
            return (residual, removed, Vec::new(), message, collision);
        }
    }
    for parent in &parents {
        // remove_dir itself atomically checks emptiness; never walk upwards.
        if fs::remove_dir(parent).is_ok() {
            removed.push(normalize_path(parent));
        }
    }
    let mut touched: Vec<_> = parents.iter().map(|p| normalize_path(p)).collect();
    touched.push(normalize_path(destination));
    (residual, removed, touched, String::new(), false)
}

fn move_input_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    match rename_no_replace(source, destination) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(17) => {
            // A create-new handle prevents a concurrent arrival from being overwritten.
            let mut input = fs::File::open(source)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(destination)?;
            let copied = io::copy(&mut input, &mut output);
            drop(output);
            drop(input);
            if let Err(error) = copied.and_then(|_| fs::remove_file(source)) {
                let _ = fs::remove_file(destination);
                return Err(error);
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

use crate::filesystem::{watch_file_observation_known_kind, WatchFileObservation};

#[derive(Clone)]
pub(crate) struct WatchCandidateRow {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) mtime: f64,
    pub(crate) observation: WatchFileObservation,
}

pub(crate) fn flatten_single_branch_directories(
    base: &Path,
    work_path: Option<&Path>,
    before_move: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
    resume_leaf: Option<&Path>,
) -> FlattenStats {
    let mut stats = FlattenStats::default();
    flatten_single_branch_chain_with_publisher(
        base,
        &mut stats,
        work_path,
        rename_no_replace,
        before_move,
        resume_leaf,
    );
    stats
}

pub(crate) fn remove_owned_file(path: &Path) -> io::Result<()> {
    remove_with_readonly(path, |path| fs::remove_file(path))
}

fn remove_with_readonly(path: &Path, remove: impl Fn(&Path) -> io::Result<()>) -> io::Result<()> {
    match remove(path) {
        #[cfg(windows)]
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            use std::os::windows::fs::MetadataExt;
            let metadata = fs::symlink_metadata(path)?;
            let permissions = metadata.permissions();
            // Never change a reparse target's attributes. Only deletion-owned
            // regular entries may have their read-only bit cleared.
            if !permissions.readonly() || metadata.file_attributes() & 0x400 != 0 {
                return Err(error);
            }
            let mut writable = permissions.clone();
            writable.set_readonly(false);
            fs::set_permissions(path, writable)?;
            let result = remove(path);
            if result.is_err() {
                let _ = fs::set_permissions(path, permissions);
            }
            result
        }
        result => result,
    }
}

pub(crate) fn remove_owned_tree(path: &Path) -> io::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let metadata = fs::symlink_metadata(path)?;
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err(error);
                }
            }
            if !metadata.is_dir() {
                return Err(error);
            }
            // The normal path uses std's native tree removal. Walk only the
            // retained subtree after a read-only/permission failure, streaming
            // entries without following directory links.
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() && !kind.is_symlink() {
                    remove_owned_tree(&entry.path())?;
                } else {
                    remove_owned_file(&entry.path())?;
                }
            }
            remove_with_readonly(path, |path| fs::remove_dir(path))
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn watch_candidate_for_path(
    path: &Path,
    since_usn: Option<i64>,
) -> io::Result<Option<WatchCandidateRow>> {
    // An unobservable candidate ends this admission attempt, as in main.
    // USN and readiness failures remain separately classified below.
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(None),
    };
    if !metadata.is_file() {
        return Ok(None);
    }
    watch_candidate_from_metadata(path, &metadata, since_usn)
}

fn watch_candidate_from_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    since_usn: Option<i64>,
) -> io::Result<Option<WatchCandidateRow>> {
    if metadata.len() == 0 {
        return Ok(None);
    }
    let observation = watch_file_observation_known_kind(path, since_usn, false)?;
    Ok(Some(WatchCandidateRow {
        path: normalize_path(path),
        size: metadata.len(),
        mtime: mtime_seconds(metadata),
        observation,
    }))
}

#[derive(Default)]
pub(crate) struct FlattenStats {
    pub(crate) moved: usize,
    pub(crate) removed_dirs: usize,
    pub(crate) errors: Vec<String>,
    pub(crate) output_dir: Option<PathBuf>,
    pub(crate) source_dir: Option<PathBuf>,
}

#[cfg(test)]
fn flatten_single_branch_chain(root: &Path, stats: &mut FlattenStats) {
    flatten_single_branch_chain_with_publisher(
        root,
        stats,
        None,
        rename_no_replace,
        |_, _, _| Ok(()),
        None,
    );
}

fn flatten_single_branch_chain_with_publisher(
    root: &Path,
    stats: &mut FlattenStats,
    reserved_work: Option<&Path>,
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
    before_move: impl FnOnce(&Path, &Path, &Path) -> io::Result<()>,
    resume_leaf: Option<&Path>,
) {
    let leaf = match resume_leaf {
        Some(leaf) => Some(leaf.to_path_buf()),
        None => discover_flatten_leaf(root),
    };
    let Some(leaf) = leaf else {
        return;
    };
    let leaf_relative = match leaf.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => relative.to_path_buf(),
        _ => {
            stats.errors.push(format!(
                "{}: flatten leaf is not below output root",
                normalize_path(root)
            ));
            return;
        }
    };

    let work = if let Some(work) = reserved_work {
        let prepared = if resume_leaf.is_none() {
            before_move(root, work, &leaf)
        } else {
            Ok(())
        };
        if let Err(error) = prepared.and_then(|_| {
            if resume_leaf.is_some() {
                Ok(())
            } else {
                rename_no_replace(root, work)
            }
        }) {
            stats
                .errors
                .push(format!("{}: {error}", normalize_path(work)));
            return;
        }
        work.to_path_buf()
    } else {
        let Some(work) = rename_root_to_visible_work(root, stats) else {
            return;
        };
        work
    };
    stats.output_dir = Some(work.clone());
    stats.source_dir = Some(root.to_path_buf());
    let leaf_in_work = work.join(&leaf_relative);
    if let Err(error) = if resume_leaf.is_some() && root.is_dir() {
        Ok(())
    } else {
        publish(&leaf_in_work, root)
    } {
        stats.errors.push(format!(
            "{} -> {}: {}",
            normalize_path(&leaf_in_work),
            normalize_path(root),
            error
        ));
        // Do not merge, overwrite, or clean up on failure.  The complete payload
        // remains under the visible work directory for straightforward inspection.
        return;
    }
    stats.moved += 1;
    stats.output_dir = Some(root.to_path_buf());
    stats.source_dir = Some(leaf);

    match remove_empty_flatten_wrappers(&work, &leaf_relative) {
        Ok(removed) => stats.removed_dirs += removed,
        Err(error) => stats.errors.push(error),
    }
}

fn discover_flatten_leaf(root: &Path) -> Option<PathBuf> {
    let mut current = only_child_directory(root)?;
    while let Some(child) = only_child_directory(&current) {
        current = child;
    }
    Some(current)
}

fn only_child_directory(dir: &Path) -> Option<PathBuf> {
    let mut entries = fs::read_dir(dir).ok()?;
    let first = entries.next()?.ok()?;
    if entries.next().is_some() {
        return None;
    }
    first.metadata().ok()?.is_dir().then(|| first.path())
}

fn rename_root_to_visible_work(root: &Path, stats: &mut FlattenStats) -> Option<PathBuf> {
    let Some(parent) = root.parent() else {
        stats.errors.push(format!(
            "{}: output root has no parent for flatten work directory",
            normalize_path(root)
        ));
        return None;
    };
    let Some(root_name) = root.file_name() else {
        stats.errors.push(format!(
            "{}: output root has no directory name",
            normalize_path(root)
        ));
        return None;
    };

    let mut attempt = 1usize;
    loop {
        let mut work_name = root_name.to_os_string();
        work_name.push(".__sunpack_flatten_work__");
        if attempt > 1 {
            work_name.push(attempt.to_string());
        }
        let work = parent.join(work_name);
        match rename_no_replace(root, &work) {
            Ok(()) => return Some(work),
            Err(error) if is_name_collision(&error) => {
                attempt = attempt.saturating_add(1);
            }
            Err(error) => {
                stats.errors.push(format!(
                    "{} -> {}: {}",
                    normalize_path(root),
                    normalize_path(&work),
                    error
                ));
                return None;
            }
        }
    }
}

fn is_name_collision(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AlreadyExists || matches!(error.raw_os_error(), Some(80 | 183))
}

fn remove_empty_flatten_wrappers(work: &Path, leaf_relative: &Path) -> Result<usize, String> {
    let leaf = work.join(leaf_relative);
    let mut current = leaf.parent().map(Path::to_path_buf);
    let mut removed = 0usize;

    while let Some(directory) = current {
        if !directory.starts_with(work) {
            break;
        }
        match fs::remove_dir(&directory) {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("{}: {}", normalize_path(&directory), error));
            }
        }
        if directory == work {
            break;
        }
        current = directory.parent().map(Path::to_path_buf);
    }

    Ok(removed)
}

fn normalize_path(path: &Path) -> String {
    let text = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string();
    crate::path_keys::normalize_windows_extended_prefix(text)
}

fn mtime_seconds(metadata: &fs::Metadata) -> f64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unobservable_metadata_retires_candidate_without_retry() {
        // An invalid native path deterministically fails metadata even under
        // an elevated test account; it does not exercise the share-open path.
        let path = Path::new("invalid\0candidate.zip");
        assert!(fs::metadata(path).is_err());
        assert!(watch_candidate_for_path(path, None).unwrap().is_none());
    }

    #[test]
    fn promotion_rolls_back_preceding_members_on_move_failure() {
        let root = TestDirectory::new("promotion-rollback");
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let first = source.join("game.001");
        let second = source.join("game.002");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let moves = plan_promotion_moves(
            vec![normalize_path(&first), normalize_path(&second)],
            &destination,
        )
        .unwrap();
        // Both a permanent failure and a concurrent collision must roll back
        // earlier members. Only a fully restored collision may replan.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::AlreadyExists,
        ] {
            let result = promote_input_files_with_move(
                &moves,
                &destination,
                || Ok(()),
                |old, new| {
                    if old == second {
                        return Err(io::Error::new(kind, "injected"));
                    }
                    rename_no_replace(old, new)
                },
            );
            assert!(result.0.is_empty());
            assert!(result.3.contains("injected"));
            assert_eq!(result.4, kind == io::ErrorKind::AlreadyExists);
            assert!(first.is_file() && second.is_file());
            assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        }
    }

    #[test]
    fn promotion_reports_only_members_left_after_partial_rollback() {
        // Complete rollback never exercises residual path reporting. Four tiny
        // files cover restored, retained, failed and not-yet-attempted members.
        let root = TestDirectory::new("promotion-partial-rollback");
        let source = root.path().join("source");
        let destination = root.path().join("destination");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&destination).unwrap();
        let paths: Vec<_> = (1..=4)
            .map(|number| source.join(format!("inner.blob.{number:03}")))
            .collect();
        for path in &paths {
            fs::write(path, b"payload").unwrap();
        }
        let moves = plan_promotion_moves(
            paths.iter().map(|path| normalize_path(path)).collect(),
            &destination,
        )
        .unwrap();
        let mut attempted = Vec::new();
        let result = promote_input_files_with_move(
            &moves,
            &destination,
            || Ok(()),
            |old, new| {
                attempted.push(old.to_path_buf());
                if old == paths[2] {
                    return Err(io::Error::new(io::ErrorKind::AlreadyExists, "collision"));
                }
                if old == moves[1].1 {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "retained"));
                }
                rename_no_replace(old, new)
            },
        );
        assert_eq!(
            result.0,
            vec![(normalize_path(&paths[1]), normalize_path(&moves[1].1))]
        );
        assert!(result.3.contains("collision") && result.3.contains("retained"));
        assert!(
            !result.4,
            "partial rollback must not allow collision replanning"
        );
        assert_eq!(
            attempted,
            vec![
                paths[0].clone(),
                paths[1].clone(),
                paths[2].clone(),
                moves[1].1.clone(),
                moves[0].1.clone(),
            ]
        );
        assert!(paths[0].is_file() && paths[2].is_file() && paths[3].is_file());
        assert!(!paths[1].exists());
        assert_eq!(fs::read(&moves[1].1).unwrap(), b"payload");
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 1);
    }
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sunpack-postprocess-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test directory should be created");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn flatten_stops_at_first_branching_level() {
        let output = TestDirectory::new("branching");
        let build = output.path().join("Build");
        fs::create_dir_all(build.join("Plugins/x86_64")).unwrap();
        fs::create_dir_all(build.join("StreamingAssets/aa")).unwrap();
        fs::write(build.join("Clicker.exe"), b"exe").unwrap();
        fs::write(build.join("Plugins/x86_64/plugin.dll"), b"dll").unwrap();
        fs::write(build.join("StreamingAssets/aa/catalog.bin"), b"catalog").unwrap();

        let mut stats = FlattenStats::default();
        flatten_single_branch_chain(output.path(), &mut stats);

        assert!(!output.path().join("Build").exists());
        assert!(output.path().join("Clicker.exe").is_file());
        assert!(output.path().join("Plugins/x86_64/plugin.dll").is_file());
        assert!(output
            .path()
            .join("StreamingAssets/aa/catalog.bin")
            .is_file());
        assert_eq!(stats.removed_dirs, 1);
        assert_eq!(stats.output_dir.as_deref(), Some(output.path()));
        assert_eq!(stats.source_dir.as_ref(), Some(&build));
        assert!(stats.errors.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn flatten_keeps_last_proven_level_when_deeper_enumeration_fails() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE};

        let output = TestDirectory::new("locked_leaf");
        let leaf = output.path().join("wrapper");
        fs::create_dir(&leaf).unwrap();
        fs::write(leaf.join("payload"), b"payload").unwrap();
        // Permit the directory entry to be inspected, but deny a new listing
        // handle. The lock is released before publishing the discovered leaf.
        let locked = fs::OpenOptions::new().read(true)
            .share_mode(FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&leaf).unwrap();
        assert!(fs::read_dir(&leaf).is_err());

        let discovered = discover_flatten_leaf(output.path()).unwrap();
        drop(locked);

        assert_eq!(discovered, leaf);
    }

    #[test]
    fn flatten_continues_along_an_unbranched_directory_chain() {
        let output = TestDirectory::new("chain");
        let payload = output.path().join("outer/inner/payload.txt");
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::write(&payload, b"payload").unwrap();

        let mut stats = FlattenStats::default();
        flatten_single_branch_chain(output.path(), &mut stats);

        assert!(output.path().join("payload.txt").is_file());
        assert!(!output.path().join("outer").exists());
        assert!(!output.path().join("inner").exists());
        assert_eq!(stats.removed_dirs, 2);
        assert_eq!(stats.output_dir.as_deref(), Some(output.path()));
        assert_eq!(stats.source_dir.as_deref(), payload.parent());
        assert!(stats.errors.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn flatten_moves_directories_beyond_win32_max_path() {
        let container = TestDirectory::new("long_path");
        let output = container.path().join("x".repeat(130)).join("y".repeat(130));
        assert!(output.as_os_str().len() > 260);
        fs::create_dir_all(output.join("wrapper/first")).unwrap();
        fs::create_dir_all(output.join("wrapper/second")).unwrap();

        let mut stats = FlattenStats::default();
        flatten_single_branch_chain(&output, &mut stats);

        assert!(stats.errors.is_empty(), "{:?}", stats.errors);
        assert!(output.join("first").is_dir() && output.join("second").is_dir());
        assert!(!output.join("wrapper").exists());
    }

    #[test]
    fn flatten_publish_failure_reports_retained_payload_without_touching_collision() {
        let container = TestDirectory::new("publish_failure");
        let output = container.path().join("output");
        fs::create_dir_all(output.join("outer/inner")).unwrap();
        fs::write(output.join("outer/inner/payload.txt"), b"payload").unwrap();
        let mut stats = FlattenStats::default();
        flatten_single_branch_chain_with_publisher(
            &output,
            &mut stats,
            None,
            |leaf, root| {
                fs::create_dir(root)?;
                fs::write(root.join("unrelated.txt"), b"unrelated")?;
                rename_no_replace(leaf, root)
            },
            |_, _, _| Ok(()),
            None,
        );
        let retained = stats.output_dir.as_ref().unwrap();
        assert_ne!(retained, &output);
        assert_eq!(stats.source_dir.as_ref(), Some(&output));
        assert_eq!(
            fs::read(retained.join("outer/inner/payload.txt")).unwrap(),
            b"payload"
        );
        assert_eq!(
            fs::read(output.join("unrelated.txt")).unwrap(),
            b"unrelated"
        );
        assert_eq!(stats.moved, 0);
        assert_eq!(stats.removed_dirs, 0);
        assert_eq!(stats.errors.len(), 1);
    }
}
