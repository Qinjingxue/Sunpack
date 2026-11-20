use super::{watch, windows, Session, Stream};
use super::failure::report as failures;
use crate::core::config::{self, CleanupMode, Config, ReadMode, Recursion};
use crate::core::i18n::Language;
use crate::core::{passwords, resources};
use crate::io::cancellation::is_cancellation;
use crate::pipeline::{
    ArchiveResult, Cancellation, Engine, Event, FailureKind, InputError,
    InputErrorKind, Mode, Observer, Outcome, Request, TaskId, TaskStatus,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

mod live;
mod json;
pub(super) mod reporting;

pub(super) struct Host {
    pub(super) scheduler: Arc<crate::pipeline::Scheduler>,
    engine: OnceLock<Arc<Engine>>,
    passwords: Arc<Mutex<Option<Arc<passwords::BuiltinStore>>>>,
    idle: Mutex<IdlePolicy>,
    pub(super) watch: Arc<watch::Watch>,
    sources: Mutex<VecDeque<Arc<SourceObservers>>>,
}

#[derive(Clone, Copy)]
pub(super) struct IdlePolicy {
    pub(super) exit: Option<Duration>,
    pub(super) caches: Option<Duration>,
}

struct SourceObservers {
    paths: Vec<PathBuf>,
    password_path: PathBuf,
    observers: Vec<watch::ConfigSubscription>,
    changed: Arc<AtomicU64>,
    checked: AtomicU64,
}

impl SourceObservers {
    fn alive(&self) -> bool {
        !self.observers.is_empty() && self.observers.iter().all(watch::ConfigSubscription::alive)
    }

    fn current(&self) -> bool {
        if !self.alive() {
            return false;
        }
        let generation = self.changed.load(Ordering::Acquire);
        if generation > self.checked.load(Ordering::Acquire) {
            if !watch::observes_files(&self.paths, &self.password_path, &self.observers) {
                return false;
            }
            self.checked.fetch_max(generation, Ordering::Release);
        }
        true
    }
}

impl Host {
    pub(super) fn new() -> Self {
        Self::with_wake(|| {})
    }

    pub(super) fn with_wake(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            scheduler: crate::pipeline::Scheduler::new(),
            engine: OnceLock::new(),
            passwords: Arc::default(),
            idle: Mutex::new(IdlePolicy {
                exit: Some(Duration::from_secs_f64(config::default_idle_seconds())),
                caches: Some(Duration::from_secs_f64(config::default_cache_idle_seconds())),
            }),
            watch: Arc::new(watch::Watch::new(Arc::new(wake))),
            sources: Mutex::default(),
        }
    }

    pub(super) fn idle_policy(&self) -> IdlePolicy {
        *self.idle.lock().unwrap()
    }

    pub(super) fn configure_idle(&self, settings: &Config) {
        super::diagnostics::retention(settings.watch.event_log_retention_days);
        let mut idle = self.idle.lock().unwrap();
        if let Some(seconds) = settings.performance.persistent_server_idle_seconds {
            idle.exit = Duration::try_from_secs_f64(seconds).ok();
        }
        idle.caches = Duration::try_from_secs_f64(settings.watch.runtime_cache_cleanup_idle_seconds).ok();
    }

    pub(super) fn clear_idle_caches(&self) {
        if let Some(engine) = self.engine.get() {
            engine.clear_idle_caches();
        } else {
            self.scheduler.clear_idle_pool();
        }
    }

    fn engine(&self, cwd: &Path) -> io::Result<Arc<Engine>> {
        if let Some(engine) = self.engine.get() {
            return Ok(Arc::clone(engine));
        }
        let worker = resources::worker_path(cwd)?;
        Ok(Arc::clone(
            self.engine.get_or_init(|| Arc::new(Engine::with_scheduler(worker, Arc::clone(&self.scheduler)))),
        ))
    }

    fn password_snapshot(&self, cwd: &Path) -> io::Result<Arc<passwords::PasswordSnapshot>> {
        let store = passwords::BuiltinStore::shared(cwd)?;
        {
            let mut held = self.passwords.lock().unwrap();
            if held.as_ref().is_none_or(|previous| !Arc::ptr_eq(previous, &store)) {
                // A notification may have arrived before this source was held.
                store.invalidate();
                *held = Some(Arc::clone(&store));
            }
        }
        let source = self.sources.lock().unwrap().iter()
            .find(|source| source.password_path == store.path()).cloned();
        Ok(if source.as_ref().is_some_and(|source| source.current()) {
            store.observed_snapshot()
        } else {
            store.snapshot_for_request()
        })
    }

    fn generation(&self, cwd: &Path, config_sources: config::ConfigSources, inspect: bool) -> config::ConfigRead {
        let mode = if inspect { ReadMode::Inspect } else { ReadMode::CheckStamp };
        let Ok(data) = resources::writable_data_dir(cwd) else {
            return config::read_generation(cwd, config_sources, mode);
        };
        let paths = config::watch_paths(cwd, &config_sources);
        let password_path = data.join(passwords::FILENAME);
        let matches = |source: &Arc<SourceObservers>| source.paths == paths && source.password_path == password_path;
        let previous = {
            let mut sources = self.sources.lock().unwrap();
            sources.iter().position(&matches).and_then(|index| sources.remove(index)).inspect(|source| {
                sources.push_front(Arc::clone(source));
            })
        };
        if previous.as_ref().is_some_and(|source| source.current()) {
            // Keep the subscription alive through the read, even if another
            // request evicts or replaces the cache entry concurrently.
            return config::read_generation(cwd, config_sources, if inspect { mode } else { ReadMode::Observe });
        }
        let passwords = Arc::clone(&self.passwords);
        let changed = Arc::new(AtomicU64::new(0));
        let notified = Arc::clone(&changed);
        let notify_path = password_path.clone();
        let observers = watch::observe_files(&paths, &password_path, move |config, changed_passwords| {
            if config {
                config::invalidate_sources();
                notified.fetch_add(1, Ordering::Release);
            }
            if changed_passwords {
                if let Some(store) = passwords.lock().unwrap().as_ref().filter(|store| store.path() == notify_path) {
                    store.invalidate();
                }
            }
        });
        let Ok(observers) = observers else {
            return config::read_generation(cwd, config_sources, mode);
        };
        if let Some(store) = self.passwords.lock().unwrap().as_ref().filter(|store| store.path() == password_path) {
            store.invalidate();
        }
        // A cold or re-armed observer cannot account for edits before it
        // started. Read once through it before allowing notification-only hits.
        let read = config::read_generation(cwd, config_sources, mode);
        let source = Arc::new(SourceObservers {
            paths, password_path, observers, changed, checked: AtomicU64::new(0),
        });
        let retired = {
            let mut sources = self.sources.lock().unwrap();
            let current = sources.iter().position(|entry| entry.paths == source.paths && entry.password_path == source.password_path);
            if current.is_some_and(|index| previous.as_ref().is_none_or(|old| !Arc::ptr_eq(old, &sources[index]))) {
                None // Another reader already published a live group.
            } else {
                let retired = current.and_then(|index| sources.remove(index));
                let evicted = if sources.len() == config::CONFIG_CACHE_LIMIT { sources.pop_back() } else { None };
                sources.push_front(source);
                retired.or(evicted)
            }
        };
        // Dropping the last subscription joins the native observer, so let it
        // retire after releasing the registry lock.
        drop(retired);
        read
    }
}

#[derive(Default)]
struct Options {
    command: &'static str,
    action: String,
    paths: Vec<String>,
    json: bool,
    verbose: bool,
    help: bool,
    no_pause: bool,
    pause: bool,
    deep: bool,
    recursive: bool,
    flatten: Option<bool>,
    depth: Option<(Recursion, String)>,
    cleanup: Option<CleanupMode>,
    output: Option<String>,
    password_file: Option<String>,
    passwords: Vec<Arc<str>>,
    prompt_passwords: bool,
    no_tray: bool,
    rule_stdin: bool,
}

const COMMANDS: &[(&str, &str)] = &[
    ("extract", "e"),
    ("watch", "w"),
    ("scan", "s"),
    ("passwords", "pw"),
    ("config", "cfg"),
    ("daemon", "d"),
    ("doctor", "doc"),
    ("version", "ver"),
];

// One declaration drives option names, arity, parser scope and help.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OptionId {
    Help, Json, Verbose, NoPause, Pause, Recursive, Deep, Password, PasswordFile,
    AskPassword, Recur, Cleanup, Output, Flatten, NoFlatten,
    NoTray, RuleStdin,
}

#[derive(Clone, Copy)]
enum OptionScope {
    Any, Json, Common, ArchiveOrAdd, Passwords, Extract, ExtractOrAdd,
    DaemonStart, Validate,
}

impl OptionScope {
    fn accepts(self, command: &str, action: &str) -> bool {
        let archives = matches!(command, "extract" | "scan");
        let add = command == "watch" && action == "add";
        match self {
            Self::Any => true,
            Self::Json => !command.is_empty() && command != "version",
            Self::Common => archives || command == "watch" || (command == "daemon" && matches!(action, "start" | "startup")),
            Self::ArchiveOrAdd => archives || add,
            Self::Passwords => archives || command == "passwords",
            Self::Extract => command == "extract",
            Self::ExtractOrAdd => command == "extract" || add,
            Self::DaemonStart => command == "daemon" && action == "start",
            Self::Validate => command == "config" && action == "validate",
        }
    }
}

struct OptionSpec {
    id: OptionId,
    name: &'static str,
    metavar: &'static str,
    scope: OptionScope,
    help: &'static str,
    watch_help: &'static str,
    watch_order: usize,
}

impl OptionSpec {
    fn takes_value(&self) -> bool { !self.metavar.is_empty() }
}

const OPTION_SPECS: &[OptionSpec] = &[
    OptionSpec { id: OptionId::Help, name: "-h", metavar: "", scope: OptionScope::Any, help: "cli.help", watch_help: "cli.help", watch_order: 0 },
    OptionSpec { id: OptionId::Json, name: "-j", metavar: "", scope: OptionScope::Json, help: "cli.json", watch_help: "cli.json", watch_order: 1 },
    OptionSpec { id: OptionId::Verbose, name: "-v", metavar: "", scope: OptionScope::Common, help: "cli.verbose", watch_help: "cli.verbose", watch_order: 2 },
    OptionSpec { id: OptionId::NoPause, name: "-npa", metavar: "", scope: OptionScope::Common, help: "cli.no_pause", watch_help: "cli.no_pause", watch_order: 3 },
    OptionSpec { id: OptionId::Pause, name: "-pa", metavar: "", scope: OptionScope::Common, help: "cli.pause", watch_help: "cli.pause", watch_order: 4 },
    OptionSpec { id: OptionId::Recursive, name: "-R", metavar: "", scope: OptionScope::ArchiveOrAdd, help: "cli.recursive_scan", watch_help: "cli.recursive_scan", watch_order: 8 },
    OptionSpec { id: OptionId::Deep, name: "-d", metavar: "", scope: OptionScope::ArchiveOrAdd, help: "cli.deep_detect", watch_help: "cli.watch.deep_detect", watch_order: 9 },
    OptionSpec { id: OptionId::Password, name: "-p", metavar: "PASSWORD", scope: OptionScope::Passwords, help: "cli.password", watch_help: "cli.password", watch_order: 7 },
    OptionSpec { id: OptionId::PasswordFile, name: "-P", metavar: "PASSWORD_FILE", scope: OptionScope::Passwords, help: "cli.password_file", watch_help: "cli.password_file", watch_order: 8 },
    OptionSpec { id: OptionId::AskPassword, name: "-a", metavar: "", scope: OptionScope::Passwords, help: "cli.prompt_passwords", watch_help: "cli.prompt_passwords", watch_order: 9 },
    OptionSpec { id: OptionId::Recur, name: "-r", metavar: "RECURSIVE_EXTRACT", scope: OptionScope::Extract, help: "cli.recursive_extract", watch_help: "cli.recursive_extract", watch_order: 11 },
    OptionSpec { id: OptionId::Cleanup, name: "-c", metavar: "ARCHIVE_CLEANUP_MODE", scope: OptionScope::Extract, help: "cli.archive_cleanup_mode", watch_help: "cli.archive_cleanup_mode", watch_order: 12 },
    OptionSpec { id: OptionId::Output, name: "-o", metavar: "OUTPUT_DIR", scope: OptionScope::ExtractOrAdd, help: "cli.output_dir", watch_help: "cli.watch.output_dir", watch_order: 6 },
    OptionSpec { id: OptionId::Flatten, name: "-f", metavar: "", scope: OptionScope::Extract, help: "cli.flatten", watch_help: "cli.flatten", watch_order: 14 },
    OptionSpec { id: OptionId::NoFlatten, name: "-nf", metavar: "", scope: OptionScope::Extract, help: "cli.no_flatten", watch_help: "cli.no_flatten", watch_order: 15 },
    OptionSpec { id: OptionId::NoTray, name: "-nt", metavar: "", scope: OptionScope::DaemonStart, help: "cli.daemon.no_tray", watch_help: "cli.daemon.no_tray", watch_order: 18 },
    OptionSpec { id: OptionId::RuleStdin, name: "-srs", metavar: "", scope: OptionScope::Validate, help: "", watch_help: "", watch_order: 20 },
];

fn option_spec(flag: &str) -> Option<&'static OptionSpec> {
    OPTION_SPECS.iter().find(|spec| spec.name == flag)
}

fn short_option(letter: u8) -> Option<&'static OptionSpec> {
    // Passwords require standalone -p followed by a separate literal value.
    OPTION_SPECS.iter().find(|spec| {
        let bytes = spec.name.as_bytes();
        bytes.len() == 2 && bytes[0] == b'-' && bytes[1] == letter
            && spec.id != OptionId::Password
    })
}

impl Options {
    fn parse(argv: &[String]) -> io::Result<Self> {
        let mut args: VecDeque<_> = argv.iter().map(|arg| Cow::Borrowed(arg.as_str())).collect();
        let mut unrecognized = Vec::new();
        let command = loop {
            let Some(arg) = args.pop_front() else {
                if !unrecognized.is_empty() { return Err(parser_error("", "", "the following arguments are required: command")); }
                return Ok(Self { help: true, ..Self::default() });
            };
            if arg == "--" && args.is_empty() {
                return Err(parser_error("", "", "the following arguments are required: command"));
            }
            if arg == "--" || !looks_like_option(&arg) { break arg; }
            if arg.starts_with("-h") && !arg.starts_with("--") {
                validate_short_cluster(&arg, args.front().map(|arg| arg.as_ref()), "", "")?;
                return Ok(Self { help: true, ..Self::default() });
            }
            let (flag, inline) = arg.split_once('=').map_or((arg.as_ref(), None), |(f, v)| (f, Some(v)));
            if flag == "-h" {
                if let Some(value) = inline { return Err(explicit_argument("", "", flag, value)); }
                return Ok(Self { help: true, ..Self::default() });
            }
            unrecognized.push(arg.into_owned());
        };
        let command = COMMANDS
            .iter()
            .find(|(name, alias)| command.as_ref() == *name || command.as_ref() == *alias)
            .map(|(name, _)| *name)
            .ok_or_else(|| invalid_choice("", "", "command", &command, "extract, e, watch, w, scan, s, passwords, pw, config, cfg, daemon, d, doctor, doc, version, ver"))?;
        let mut options = Self {
            command,
            ..Self::default()
        };
        let mut positional = false;
        let mut supplied = false;
        let mut after_action = false;
        let mut paths_closed = false;
        let mut parent_flags = (false, false, false);
        let mut in_cluster = false;
        // argparse reports unknown arguments only after processing actions;
        // a later help action may exit successfully first.
        while let Some(mut arg) = args.pop_front() {
            let from_cluster = std::mem::take(&mut in_cluster);
            supplied = true;
            if arg == "--" && !positional {
                // Only a command with positional operands consumes the
                // separator. A subcommand selector instead sees it as a value.
                let action_missing = matches!(command, "watch" | "daemon" | "config") && options.action.is_empty();
                let has_operands = match (command, options.action.as_str()) {
                    ("extract" | "scan", _) | ("watch", "add" | "remove") => true,
                    ("daemon", "startup") => options.paths.is_empty() || args.is_empty(),
                    _ => false,
                };
                positional = true;
                if (has_operands && !paths_closed) || (action_missing && args.is_empty()) {
                    after_action |= !options.action.is_empty();
                    continue;
                }
            }
            if positional || !looks_like_option(&arg) {
                if matches!(command, "watch" | "daemon" | "config") && options.action.is_empty() {
                    // The action has its own common options. Explicit parent
                    // flags are restored after parsing the action.
                    options.json = false;
                    options.verbose = false;
                    options.pause = false;
                    options.no_pause = false;
                    positional = false;
                    let action = match (command, arg.as_ref()) {
                        ("watch", "ea") => "enable".into(),
                        ("watch", "da") => "disable".into(),
                        ("watch", "rl") => "reload".into(),
                        ("watch", "rlg") => "relog".into(),
                        ("watch", "rm") => "remove".into(),
                        ("watch", "ls") => "list".into(),
                        ("watch", "st") => "status".into(),
                        _ => arg.into_owned(),
                    };
                    if !matches!((command, action.as_str()),
                        ("watch", "add" | "remove" | "enable" | "disable" | "status" | "reload" | "list" | "relog")
                        | ("daemon", "start" | "stop" | "startup")
                        | ("config", "show" | "validate"))
                    {
                        return Err(invalid_choice(command, "", &format!("{command}_action"), &action, match command { "watch" => "enable, ea, disable, da, add, remove, rm, list, ls, reload, rl, relog, rlg, status, st", "daemon" => "start, stop, startup", _ => "show, validate" }));
                    }
                    options.action = action;
                } else {
                    if paths_closed {
                        unrecognized.push(arg.into_owned());
                        continue;
                    }
                    after_action = true;
                    if !matches!(command, "extract" | "scan")
                        && !matches!((command, options.action.as_str()), ("watch", "add" | "remove") | ("daemon", "startup"))
                    {
                        unrecognized.push(arg.into_owned());
                        continue;
                    }
                    if command == "daemon" && options.action == "startup" {
                        if options.paths.is_empty() && !matches!(arg.as_ref(), "enable" | "disable" | "status") {
                            return Err(invalid_choice(command, &options.action, "action", &arg, "enable, disable, status"));
                        }
                        if !options.paths.is_empty() {
                            unrecognized.push(arg.into_owned());
                            continue;
                        }
                    }
                    options.paths.push(arg.into_owned());
                }
                continue;
            }
            paths_closed |= !options.paths.is_empty();
            validate_short_cluster(&arg, args.front().map(|arg| arg.as_ref()), command, &options.action)?;
            if !from_cluster && matches!(command, "watch" | "daemon" | "config") && options.action.is_empty() {
                match arg.as_ref() {
                    "-j" => parent_flags.0 = true,
                    "-v" => parent_flags.1 = true,
                    "-pa" => parent_flags.2 = true,
                    _ => {}
                }
            }
            if !arg.starts_with("--") && arg.len() > 2 && arg.as_bytes()[1].is_ascii() {
                let short = short_option(arg.as_bytes()[1]).filter(|spec| spec.scope.accepts(command, &options.action));
                if short.is_some_and(OptionSpec::takes_value) {
                    if from_cluster || arg.as_bytes()[2] != b'=' {
                        arg.to_mut().insert(2, '=');
                    }
                } else if short.is_some() {
                    args.push_front(Cow::Owned(format!("-{}", &arg[2..])));
                    in_cluster = true;
                    arg = Cow::Owned(arg[..2].to_owned());
                }
            }
            after_action |= !options.action.is_empty();
            let (flag, inline) = arg
                .split_once('=')
                .map_or((arg.as_ref(), None), |(flag, value)| (flag, Some(value)));
            let mut take = || {
                inline
                    .map(str::to_owned)
                    .or_else(|| {
                        args.pop_front()
                            .filter(|value| flag == "-p" || !looks_like_option(value))
                            .map(Cow::into_owned)
                    })
                    .ok_or_else(|| argument_error(command, &options.action, flag, "expected one argument"))
            };
            let selected = option_spec(flag).filter(|spec| spec.scope.accepts(command, &options.action));
            if let (Some(spec), Some(value)) = (selected, inline) {
                if !spec.takes_value() || spec.id == OptionId::Password {
                    return Err(explicit_argument(command, &options.action, flag, value));
                }
            }
            match selected.map(|spec| spec.id) {
                Some(OptionId::Help) => {
                    options.help = true;
                    break;
                }
                Some(OptionId::Json) => options.json = true,
                Some(OptionId::Verbose) => options.verbose = true,
                Some(OptionId::Pause) => {
                    if options.no_pause { return Err(argument_error(command, &options.action, "-pa", "not allowed with argument -npa")); }
                    options.pause = true;
                }
                Some(OptionId::NoPause) => {
                    if options.pause { return Err(argument_error(command, &options.action, "-npa", "not allowed with argument -pa")); }
                    options.no_pause = true;
                }
                Some(OptionId::Recursive) => options.recursive = true,
                Some(OptionId::Deep) => options.deep = true,
                Some(OptionId::Flatten) => {
                    if options.flatten == Some(false) { return Err(argument_error(command, &options.action, "-f", "not allowed with argument -nf")); }
                    options.flatten = Some(true)
                }
                Some(OptionId::NoFlatten) => {
                    if options.flatten == Some(true) { return Err(argument_error(command, &options.action, "-nf", "not allowed with argument -f")); }
                    options.flatten = Some(false)
                }
                Some(OptionId::Recur) => {
                    let value = take()?.trim().to_owned();
                    let depth = Recursion::parse(&value).map_err(|error| argument_error(command, &options.action, flag, &error.to_string()))?;
                    options.depth = Some((depth, value));
                    continue;
                }
                Some(OptionId::Cleanup) => {
                    let value = take()?.trim().to_ascii_lowercase();
                    options.cleanup = Some(CleanupMode::parse(&value)
                        .map_err(|error| argument_error(command, &options.action, flag, &error.to_string()))?);
                    continue;
                }
                Some(OptionId::Output) => {
                    // Extract treats an empty destination as absent; watch must
                    // retain explicit presence for its single-root validation.
                    options.output = Some(take()?).filter(|value| command != "extract" || !value.is_empty());
                    continue;
                }
                Some(OptionId::Password) => {
                    options.passwords.push(take()?.into());
                    continue;
                }
                Some(OptionId::PasswordFile) => {
                    options.password_file = Some(take()?).filter(|value| !value.is_empty());
                    continue;
                }
                Some(OptionId::AskPassword) => options.prompt_passwords = true,
                Some(OptionId::NoTray) => options.no_tray = true,
                Some(OptionId::RuleStdin) => {
                    options.rule_stdin = true
                }
                _ => {
                    unrecognized.push(arg.into_owned());
                    continue;
                }
            }
        }
        let wants_paths = match (command, options.action.as_str()) {
            ("extract" | "scan", "") => true,
            ("watch", "add" | "remove") | ("daemon", "startup") => true,
            ("watch", "enable" | "disable" | "status" | "reload" | "list" | "relog" | "")
            | ("daemon", "start" | "stop" | "")
            | ("config", "show" | "validate" | "")
            | ("passwords" | "doctor" | "version", "") => false,
            _ => return Err(invalid(format!("invalid action: {}", options.action))),
        };
        if options.help {
            return Ok(options);
        }
        if wants_paths && options.paths.is_empty() {
            if !supplied || (matches!(command, "watch" | "daemon") && !after_action) {
                options.help = true;
            } else {
                return Err(parser_error(command, &options.action, if options.action == "startup" { "the following arguments are required: action" } else { "the following arguments are required: paths" }));
            }
        }
        if matches!(command, "watch" | "daemon" | "config") && options.action.is_empty() {
            if supplied {
                return Err(parser_error(command, "", format!("the following arguments are required: {command}_action")));
            }
            options.help = true;
        }
        // An empty required subparser invokes help before the parent reports
        // unknown arguments, just like _ContextArgumentParser in main.
        if options.help { return Ok(options); }
        if !unrecognized.is_empty() {
            return Err(parser_error("", "", format!("unrecognized arguments: {}", unrecognized.join(" "))));
        }
        options.json |= parent_flags.0;
        options.verbose |= parent_flags.1;
        options.pause |= parent_flags.2 && !options.no_pause;
        Ok(options)
    }
}

// argparse validates the arity of an entire short-option cluster before
// executing any of its actions, including help.
fn validate_short_cluster(arg: &str, next: Option<&str>, command: &str, action: &str) -> io::Result<()> {
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() <= 2 { return Ok(()); }
    for index in 1..arg.len() {
        let flag = arg.as_bytes()[index];
        let Some(spec) = short_option(flag).filter(|spec| spec.scope.accepts(command, action)) else {
            if index >= 2 {
                let previous = arg.as_bytes()[index - 1];
                return Err(explicit_argument(command, action, &format!("-{}", char::from(previous)), &arg[index..]));
            }
            break;
        };
        let takes_value = spec.takes_value();
        let tail = &arg[index + 1..]; // recognized option letters are ASCII
        if takes_value {
            if tail.is_empty() && next.is_none_or(looks_like_option) {
                return Err(argument_error(command, action, &format!("-{}", char::from(flag)), "expected one argument"));
            }
            break;
        }
        if tail.starts_with('=') || tail.starts_with('-') {
            let value = if index == 1 { tail.strip_prefix('=').unwrap_or(tail) } else { tail };
            return Err(explicit_argument(command, action, &format!("-{}", char::from(flag)), value));
        }
    }
    Ok(())
}

fn looks_like_option(arg: &str) -> bool {
    let Some(value) = arg.strip_prefix('-') else {
        return false;
    };
    // argparse's negative-number regex uses $, which also matches before one
    // final newline. Normalize only this lexical check, never the actual value.
    let value = value.strip_suffix('\n').filter(|value| !value.is_empty()).unwrap_or(value);
    // Numeric negative values can be passed as separate arguments, including passwords.
    !value.is_empty()
        && !arg.contains(' ')
        && !value.chars().all(|character| config::decimal_digit(character).is_some())
        && !value.split_once('.').is_some_and(|(integer, fraction)| {
            !fraction.is_empty()
                && integer
                    .chars()
                    .chain(fraction.chars())
                    .all(|character| config::decimal_digit(character).is_some())
        })
}

// main suppresses usage and lets argparse report canonical parser scope.
fn parser_error(command: &str, action: &str, message: impl std::fmt::Display) -> io::Error {
    let mut program = String::from("sunpack");
    if !command.is_empty() { program.push(' '); program.push_str(command); }
    if !action.is_empty() { program.push(' '); program.push_str(action); }
    invalid(format!("{program}: error: {message}"))
}

fn argument_error(command: &str, action: &str, flag: &str, message: &str) -> io::Error {
    parser_error(command, action, format!("argument {flag}: {message}"))
}

fn explicit_argument(command: &str, action: &str, flag: &str, value: &str) -> io::Error {
    argument_error(command, action, flag, &format!("ignored explicit argument {}", password_repr(value)))
}

fn invalid_choice(command: &str, action: &str, name: &str, value: &str, choices: &str) -> io::Error {
    argument_error(command, action, name, &format!("invalid choice: {} (choose from {choices})", password_repr(value)))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn line(session: &dyn Session, stream: Stream, text: &str) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(b'\n');
    session.write(stream, &bytes)
}

fn help(options: &Options, language: Language, session: &dyn Session) -> io::Result<()> {
    // Match main's registered argparse actions, including their order/metavars.
    // All current labels and descriptions fit its 120-column help layout.
    let mut positional = Vec::new();
    let mut specs: Vec<_> = OPTION_SPECS.iter()
        .filter(|spec| spec.scope.accepts(options.command, &options.action) && !spec.help.is_empty())
        .collect();
    if options.command == "watch" {
        specs.sort_by_key(|spec| spec.watch_order);
    }
    let optional: Vec<_> = specs.into_iter().map(|spec| {
        let label = if spec.takes_value() { format!("{} {}", spec.name, spec.metavar) } else { spec.name.to_owned() };
        let key = if options.command == "watch" { spec.watch_help } else { spec.help };
        (label, key.to_owned())
    }).collect();
    match options.command {
        "" => {
            for (command, alias) in COMMANDS {
                positional.push((format!("{command} ({alias})"), format!("cli.{command}.help")));
            }
        }
        "scan" | "extract" => positional.push(("paths".into(), format!("cli.{}.paths", options.command))),
        "watch" => match options.action.as_str() {
            "" => {
                for (action, label) in [
                    ("enable", "enable (ea)"), ("disable", "disable (da)"), ("add", "add"), ("remove", "remove (rm)"),
                    ("list", "list (ls)"), ("reload", "reload (rl)"), ("relog", "relog (rlg)"),
                    ("status", "status (st)"),
                ] {
                    positional.push((label.into(), format!("cli.watch.{}", action.replace('-', "_"))));
                }
            }
            "add" | "remove" => positional.push(("paths".into(), "cli.watch.paths".into())),
            _ => {}
        },
        "daemon" => match options.action.as_str() {
            "" => {
                for action in ["start", "stop", "startup"] {
                    positional.push((action.into(), format!("cli.daemon.{action}")));
                }
            }
            "startup" => positional.push(("action".into(), "cli.daemon.startup_action".into())),
            _ => {}
        },
        "config" if options.action.is_empty() => positional.extend([
            ("show".into(), "cli.config.show_help".into()),
            ("validate".into(), "cli.config.validate_help".into()),
        ]),
        _ => {}
    }
    let width = positional.iter().chain(&optional)
        .map(|(option, _)| option.chars().count()).max().unwrap_or(0) + 2;
    let mut help = String::new();
    use std::fmt::Write;
    for (heading, entries) in [("cli.positional_arguments", positional), ("cli.options", optional)] {
        if entries.is_empty() { continue; }
        if !help.is_empty() { help.push('\n'); }
        writeln!(help, "{}:", language.text(heading)).unwrap();
        for (option, description) in entries {
            writeln!(help, "  {option:<width$}{}", language.text(&description)).unwrap();
        }
    }
    session.write(Stream::Out, help.as_bytes())
}

struct CommandResult {
    command: &'static str,
    inputs: Value,
    summary: Value,
    errors: Vec<String>,
    items: Vec<Value>,
    password_sources: Option<Box<PasswordSources>>,
    scan_report: Option<Box<json::ScanReport>>,
    tasks: Vec<Value>,
    logs: Vec<String>,
}

impl CommandResult {
    fn new(command: &'static str) -> Self {
        Self {
            command,
            inputs: json!({}),
            summary: json!({}),
            errors: Vec::new(),
            items: Vec::new(),
            password_sources: None,
            scan_report: None,
            tasks: Vec::new(),
            logs: Vec::new(),
        }
    }

    fn emit_errors(&self, session: &dyn Session) -> io::Result<()> {
        for error in &self.errors {
            line(session, Stream::Err, error)?;
        }
        Ok(())
    }
}

struct SessionWriter<'a>(&'a dyn Session);
impl Write for SessionWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.write(Stream::Out, data)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_json(session: &dyn Session, value: &impl Serialize) -> io::Result<()> {
    let mut writer = BufWriter::with_capacity(16 * 1024, SessionWriter(session));
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub(super) fn run_console(
    host: &Host, cwd: &Path, args: Vec<String>, session: Arc<dyn Session>, cancel: Cancellation,
) -> io::Result<i32> {
    crate::pipeline::block_on(run(host, cwd, args, session, cancel))
}

fn trim_password_retry_recovery(paths: &[PathBuf], checkpoints: &mut Vec<crate::pipeline::InputCheckpoint>,
    generated: &mut Vec<crate::pipeline::GeneratedSource>) {
    let candidates: HashSet<_> = paths.iter().map(|path| path_key(path)).collect();
    // Preserve all logical siblings of the failed physical carrier and its
    // source receipts, not unrelated successful ancestors or descendants.
    let carriers: HashSet<_> = checkpoints.iter().filter(|checkpoint|
        candidates.contains(&path_key(checkpoint.carrier()))
        || checkpoint.source_paths().any(|path| candidates.contains(&path_key(path))))
        .map(|checkpoint| path_key(checkpoint.carrier())).collect();
    checkpoints.retain(|checkpoint| carriers.contains(&path_key(checkpoint.carrier())));
    let mut sources = candidates;
    sources.extend(checkpoints.iter().flat_map(|checkpoint| checkpoint.source_paths()).map(path_key));
    generated.retain(|source| sources.contains(&path_key(source.path())));
    // The prompt can remain open indefinitely: release discarded inline slots,
    // not only the layouts formerly owned by those slots.
    if checkpoints.capacity() > checkpoints.len().saturating_mul(4) { checkpoints.shrink_to_fit(); }
    if generated.capacity() > generated.len().saturating_mul(4) { generated.shrink_to_fit(); }
}

pub(super) async fn run(
    host: &Host,
    cwd: &Path,
    args: Vec<String>,
    owned_session: Arc<dyn Session>,
    cancel: Cancellation,
) -> io::Result<i32> {
    let session = owned_session.as_ref();
    if args.first().is_some_and(|arg| arg == "--cancel-watch-batch") {
        let [_, id] = args.as_slice() else { return Ok(2); };
        return Ok(i32::from(!host.watch.cancel_batch_async(id).await));
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(error) => {
            line(session, Stream::Err, &error.to_string())?;
            return Ok(2);
        }
    };
    crate::pipeline::stage("cli", &Cancellation::new()).await?;
    if options.help {
        let language = config::load_language(cwd);
        session.set_language(language);
        help(&options, language, session)?;
        return Ok(0);
    }
    if options.json && options.prompt_passwords {
        let language = config::load_language(cwd);
        let mut result = CommandResult::new(options.command);
        result.inputs = json!({"argv": args});
        result
            .errors
            .push(language.text("cli.json_password_prompt_unavailable").into());
        write_json(session, &result)?;
        return Ok(2);
    }
    // main's archive dispatch errors retain argv, but config/password handlers
    // catch their own failures and return an empty command-input envelope.
    let error_argv = (options.json && matches!(options.command, "scan" | "extract")).then_some(args);
    let inspection = options.command == "doctor" || (options.command == "config" && !options.rule_stdin);
    let generation = (!options.rule_stdin && options.command != "version")
        .then(|| host.generation(cwd, config::resolve_sources(cwd), inspection));
    let language = generation.as_ref().map_or_else(|| config::load_language(cwd), config::ConfigRead::language);
    session.set_language(language);
    let execution = match options.command {
        "scan" | "extract" => match generation.unwrap().normalized(true) {
            Ok(config) => {
                host.configure_idle(&config);
                archives(host, cwd, &options, Arc::clone(&owned_session), language, &cancel, config).await
            }
            Err(error) => Err(error),
        },
        "passwords" => match generation.unwrap().normalized(true) {
            Ok(config) => show_passwords(host, cwd, &options, session, language, config).await,
            Err(error) => Err(error),
        },
        "config" if options.rule_stdin => validate_scan_rule(session).await,
        "config" => show_config(generation.unwrap().into_inspection(), &options, session, language),
        "version" => show_version(session),
        "doctor" => doctor(cwd, generation.unwrap().into_inspection().map(|(path, _, settings)| (path, settings)),
            session, options.json, language),
        "watch" => watch_command(host, cwd, &options, session, language).await,
        "daemon" => daemon_command(host, cwd, &options, session, language).await,
        _ => unreachable!(),
    };
    crate::pipeline::stage("cli_output", &Cancellation::new()).await?;
    let (code, result) = match execution {
        Ok(value) => value,
        Err(error) if is_cancellation(&error) => {
            interrupted(&options, session, language, None, Vec::new())?
        }
        Err(error) => {
            let mut result = CommandResult::new(options.command);
            if let Some(argv) = error_argv {
                result.inputs = json!({"argv": argv});
            }
            let (code, message) = match options.command {
                "version" | "scan" | "extract" => (3, "cli.runtime_failure"),
                "watch" | "daemon" => (1, "cli.operation_failed"),
                _ => (2, "cli.operation_failed"),
            };
            result
                .errors
                .push(language.translate(message, &[("error", &error.to_string())]));
            (code, result)
        }
    };
    if options.json {
        write_json(session, &result)?;
    } else {
        result.emit_errors(session)?;
        for log in &result.logs {
            line(session, Stream::Out, log)?;
        }
        if options.pause
            && code != 130
            && (options.command != "extract" || code != 0)
        {
            session.pause_on_exit(language.text("cli.press_enter")).await?;
        }
    }
    Ok(code)
}

fn interrupted(
    options: &Options,
    session: &dyn Session,
    language: Language,
    inputs: Option<&[PathBuf]>,
    cleanup_errors: Vec<String>,
) -> io::Result<(i32, CommandResult)> {
    let clean = cleanup_errors.is_empty();
    line(session, Stream::Err, language.text("interrupt.finished"))?;
    let message = if clean {
        "interrupt.cleaned"
    } else {
        "interrupt.cleanup_failed"
    };
    line(session, Stream::Err, language.text(message))?;
    if options.json {
        for error in &cleanup_errors { line(session, Stream::Err, error)?; }
    }
    let mut result = CommandResult::new(options.command);
    if let Some(paths) = inputs {
        result.inputs = json!({"paths": paths});
    }
    result.summary = json!({"interrupted": true, "cleanup_complete": clean});
    result.errors = cleanup_errors;
    Ok((130, result))
}

pub(super) fn resolve(cwd: &Path, value: &str) -> io::Result<PathBuf> {
    std::path::absolute(request_path(cwd, value))
}

// Both execution and Watch receipts use the requesting client's drive/cwd.
// Only execution normalizes: main echoes the lexical join (including .\).
fn request_path<'a>(cwd: &Path, value: &'a str) -> Cow<'a, Path> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Cow::Borrowed(path);
    }
    let mut components = path.components();
    let mut base_components = cwd.components();
    let relative = match (components.next(), base_components.next()) {
        (Some(Component::Prefix(target)), Some(Component::Prefix(base)))
            if matches!((target.kind(), base.kind()),
                (Prefix::Disk(target), Prefix::Disk(base) | Prefix::VerbatimDisk(base))
                    if target.eq_ignore_ascii_case(&base)) =>
        {
            // ntpath.join keeps an explicitly supplied drive's spelling.
            if matches!(base.kind(), Prefix::Disk(_)) && target.as_os_str() != base.as_os_str() {
                let mut joined = PathBuf::from(target.as_os_str());
                joined.push(base_components.as_path());
                joined.push(components.as_path());
                return Cow::Owned(joined);
            }
            // A same-drive relative path uses the requesting client's directory.
            components.as_path()
        }
        _ => path,
    };
    Cow::Owned(cwd.join(relative))
}

fn watch_targets(cwd: &Path, options: &Options) -> Vec<PathBuf> {
    options.paths.iter().map(|value| request_path(cwd, value).into_owned()).collect()
}

fn targets(cwd: &Path, options: &Options) -> io::Result<Vec<PathBuf>> {
    options
        .paths
        .iter()
        .map(|path| resolve(cwd, path))
        .collect()
}

async fn prompt_passwords(session: &dyn Session, language: Language) -> io::Result<Vec<Arc<str>>> {
    session.awrite(Stream::Out, format!("{}\n", language.text("cli.password_prompt")).as_bytes()).await?;
    let mut passwords = Vec::new();
    while let Some(value) = session.aread_line(language.text("cli.password_input_prompt")).await? {
        let value = value.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            break;
        }
        passwords.push(Arc::from(value));
    }
    Ok(passwords)
}

async fn cli_passwords(
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<Vec<Arc<str>>> {
    crate::pipeline::stage("password_file", &Cancellation::new()).await?;
    let mut result = options.passwords.clone();
    if let Some(file) = &options.password_file {
        result = crate::password::lists::read_password_file(resolve(cwd, file)?, Some(result))?;
    }
    if options.prompt_passwords {
        result.extend(prompt_passwords(session, language).await?);
    }
    if options.password_file.is_none() || options.prompt_passwords {
        dedupe(&mut result);
    }
    Ok(result)
}

fn dedupe(values: &mut Vec<Arc<str>>) {
    let mut seen = HashSet::with_capacity(values.len());
    values.retain(|value| seen.insert(Arc::clone(value)));
}

fn cli_clipboard(settings: &Config) -> Vec<Arc<str>> {
    if settings.passwords.clipboard_passwords_enabled {
        passwords::clipboard_passwords()
            .into_iter()
            .map(Arc::from)
            .collect()
    } else {
        Vec::new()
    }
}

async fn confirm(session: &dyn Session, language: Language, prompt: &str) -> io::Result<bool> {
    confirm_on(session, language, prompt, Stream::Out).await
}

async fn confirm_on(session: &dyn Session, language: Language, prompt: &str, stream: Stream) -> io::Result<bool> {
    loop {
        session.awrite(stream, prompt.as_bytes()).await?;
        let Some(answer) = session.aread_line("").await? else { return Ok(false); };
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" | "" => return Ok(false),
            _ => session.awrite(stream, format!("{}\n", language.text("cli.answer_yes_no")).as_bytes()).await?,
        }
    }
}

pub(super) fn depth(value: Recursion) -> usize {
    match value {
        Recursion::Infinite | Recursion::Prompt => usize::MAX,
        Recursion::Fixed(rounds) => rounds.saturating_sub(1),
    }
}

// Preserve the position of the first receipt when a retry replaces it.
struct ReceiptOrder<K, V> {
    indices: HashMap<K, usize>,
    values: Vec<V>,
}

impl<K: Eq + std::hash::Hash, V> ReceiptOrder<K, V> {
    fn new() -> Self {
        Self { indices: HashMap::new(), values: Vec::new() }
    }

    fn insert(&mut self, key: K, value: V) {
        let index = *self.indices.entry(key).or_insert(self.values.len());
        if index == self.values.len() {
            self.values.push(value);
        } else {
            self.values[index] = value;
        }
    }

}

fn record_archive_failures(failed: &mut HashSet<String>, current: &[ArchiveResult]) {
    let unsuccessful = |archive: &ArchiveResult| !archive.partial && archive.failure.is_some();
    if !failed.is_empty() {
        for archive in current.iter().filter(|archive| !unsuccessful(archive)) {
            failed.remove(&path_key(&archive.path));
            if failed.is_empty() {
                break;
            }
        }
    }
    // A carrier can have both successful and failed segments in one round.
    // Clear old failures first so any current failure wins regardless of order.
    failed.extend(current.iter().filter(|archive| unsuccessful(archive)).map(|archive| path_key(&archive.path)));
    if failed.capacity() > 256.max(failed.len().saturating_mul(4)) {
        failed.shrink_to(failed.len().saturating_mul(2));
    }
}

fn path_key(path: &Path) -> String {
    crate::watch_store::watch_path_key(&path.to_string_lossy())
}

fn password_failure(archive: &ArchiveResult) -> bool {
    archive
        .failure
        .as_ref()
        .is_some_and(|failure| failure.is_password_retry())
}

fn password_retry_paths(archives: &[ArchiveResult]) -> Vec<PathBuf> {
    let mut retry = ReceiptOrder::new();
    for archive in archives {
        let Some(failure) = archive.failure.as_ref() else { continue; };
        let blocked = failures::recovery(failure).map_or_else(
            || failure.is_password_retry() && failure.kind != FailureKind::MissingVolume,
            crate::pipeline::InputRecovery::has_password_blocker,
        );
        if blocked {
            retry.insert(path_key(&archive.path), &archive.path);
        }
    }
    retry.values.into_iter().filter(|path| path.exists()).cloned().collect()
}

use super::failure::message as failure_message;

#[derive(Default)]
struct ArchiveSummary {
    success: usize,
    partial: usize,
    failed: usize,
    input_errors: usize,
    processed: usize,
    nested: usize,
    depth: usize,
    recovered: Vec<RecoveredOutput>,
    errors: Vec<String>,
}

#[derive(Serialize)]
struct RecoveredOutput {
    archive: PathBuf,
    out_dir: PathBuf,
    complete_files: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<Value>,
    #[serde(skip)]
    has_warning: bool,
}

impl ArchiveSummary {
    fn collect<'a>(
        archives: impl IntoIterator<Item = &'a ArchiveResult>,
        language: Language,
        json: bool,
    ) -> Self {
        let groups = failures::archive_groups(archives);
        Self::from_groups(&groups, language, json)
    }

    fn from_groups(groups: &[Vec<&ArchiveResult>], language: Language, json: bool) -> Self {
        let mut summary = Self {
            processed: groups.len(),
            ..Self::default()
        };
        for entries in groups {
            let depth = entries[0].depth;
            summary.depth = summary.depth.max(depth);
            summary.nested += usize::from(depth > 1);
            let failure = entries
                .iter()
                .find_map(|entry| (!entry.partial).then_some(entry.failure.as_ref()).flatten());
            if let Some(failure) = failure {
                let invalid = failure.kind == FailureKind::InvalidInput;
                summary.input_errors += usize::from(invalid);
                summary.failed += usize::from(!invalid);
                let message = failures::carrier_message(entries, language);
                let path = &entries[0].path;
                let task = if invalid || entries.iter().any(|entry| entry.depth > 1) {
                    path.as_os_str()
                } else { path.file_name().unwrap_or(path.as_os_str()) };
                let text = format!("{} [{message}]", task.to_string_lossy());
                summary.errors.push(if json {
                    text
                } else {
                    let key = if invalid {
                        "report.input_error"
                    } else {
                        "report.failed"
                    };
                    language.translate(key, &[("task", &text)])
                });
            } else if entries.iter().any(|entry| entry.partial) {
                summary.partial += 1;
                let output = if json {
                    crate::pipeline::common_ancestor(entries.iter().filter_map(|entry| entry.output.as_deref()))
                        .unwrap_or_default()
                } else { PathBuf::new() };
                let complete = entries
                    .iter()
                    .filter(|entry| entry.failure.is_none() || entry.partial)
                    .map(|entry| {
                        if entry.partial {
                            entry.recovered_complete_files
                        } else {
                            entry.files
                        }
                    })
                    .sum::<u64>();
                let (warning, has_warning) = if json {
                    let report = failures::recovery_warning(entries, language);
                    let value = report.map(|warning| serde_json::to_value(warning).expect("failure report is serializable"));
                    (value, false)
                } else {
                    (None, failures::has_recovery_warning(entries))
                };
                summary.recovered.push(RecoveredOutput {
                    archive: entries[0].path.clone(), out_dir: output,
                    complete_files: complete, warning, has_warning,
                });
            } else {
                summary.success += 1;
            }
        }
        summary
    }
}

fn input_error_message(error: &InputError, language: Language, json: bool) -> String {
    let text = if error.kind == InputErrorKind::InvalidInput {
        failures::invalid_input_message(error, language)
    } else if let Some(operation) = &error.scan_operation {
        language.translate(
            &format!("filesystem_scan.{operation}"),
            &[
                ("path", &error.path.to_string_lossy()),
                ("error", &error.message),
            ],
        )
    } else if error.path.as_os_str().is_empty() {
        error.message.clone()
    } else {
        format!("{}: {}", error.path.display(), error.message)
    };
    match (json, error.kind) {
        (false, InputErrorKind::FilesystemScan) => {
            language.translate("report.scan_error", &[("task", &text)])
        }
        (false, InputErrorKind::EmbeddedDiscovery) => {
            language.translate("report.failed", &[("task", &text)])
        }
        (false, InputErrorKind::InvalidInput) => {
            language.translate("report.input_error", &[("task", &text)])
        }
        _ => text,
    }
}

struct Progress {
    session: Arc<dyn Session>,
    watch: Arc<watch::Watch>,
    cancel: Cancellation,
    language: Language,
    display: Mutex<Display>,
    reporting: reporting::Reports,
    prompt: bool,
    visible: bool,
    verbose: bool,
}

// Preserve finally-style async teardown even when a worker future unwinds.
pub(super) async fn settle_unwind<T>(future: impl std::future::Future<Output = T>) -> std::thread::Result<T> {
    let mut future = Box::pin(future);
    std::future::poll_fn(|cx| {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(||
            std::future::Future::poll(future.as_mut(), cx))) {
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Ok(std::task::Poll::Ready(value)) => std::task::Poll::Ready(Ok(value)),
            Err(panic) => std::task::Poll::Ready(Err(panic)),
        }
    }).await
}

struct ReportClose<'a>(&'a reporting::Reports);
impl Drop for ReportClose<'_> {
    fn drop(&mut self) { self.0.close(); }
}

#[derive(Default)]
struct Display {
    panel: Option<live::Panel>,
    prompting: bool,
    deferred_scopes: Vec<(TaskId, bool)>,
    output_location: crate::pipeline::CommonAncestor,
}

impl Progress {
    fn clear_panel(&self) -> io::Result<()> {
        let mut display = self.display.lock().unwrap();
        if let Some(mut panel) = display.panel.take() {
            // The launcher can already have printed its interrupt message.
            // In that case the old cursor position no longer belongs to us.
            if !self.cancel.cancelled() {
                panel.clear(self.session.as_ref())?;
            }
        }
        Ok(())
    }

    fn flush_events(&self) {
        let mut display = self.display.lock().unwrap();
        self.apply_events(&mut display, true);
    }

    fn apply_events(&self, display: &mut Display, render: bool) {
        let events = self.reporting.take_events();
        if events.is_empty() { return; }
        display.panel.get_or_insert_with(|| live::Panel::new(self.verbose)).begin_batch();
        for event in events { self.display_event(event, display); }
        if let Some(panel) = &mut display.panel {
            panel.end_batch(self.session.as_ref(), self.language, render && !display.prompting);
        }
    }

    fn display_event(&self, event: Event, display: &mut Display) {
        if self.cancel.cancelled() {
            return;
        }
        // Keep one task-tree model for both final reports and live rendering.
        // Noninteractive sessions only update the model; no terminal frame is made.
        let interactive = self.session.interactive();
        if !interactive {
            if let Event::ResourceWait { id, path, state } = &event {
                if state.disk && !display.panel.as_ref().is_some_and(|panel| panel.disk_waiting(*id, state.disk_episode)) {
                    let (_, hint) = live::wait_status(
                        crate::pipeline::ResourceWait { memory: false, ..*state }, self.language,
                    );
                    let filename = path.file_name().unwrap_or(path.as_os_str()).to_string_lossy();
                    let _ = line(self.session.as_ref(), Stream::Err, &format!("{filename}: {hint}"));
                }
            }
        }
        let prompting = display.prompting || !interactive;
        display.panel.get_or_insert_with(|| live::Panel::new(self.verbose))
            .update(self.session.as_ref(), self.language, event, prompting);
    }

    fn finish_scope<'a>(&self, id: TaskId, archives: impl IntoIterator<Item = &'a ArchiveResult>) -> io::Result<()> {
        let mut display = self.display.lock().unwrap();
        if self.cancel.cancelled() {
            return Ok(());
        }
        // Do not render the completion events only to immediately clear them.
        self.apply_events(&mut display, false);
        let prompting = display.prompting;
        let Some(panel) = &mut display.panel else { return Ok(()); };
        let mut archives = archives.into_iter().peekable();
        if archives.peek().is_none() {
            panel.remove(id);
        } else {
            // A directory kept for manual recovery is still a failed input.
            // Only accepted root inputs authorize the summary output.
            let accepted = archives.take_while(|archive| archive.depth == 1)
                .any(|archive| archive.failure.is_none() || archive.partial);
            if prompting {
                display.deferred_scopes.push((id, accepted));
                return Ok(());
            }
            panel.clear(self.session.as_ref())?;
            self.write_scope(&mut display, id, accepted)?;
        }
        if !prompting {
            if let Some(panel) = &mut display.panel { panel.redraw(self.session.as_ref(), self.language, true); }
        }
        Ok(())
    }

    fn write_scope(&self, display: &mut Display, id: TaskId, accepted: bool) -> io::Result<()> {
        let Display { panel, output_location, .. } = display;
        let Some(panel) = panel else { return Ok(()); };
        let mut writer = BufWriter::new(SessionWriter(self.session.as_ref()));
        panel.write_scope(id, self.session.unicode(), self.language, &mut writer)?;
        writer.flush()?;
        if accepted {
            if let Some(output) = panel.take_scope_output(id) { output_location.include(&output); }
        }
        panel.remove(id);
        Ok(())
    }

    fn resume_panel(&self, display: &mut Display) {
        display.prompting = false;
        let deferred = std::mem::take(&mut display.deferred_scopes);
        for (id, accepted) in deferred {
            let _ = self.write_scope(display, id, accepted);
        }
        if let Some(panel) = display.panel.as_mut().filter(|_| !self.cancel.cancelled()) {
            panel.redraw(self.session.as_ref(), self.language, true);
        }
    }
}

impl Observer for Progress {
    fn worker_updates(&self) -> crate::pipeline::WorkerUpdates {
        use crate::pipeline::WorkerUpdates;
        if !self.visible {
            WorkerUpdates::None
        } else {
            WorkerUpdates::All
        }
    }

    fn notify(&self, event: Event) {
        if self.visible && !self.cancel.cancelled() {
            self.reporting.notify(event);
        }
    }

    async fn scope_finished<'a>(
        &self,
        id: TaskId,
        archives: impl Iterator<Item = &'a ArchiveResult> + Send,
    ) -> io::Result<()> {
        if self.visible {
            crate::pipeline::stage("report", &Cancellation::default()).await?;
            self.finish_scope(id, archives)?;
        }
        Ok(())
    }

    async fn allow_recursive_async(&self, depth: usize, pending: usize) -> bool {
        if !self.prompt {
            return true;
        }
        let prompt = self.language.translate(
            "recursion.prompt",
            &[
                ("count", &pending.to_string()),
                ("round", &depth.saturating_sub(1).to_string()),
            ],
        );
        if crate::pipeline::stage("report", &self.cancel).await.is_err() { return false; }
        {
            let mut display = self.display.lock().unwrap();
            if let Some(panel) = &mut display.panel {
                let _ = panel.clear(self.session.as_ref());
            }
            display.prompting = true;
        }
        let confirmed = confirm_on(self.session.as_ref(), self.language, &prompt,
            if self.visible { Stream::Out } else { Stream::Err }).await.unwrap_or(false);
        let _ = crate::pipeline::stage("report", &Cancellation::new()).await;
        self.resume_panel(&mut self.display.lock().unwrap());
        confirmed
    }

    fn register_output(&self, _archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        self.watch.register_external_output(output)
    }

    fn reuse_output(&self, _archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        self.watch.reuse_external_output(output)
    }

    fn before_flatten(&self, root: &Path, work: &Path, leaf: &Path, destination: &Path) -> io::Result<()> {
        self.watch.prepare_external_flatten(root, work, leaf, destination)
    }

    fn after_flatten(&self, id: TaskId, root: &Path, old: &Path, output: &Path) -> io::Result<()> {
        if old != root { self.watch.finish_external_flatten(root)?; }
        if self.visible {
            // Keep relocation in the same ordered stream as registration and
            // Finished, so buffered results cannot restore stale output paths.
            self.reporting.notify(Event::OutputsRelocated {
                id, root: root.to_owned(), old: old.to_owned(), new: output.to_owned(),
            });
        }
        Ok(())
    }

    fn outputs_finished(&self, paths: impl FnOnce() -> Vec<String>) -> io::Result<()> {
        self.watch.finish_external_outputs(&paths())
    }

    fn after_output(&self, archive: &ArchiveResult) -> io::Result<()> {
        if let Some(output) = &archive.output {
            self.watch.finish_external_flatten(output)?;
        }
        Ok(())
    }
}

fn tree_edge(unicode: bool, last: bool) -> (&'static str, &'static str) {
    match (unicode, last) {
        (true, true) => ("└─ ", "   "),
        (true, false) => ("├─ ", "│  "),
        (false, true) => ("\\---", "    "),
        (false, false) => ("+---", "|   "),
    }
}

fn single_line(value: &str) -> Cow<'_, str> {
    if value.contains(['\r', '\n']) { value.replace(['\r', '\n'], " ").into() }
    else { value.into() }
}

fn task_status_key(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Skipped => "report.status.skipped",
        TaskStatus::Complete => "report.status.complete",
        TaskStatus::Partial => "report.status.partial",
        TaskStatus::Failed => "report.status.error",
    }
}

fn task_detail<'a>(
    status: TaskStatus, failure: Option<&'a crate::pipeline::Failure>,
    segment: bool, verbose: bool, language: Language,
) -> Option<Cow<'a, str>> {
    let failure = failure?;
    let discovery = match failure.context.as_deref() {
        Some(crate::pipeline::FailureContext::Discovery { discovery, path, .. }) => Some((*discovery, path.as_path())),
        _ => None,
    };
    if status != TaskStatus::Failed && !verbose { return None; }
    if segment && discovery.is_none() && failure.kind != crate::pipeline::FailureKind::FilesystemError && failure.is_password_retry() {
        return None;
    }
    let detail = failure_message(failure, language);
    Some(match discovery {
        Some((crate::pipeline::DiscoverySource::Embedded, path)) => format!("{}: {detail}", path.display()).into(),
        _ => detail,
    })
}

fn command_error(
    command: &'static str,
    code: i32,
    key: &str,
    error: io::Error,
    language: Language,
) -> (i32, CommandResult) {
    let mut result = CommandResult::new(command);
    result.errors.push(language.translate(key, &[("error", &error.to_string())]));
    (code, result)
}

fn archive_request_error(
    error: io::Error,
    inputs: &[PathBuf],
    command: &'static str,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    if error.get_ref().is_some_and(|inner| inner.is::<crate::pipeline::StartupError>()) {
        return Ok(command_error(command, 1, "cli.persistent_request_failed", error, language));
    }
    let Some(conflict) = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<crate::pipeline::BusyConflict>())
    else {
        return Err(error);
    };
    let (status, key) = if conflict.origin == crate::pipeline::Origin::Watch {
        ("watch_busy", "cli.watch_busy")
    } else {
        ("busy", "cli.archive_busy")
    };
    let mut result = CommandResult::new(command);
    result.inputs = json!({"paths":inputs});
    result.summary = json!({"status":status,"conflicts":conflict.paths});
    result.errors.push(language.text(key).into());
    Ok((1, result))
}

async fn archives(
    host: &Host,
    cwd: &Path,
    options: &Options,
    owned_session: Arc<dyn Session>,
    language: Language,
    cancel: &Cancellation,
    mut settings: Config,
) -> io::Result<(i32, CommandResult)> {
    let session = owned_session.as_ref();
    let inputs = targets(cwd, options)?;
    let engine = match host.engine(cwd) {
        Ok(engine) => engine,
        Err(error) => return Ok(command_error(options.command, 1, "cli.persistent_request_failed", error, language)),
    };
    let reservation = match engine.reserve_foreground_async(&inputs, cancel).await {
        Ok(reservation) => Arc::new(reservation),
        Err(error) => return archive_request_error(error, &inputs, options.command, language),
    };
    let foreground = windows::Foreground::enter_async(&engine, &host.watch, settings.runtime.process_mode).await;
    let execution = async {
    if let Some((depth, _)) = &options.depth {
        settings.recursive_extract = *depth;
    }
    if let Some(cleanup) = options.cleanup {
        settings.post_extract.archive_cleanup_mode = cleanup;
    }
    if let Some(flatten) = options.flatten {
        settings.post_extract.flatten_single_directory = flatten;
    }
    let output = options
        .output
        .as_deref()
        .map(|value| resolve(cwd, value))
        .transpose()?;
    let scan = options.command == "scan";
    let mut candidate_paths = inputs.clone();
    let mut user = match cli_passwords(cwd, options, session, language).await {
        Ok(passwords) => passwords,
        Err(error) if is_cancellation(&error) => return Err(error),
        Err(error) => {
            let (code, mut result) = command_error(options.command, 2, "cli.operation_failed", error, language);
            result.inputs = json!({"paths": options.paths});
            return Ok((code, result));
        }
    };
    crate::pipeline::stage("password_reload", cancel).await?;
    let builtin = host.password_snapshot(cwd)?;
    let clipboard = cli_clipboard(&settings);
    if cancel.cancelled() {
        return interrupted(options, session, language, Some(&inputs), Vec::new());
    }
    let common_root = (!scan && (output.is_some() || options.verbose || options.json))
        .then(|| crate::pipeline::common_output_base(&inputs).unwrap_or_else(|| cwd.to_owned()));
    if !options.json {
        if !scan {
            let message = if inputs.len() == 1 {
                language.translate(
                    "cli.extract.single_target",
                    &[("path", &inputs[0].to_string_lossy())],
                )
            } else {
                language.translate(
                    "cli.extract.target_paths",
                    &[("count", &inputs.len().to_string())],
                )
            };
            line(session, Stream::Out, &message)?;
            if let Some(common_root) = common_root.as_ref().filter(|_| options.verbose) {
                if inputs.len() > 1 {
                    for path in &inputs {
                        let detail = language.translate(
                            "cli.detail_item_path",
                            &[("path", &path.to_string_lossy())],
                        );
                        line(session, Stream::Out, &detail)?;
                    }
                }
                let detail = language.translate(
                    "cli.extract.common_root",
                    &[("root", &common_root.to_string_lossy())],
                );
                line(session, Stream::Out, &detail)?;
            }
        }
        if session.interactive() {
            line(session, Stream::Out, language.text("interrupt.hint"))?;
        }
    }
    let max_depth = depth(settings.recursive_extract);
    let settings = Arc::new(settings);
    let mut failed_archives = HashSet::new();
    let mut had_input_error = false;
    let mut checkpoints = Vec::new();
    let mut generated_sources = Vec::new();
    loop {
        let began = Instant::now();
        let progress = Arc::new(Progress {
            session: Arc::clone(&owned_session),
            watch: Arc::clone(&host.watch),
            cancel: cancel.clone(),
            language,
            display: Mutex::default(),
            reporting: reporting::Reports::default(),
            prompt: settings.recursive_extract == Recursion::Prompt,
            visible: !options.json && !scan,
            verbose: options.verbose,
        });
        let mut request = Request::with_config(
            std::mem::take(&mut candidate_paths),
            if scan { Mode::Scan } else { Mode::Extract },
            Arc::clone(&settings),
        );
        request.output_root = output.clone();
        request.output_base = common_root.clone();
        request.max_depth = max_depth;
        request.recursive = options.recursive;
        request.deep = options.deep;
        request.passwords = user.iter().chain(&clipboard).cloned().collect();
        request.password_snapshot = Some(Arc::clone(&builtin));
        request.cancel = cancel.clone();
        request.checkpoints = std::mem::take(&mut checkpoints);
        request.generated_sources = std::mem::take(&mut generated_sources);
        let _report_close = ReportClose(&progress.reporting);
        let reporting = if progress.visible {
            let progress = Arc::clone(&progress);
            Some(engine.spawn_control(crate::pipeline::Origin::Foreground, &Cancellation::new(), async move {
                progress.reporting.serve_async(|| progress.flush_events()).await;
            })?)
        } else { None };
        let current = settle_unwind(engine.run_reserved_async(request, Arc::clone(&progress), Arc::clone(&reservation))).await;
        progress.reporting.close();
        if let Some(reporting) = reporting { reporting.wait().await; }
        let current = match current {
            Ok(current) => current,
            Err(panic) => std::panic::resume_unwind(panic),
        };
        crate::pipeline::stage("cli_output", &Cancellation::new()).await?;
        let cleared = progress.clear_panel();
        let current = match current {
            Ok(outcome) => outcome,
            Err(error) => return archive_request_error(error, &inputs, options.command, language),
        };
        cleared?;
        if cancel.cancelled() {
            let errors = current
                .cleanup_results
                .into_iter()
                .filter(|receipt| receipt.mode == "rollback")
                .map(|receipt| format!("{}: {}", receipt.path.display(), receipt.message))
                .collect();
            return interrupted(options, session, language, Some(&inputs), errors);
        }
        if scan {
            return report_scan(current, inputs, options, session, language);
        }
        if options.json {
            let mut result = CommandResult::new(options.command);
            let mut overrides = serde_json::Map::new();
            if let Some((_, value)) = &options.depth {
                overrides.insert("recursive_extract".into(), json!(value));
            }
            if let Some(cleanup) = options.cleanup {
                overrides.insert("archive_cleanup_mode".into(), json!(cleanup.option()));
            }
            if let Some(flatten) = options.flatten {
                overrides.insert("flatten_single_directory".into(), json!(flatten));
            }
            if let Some(path) = &output {
                overrides.insert("output_dir".into(), json!(path));
            }
            let groups = failures::archive_groups(&current.archives);
            let counts = ArchiveSummary::from_groups(&groups, language, true);
            let filesystem_errors = current.errors.iter().filter(|error| error.kind == InputErrorKind::FilesystemScan);
            let scan_errors = filesystem_errors.clone().count();
            let invalid_inputs = current
                .errors
                .iter()
                .filter(|error| error.kind == InputErrorKind::InvalidInput);
            let input_errors = invalid_inputs.clone().count() + counts.input_errors;
            let embedded_failures = current.errors.iter().filter(|error| error.kind == InputErrorKind::EmbeddedDiscovery);
            let failed = counts.failed + embedded_failures.clone().count();
            let mut failures: Vec<_> = embedded_failures
                .map(|error| failures::Report::input_error(error, language)).collect();
            failures.extend(groups.iter().filter_map(|entries| failures::archive_report(entries, language)));
            failures.extend(invalid_inputs.clone().map(|error| failures::Report::input_error(error, language)));
            result.errors.extend(current.errors.iter()
                .filter(|error| matches!(error.kind, InputErrorKind::FilesystemScan | InputErrorKind::EmbeddedDiscovery))
                .chain(invalid_inputs)
                .map(|error| input_error_message(error, language, true)));
            result.errors.extend(counts.errors);
            result.tasks.push(json!({
                "success_count": counts.success, "failed_count": failed,
                "input_error_count": input_errors, "scan_error_count": scan_errors,
                "processed_count": counts.processed, "partial_success_count": counts.partial,
                "recovered_outputs": &counts.recovered, "wrong_password_failure": current.archives.iter().any(password_failure),
                "failures": failures,
            }));
            let mut cleanup = ReceiptOrder::new();
            for receipt in current.cleanup_results {
                cleanup.insert(path_key(&receipt.path), receipt);
            }
            result.inputs = json!({
                "paths": inputs, "common_root": common_root, "json": true, "verbose": options.verbose,
                "deep_detect": options.deep, "config_overrides": overrides,
            });
            result.summary = json!({
                "success_count": counts.success, "failed_count": failed, "scan_error_count": scan_errors,
                "scan_failures": filesystem_errors.map(|error| failures::Report::filesystem_scan(error, language)).collect::<Vec<_>>(),
                "input_error_count": input_errors, "processed_count": counts.processed,
                "partial_success_count": counts.partial, "recovered_outputs": counts.recovered,
                "password_retry_count": 0, "cleanup_results": cleanup.values,
            });
            result.password_sources = Some(Box::new(PasswordSources::new(
                user,
                clipboard,
                engine.recent_passwords(),
                builtin,
            )));
            return Ok((i32::from(!result.errors.is_empty()), result));
        }
        let output_location = std::mem::take(&mut progress.display.lock().unwrap().output_location);
        report_extract_round(&current, output_location, began.elapsed().as_secs(), session, language)?;
        checkpoints = current.checkpoints;
        generated_sources = current.generated_sources;
        // Retry inputs are physical paths. Replace every segment for a path
        // together even when a formerly nested carrier is now a root.
        candidate_paths = password_retry_paths(&current.archives);
        record_archive_failures(&mut failed_archives, &current.archives);
        had_input_error |= !current.errors.is_empty();
        drop(current.archives);
        drop(current.errors);
        drop(current.cleanup_results);
        drop(_report_close);
        drop(progress);
        if candidate_paths.is_empty() {
            break;
        }
        trim_password_retry_recovery(&candidate_paths, &mut checkpoints, &mut generated_sources);
        let retry = confirm(
            session,
            language,
            language.text("cli.password_retry_prompt"),
        ).await?;
        if cancel.cancelled() {
            return interrupted(options, session, language, Some(&inputs), Vec::new());
        }
        if !retry {
            break;
        }
        let additional = prompt_passwords(session, language).await?;
        if cancel.cancelled() {
            return interrupted(options, session, language, Some(&inputs), Vec::new());
        }
        if additional.is_empty() {
            line(
                session,
                Stream::Out,
                language.text("cli.extract.retry_no_passwords"),
            )?;
            break;
        }
        user.extend(additional);
        dedupe(&mut user);
    }
    // Each round has already written its report. Only the latest status per
    // carrier and any request-level input failures affect the final exit code.
    let failed = had_input_error || !failed_archives.is_empty();
    Ok((i32::from(failed), CommandResult::new(options.command)))
    };
    let result = settle_unwind(execution).await;
    foreground.finish_async().await;
    match result { Ok(result) => result, Err(panic) => std::panic::resume_unwind(panic) }
}

fn report_extract_round(
    current: &Outcome, output_location: crate::pipeline::CommonAncestor, elapsed: u64,
    session: &dyn Session, language: Language,
) -> io::Result<()> {
    let counts = ArchiveSummary::collect(&current.archives, language, false);
    let scan_errors = current.errors.iter()
        .filter(|error| error.kind == InputErrorKind::FilesystemScan)
        .count();
    let input_errors = current.errors.iter()
        .filter(|error| error.kind == InputErrorKind::InvalidInput).count() + counts.input_errors;
    let failed = counts.failed + current.errors.iter()
        .filter(|error| error.kind == InputErrorKind::EmbeddedDiscovery).count();
    let mut errors: Vec<_> = current.errors.iter()
        .filter(|error| matches!(error.kind, InputErrorKind::FilesystemScan | InputErrorKind::EmbeddedDiscovery))
        .chain(current.errors.iter().filter(|error| error.kind == InputErrorKind::InvalidInput))
        .map(|error| input_error_message(error, language, false)).collect();
    errors.extend(counts.errors);
    if scan_errors != 0 { errors.push(language.text("report.scan_incomplete").into()); }
    line(session, Stream::Out, &format!("\n{}", "-".repeat(54)))?;
    let seconds = (elapsed % 60).to_string();
    let duration = if elapsed >= 60 {
        language.translate(
            "duration.minutes_seconds",
            &[
                ("minutes", &(elapsed / 60).to_string()),
                ("seconds", &seconds),
            ],
        )
    } else {
        language.translate("duration.seconds", &[("seconds", &seconds)])
    };
    line(
        session,
        Stream::Out,
        &language.translate("report.time", &[("duration", &duration)]),
    )?;
    line(
        session,
        Stream::Out,
        &language.translate(
            "report.counts",
            &[
                ("complete", &counts.success.to_string()),
                ("partial", &counts.partial.to_string()),
                ("failed", &failed.to_string()),
                ("scan_errors", &scan_errors.to_string()),
                ("input_errors", &input_errors.to_string()),
            ],
        ),
    )?;
    if counts.nested != 0 {
        line(
            session,
            Stream::Out,
            &language.translate(
                "report.recursion",
                &[
                    ("levels", &counts.depth.to_string()),
                    ("count", &counts.nested.to_string()),
                ],
            ),
        )?;
    }
    use crate::pipeline::CommonAncestor;
    if !matches!(output_location, CommonAncestor::Empty) {
        let display = match &output_location {
            CommonAncestor::Shared(path) => path.to_string_lossy(),
            _ => Cow::Borrowed(language.text("report.multiple_locations")),
        };
        line(
            session,
            Stream::Out,
            &language.translate("report.output", &[("output", &display)]),
        )?;
    }
    for recovery in &counts.recovered {
        let name = recovery.archive
            .file_name()
            .unwrap_or(recovery.archive.as_os_str())
            .to_string_lossy();
        let complete = recovery.complete_files.to_string();
        line(
            session,
            Stream::Out,
            &language.translate(
                "report.partial",
                &[("archive", &name), ("complete_files", &complete)],
            ),
        )?;
        if recovery.has_warning {
            let warning = language.text("failure.possible_missing_volume");
            line(
                session,
                Stream::Out,
                &language.translate("report.partial_warning", &[("warning", warning)]),
            )?;
        }
    }
    for error in &errors { line(session, Stream::Err, error)?; }
    if counts.partial > 0 && errors.is_empty() {
        line(
            session,
            Stream::Out,
            language.text("report.partial_complete"),
        )?;
    }
    let cleanup_failures = current.cleanup_results.len();
    if cleanup_failures > 0 {
        let message = language.translate(
            "cleanup.incomplete",
            &[("count", &cleanup_failures.to_string())],
        );
        line(
            session,
            Stream::Err,
            &language.translate("report.postprocess_warning", &[("message", &message)]),
        )?;
        for receipt in &current.cleanup_results {
            line(session, Stream::Err, &format!("  {}: {}", receipt.path.display(), receipt.message))?;
        }
    }
    line(session, Stream::Out, &"-".repeat(54))?;
    Ok(())
}

fn report_scan(
    outcome: Outcome,
    inputs: Vec<PathBuf>,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let scan_errors = outcome
        .errors
        .iter()
        .filter(|error| error.kind == InputErrorKind::FilesystemScan)
        .count();
    let input_errors = outcome
        .errors
        .iter()
        .filter(|error| error.kind == InputErrorKind::InvalidInput)
        .count();
    let mut result = CommandResult::new("scan");
    let mut failed = 0;
    let mut archive_input_errors = 0;
    let scan_failures = outcome.errors.iter().filter(|error| matches!(error.kind,
        InputErrorKind::FilesystemScan | InputErrorKind::EmbeddedDiscovery));
    for error in scan_failures {
        failed += usize::from(error.kind == InputErrorKind::EmbeddedDiscovery);
        let message = input_error_message(error, language, true);
        result.errors.push(if options.json { message } else {
            language.translate("report.scan_error", &[("task", &message)])
        });
    }
    if !options.json && scan_errors != 0 {
        result.errors.push(language.text("report.scan_incomplete").into());
    }
    result.errors.extend(outcome.errors.iter()
        .filter(|error| error.kind == InputErrorKind::InvalidInput)
        .map(|error| {
            let message = failures::invalid_input_message(error, language);
            if options.json { message } else { format!("{}: {message}", error.path.display()) }
        }));
    for task in &outcome.scan_failures {
        let entries = &outcome.archives[task.archives.clone()];
        let failure = task.preflight.as_deref()
            .or_else(|| entries.iter().find_map(|entry| entry.failure.as_ref()))
            .expect("failed scan task");
        let invalid = failure.kind == FailureKind::InvalidInput;
        failed += usize::from(!invalid);
        archive_input_errors += usize::from(invalid);
        if options.json {
            let message = if task.preflight.is_some() {
                failure_message(failure, language)
            } else {
                failures::scan_message(entries.iter(), language)
            };
            result.errors.push(format!("{} [{message}]", task.path.display()));
        } else if entries.is_empty() {
            result.errors.push(format!("{}: {}", task.path.display(), failure_message(failure, language)));
        }
    }
    let mut rows: Vec<_> = outcome.archives.iter().enumerate()
        .map(|(index, entry)| (path_key(&entry.path), index))
        .collect();
    rows.sort_unstable_by(|(ka, a), (kb, b)| {
        ka.cmp(kb).then_with(|| {
            let a = &outcome.archives[*a];
            let b = &outcome.archives[*b];
            a.offset.cmp(&b.offset).then_with(|| a.format.cmp(&b.format))
        })
    });
    let code = i32::from(!outcome.scan_failures.is_empty() || !result.errors.is_empty());
    if options.json {
        result.inputs = json!({"paths": inputs, "deep_detect": options.deep});
        result.summary = json!({
            "archive_count": rows.len(), "failed_count": failed,
            "scan_error_count": scan_errors, "input_error_count": input_errors + archive_input_errors,
        });
        result.scan_report = Some(Box::new(json::ScanReport {
            archives: outcome.archives, rows, language, verbose: options.verbose,
        }));
        return Ok((code, result));
    }
    let mut start = 0;
    while start < rows.len() {
        let key = &rows[start].0;
        let end = start
            + rows[start..]
                .iter()
                .take_while(|(path, _)| path == key)
                .count();
        let group = &rows[start..end];
        line(session, Stream::Out, &outcome.archives[group[0].1].path.to_string_lossy())?;
        for (index, &(_, row)) in group.iter().enumerate() {
            let entry = &outcome.archives[row];
            let embedded = entry.scan_layout.range;
            let show_password = entry.encrypted == Some(true)
                || entry.password.is_some()
                || password_failure(entry);
            let plan = entry.volume_attempts.as_deref();
            let (show_parts, completeness) = entry.scan_layout.volumes(entry);
            let multiple = group.len() > 1;
            let last = index + 1 == group.len();
            let (edge, continuation) = if multiple {
                tree_edge(session.unicode(), last)
            } else {
                ("", "")
            };
            let prefix = format!("{continuation}  ");
            let prefix = prefix.as_str();
            if multiple {
                let text = language
                    .translate("cli.scan.segment", &[("index", &(index + 1).to_string())]);
                let range = if embedded {
                    format!(": [{}, {})", entry.offset, end_offset(entry))
                } else {
                    String::new()
                };
                line(session, Stream::Out, &format!("{edge}{text}{range}"))?;
            } else if embedded {
                let text = language.translate(
                    "cli.scan.range",
                    &[
                        ("start", &entry.offset.to_string()),
                        ("end", &end_offset(entry)),
                    ],
                );
                line(session, Stream::Out, &format!("{prefix}{text}"))?;
            }
            if let Some(failure) = &entry.failure {
                if !(failure.kind == FailureKind::WrongPassword && entry.password.is_none())
                    && !(failure.kind == FailureKind::MissingVolume
                        && entry.volume_completeness == Some(crate::io::archive_state::VolumeCompleteness::Missing))
                {
                    let error = language.translate("cli.scan.error", &[
                        ("error", &failure_message(failure, language)),
                    ]);
                    let text = if embedded {
                        format!("{}: [{}, {}): {error}",
                            entry.path.display(), entry.offset, end_offset(entry))
                    } else {
                        format!("{}: {error}", entry.path.display())
                    };
                    line(session, Stream::Err, &text)?;
                }
            }
            if !entry.format.is_empty() {
                let format = language.translate("cli.scan.format", &[("format", &entry.format)]);
                line(session, Stream::Out, &format!("{prefix}{format}"))?;
            }
            if let Some(plan) = plan {
                report_volume_plan(plan, prefix, language, session)?;
            } else if show_parts {
                let parts = entry
                    .source_paths
                    .iter()
                    .map(|path| {
                        path.file_name()
                            .unwrap_or(path.as_os_str())
                            .to_string_lossy()
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let text = language.translate("cli.scan.parts", &[("parts", &parts)]);
                line(session, Stream::Out, &format!("{prefix}{text}"))?;
            }
            if let Some(completeness) = completeness {
                let key = format!("cli.scan.volumes.{completeness}");
                let state = language.text(&key);
                let text = language.translate("cli.scan.volumes", &[("state", state)]);
                line(session, Stream::Out, &format!("{prefix}{text}"))?;
            }
            if show_password {
                let value = entry
                    .password
                    .as_deref()
                    .map(|password| if password.is_empty() { "''" } else { password })
                    .unwrap_or(language.text("cli.scan.password_unknown"));
                let text = language.translate("cli.scan.password", &[("password", value)]);
                line(session, Stream::Out, &format!("{prefix}{text}"))?;
            }
            if options.verbose {
                let source = match entry.discovery_source {
                    crate::pipeline::DiscoverySource::Relations => "relations",
                    crate::pipeline::DiscoverySource::Detection => "detection",
                    crate::pipeline::DiscoverySource::Embedded => "embedded",
                };
                let text = language.translate("cli.scan.source", &[("source", source)]);
                line(session, Stream::Out, &format!("{prefix}{text}"))?;
            }
        }
        start = end;
    }
    Ok((code, result))
}

fn report_volume_plan(
    plan: &crate::io::archive_state::VolumeAttemptPlan,
    prefix: &str,
    language: Language,
    session: &dyn Session,
) -> io::Result<()> {
    let mut positions = BTreeMap::<u32, (BTreeSet<usize>, usize)>::new();
    let mut minimum = usize::MAX;
    let mut maximum = 0;
    for layout in &plan.layouts {
        let Some(tail) = layout.slots.last() else {
            continue;
        };
        let count = if layout.minimum_slots == 0 {
            layout.slots.len()
        } else {
            layout.minimum_slots
        };
        minimum = minimum.min(count);
        maximum = maximum.max(layout.slots.len());
        for (index, slot) in layout.slots.iter().enumerate() {
            let (domains, required) = positions.entry(slot.number).or_default();
            domains.insert(slot.domain);
            *required += usize::from(index < count);
            if index + 1 >= count {
                domains.insert(tail.domain);
            }
        }
    }
    let mut groups = BTreeMap::<(BTreeSet<usize>, bool), Vec<u32>>::new();
    for (position, (domains, required)) in positions {
        let optional = required < plan.layouts.len();
        groups
            .entry((domains, optional))
            .or_default()
            .push(position);
    }
    let mut groups = groups.into_iter().collect::<Vec<_>>();
    groups.sort_unstable_by_key(|(_, positions)| positions[0]);
    for ((domains, optional), positions) in groups {
        let choices: BTreeSet<_> = domains
            .into_iter()
            .flat_map(|domain| plan.domains[domain].choices.iter().copied())
            .collect();
        if choices.len() <= 1 && !optional {
            continue;
        }
        let names = choices
            .into_iter()
            .map(|source| {
                let source = &plan.sources[source];
                let path = Path::new(&source.path);
                let mut name = path
                    .file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy()
                    .into_owned();
                if source.start != 0 || source.end.is_some() {
                    let end = source
                        .end
                        .map_or_else(|| "?".to_owned(), |end| end.to_string());
                    name.push_str(&format!("[{}, {end})", source.start));
                }
                name
            })
            .collect::<Vec<_>>()
            .join(", ");
        let positions = positions
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let key = if optional {
            "cli.scan.optional_volume_candidates"
        } else {
            "cli.scan.volume_candidates"
        };
        let text = language.translate(key, &[("positions", &positions), ("candidates", &names)]);
        line(session, Stream::Out, &format!("{prefix}{text}"))?;
    }
    if minimum < maximum {
        let text = language.translate(
            "cli.scan.volume_count",
            &[
                ("minimum", &minimum.to_string()),
                ("maximum", &maximum.to_string()),
            ],
        );
        line(session, Stream::Out, &format!("{prefix}{text}"))?;
    }
    Ok(())
}

fn end_offset(entry: &ArchiveResult) -> String {
    entry
        .end_offset
        .map_or_else(|| "?".to_owned(), |end| end.to_string())
}

#[derive(Serialize)]
struct PasswordItem<'a> {
    user_passwords: &'a [Arc<str>],
    recent_passwords: &'a [Arc<str>],
    clipboard_passwords: &'a [Arc<str>],
    builtin_passwords: &'a [Arc<str>],
    combined_passwords: &'a [Arc<str>],
}

struct PasswordSources {
    user: Vec<Arc<str>>,
    clipboard: Vec<Arc<str>>,
    recent: Vec<Arc<str>>,
    builtin: Arc<passwords::PasswordSnapshot>,
    combined: Vec<Arc<str>>,
}

impl PasswordSources {
    fn new(
        user: Vec<Arc<str>>, clipboard: Vec<Arc<str>>, recent: Vec<Arc<str>>,
        builtin: Arc<passwords::PasswordSnapshot>,
    ) -> Self {
        let global = builtin.global();
        let configured = user.iter().chain(&clipboard).chain(global);
        let mut missing_recent: HashSet<&str> = recent.iter().map(Arc::as_ref).collect();
        if !missing_recent.is_empty() {
            for value in configured.clone() {
                missing_recent.remove(value.as_ref());
                if missing_recent.is_empty() { break; }
            }
        }
        let mut seen = HashSet::new();
        let combined = recent.iter()
            .filter(|value| !missing_recent.contains(value.as_ref()))
            .chain(configured)
            .filter(|&value| seen.insert(value.as_ref()))
            .cloned()
            .collect();
        Self { user, clipboard, recent, builtin, combined }
    }

    fn item(&self) -> PasswordItem<'_> {
        PasswordItem {
            user_passwords: &self.user,
            recent_passwords: &self.recent,
            clipboard_passwords: &self.clipboard,
            builtin_passwords: self.builtin.global(),
            combined_passwords: &self.combined,
        }
    }
}

// The command displays Python-style list values, as main does. Escape only
// their textual representation; the candidates themselves remain unchanged.
fn password_repr(value: &str) -> String {
    let mut text = String::with_capacity(value.len() + 2);
    append_password_repr(&mut text, value);
    text
}

fn append_password_repr(text: &mut String, value: &str) {
    let quote = if value.contains('\'') && !value.contains('"') { '"' } else { '\'' };
    text.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => text.push_str("\\\\"),
            '\t' => text.push_str("\\t"),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            c if c == quote => { text.push('\\'); text.push(c); }
            c if password_non_printable(c) => {
                use std::fmt::Write;
                let code = c as u32;
                if code <= 0xff { let _ = write!(text, "\\x{code:02x}"); }
                else if code <= 0xffff { let _ = write!(text, "\\u{code:04x}"); }
                else { let _ = write!(text, "\\U{code:08x}"); }
            }
            c => text.push(c),
        }
    }
    text.push(quote);
}

fn password_non_printable(value: char) -> bool {
    if value.is_ascii() {
        return value.is_ascii_control();
    }
    use regex_syntax::hir::{Class, ClassUnicode, HirKind};
    static NON_PRINTABLE: OnceLock<ClassUnicode> = OnceLock::new();
    let ranges = NON_PRINTABLE.get_or_init(|| {
        let hir = regex_syntax::Parser::new().parse(r"[\p{C}\p{Z}]").unwrap();
        let HirKind::Class(Class::Unicode(class)) = hir.into_kind() else { unreachable!() };
        class
    }).ranges();
    let index = ranges.partition_point(|range| range.end() < value);
    ranges.get(index).is_some_and(|range| range.start() <= value)
}

fn password_list_repr<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let mut text = String::from("[");
    for (index, value) in values.into_iter().enumerate() {
        if index != 0 { text.push_str(", "); }
        append_password_repr(&mut text, value);
    }
    text.push(']');
    text
}

async fn show_passwords(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
    settings: Config,
) -> io::Result<(i32, CommandResult)> {
    let user = cli_passwords(cwd, options, session, language).await?;
    crate::pipeline::stage("password_reload", &Cancellation::new()).await?;
    let clipboard = cli_clipboard(&settings);
    let snapshot = host.password_snapshot(cwd)?;
    let sources = PasswordSources::new(user, clipboard, Vec::new(), snapshot);
    let item = sources.item();
    let mut result = CommandResult::new("passwords");
    if options.json {
        result.inputs = json!({"json":true});
        result.summary = json!({
            "user_password_count": item.user_passwords.len(), "recent_password_count": 0,
            "clipboard_password_count": item.clipboard_passwords.len(), "builtin_password_count": item.builtin_passwords.len(),
            "combined_password_count": item.combined_passwords.len(),
        });
        result.password_sources = Some(Box::new(sources));
        return Ok((0, result));
    }
    line(session, Stream::Out, language.text("cli.passwords.summary"))?;
    let show = |key, value: String| {
        line(session, Stream::Out, &language.translate(key, &[("value", &value)]))
    };
    for (key, values) in [
        ("cli.passwords.user_input", item.user_passwords),
        ("cli.passwords.recent", item.recent_passwords),
        ("cli.passwords.clipboard", item.clipboard_passwords),
        ("cli.passwords.builtin", item.builtin_passwords),
    ] {
        show(key, password_list_repr(values.iter().map(Arc::as_ref)))?;
    }
    show("cli.passwords.final_order", password_list_repr(item.combined_passwords.iter().map(Arc::as_ref)))?;
    Ok((0, result))
}

async fn validate_scan_rule(session: &dyn Session) -> io::Result<(i32, CommandResult)> {
    let mut input = String::new();
    while let Some(line) = session.aread_line("").await? {
        input.push_str(&line);
        if session.input_is_terminal() { break; }
    }
    crate::pipeline::stage("cli", &Cancellation::new()).await?;
    let mut rule: Value = serde_json::from_str(&input)?;
    if let Some(object) = rule.as_object_mut() {
        object.insert("name".into(), json!("blacklist"));
    }
    config::PathRule::parse(&rule)?.compile()?;
    let mut result = CommandResult::new("config");
    result.inputs = json!({"action": "validate"});
    result.summary = json!({"valid": true});
    Ok((0, result))
}

fn show_config(
    settings: io::Result<(PathBuf, Value, Config)>,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("config");
    result.inputs = json!({"action": options.action});
    let (path, payload, settings) = settings?;
    result.summary = json!({"config_path": path, "changed": false});
    if options.action == "show" {
        if !options.json {
            write_json(session, &payload)?;
        }
        result.items.push(payload);
        return Ok((0, result));
    }
    let errors = settings.validate_scan_filters();
    if !errors.is_empty() {
        result.summary["valid"] = Value::Bool(false);
        result.errors.extend(errors.iter().map(|error| language.translate(
            "cli.config.validation_error", &[("error", error.as_str())],
        )));
        result.items.push(json!({"ok": false, "errors": errors, "warnings": []}));
        return Ok((2, result));
    }
    if !options.json {
        line(session, Stream::Out, language.text("cli.config.valid_config"))?;
    }
    result.items.push(json!({"ok": true, "errors": [], "warnings": []}));
    Ok((0, result))
}

fn show_version(session: &dyn Session) -> io::Result<(i32, CommandResult)> {
    let path = std::env::current_exe()?.with_file_name("VERSION.txt");
    let text = std::fs::read_to_string(path)?;
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("version="))
        .ok_or(io::ErrorKind::InvalidData)?;
    line(session, Stream::Out, version)?;
    let mut result = CommandResult::new("version");
    result.summary = json!({"version": version});
    Ok((0, result))
}

fn doctor(
    cwd: &Path,
    settings: io::Result<(PathBuf, Config)>,
    session: &dyn Session,
    json_output: bool,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("doctor");
    result.items = super::doctor::checks(cwd, settings);
    let failed = result
        .items
        .iter()
        .filter(|check| check["status"] == "fail")
        .count();
    let count = |status: &str| {
        result
            .items
            .iter()
            .filter(|check| check["status"] == status)
            .count()
    };
    let ok = count("ok");
    let warnings = count("warn");
    let skipped = count("skip");
    if !json_output {
        for check in &result.items {
            let name = check["name"].as_str().unwrap_or_default();
            let mut label = super::doctor::label(name, language);
            if name == "watch_root" {
                label.push(' ');
                label.push_str(check["path"].as_str().unwrap_or_default());
            }
            let detail = check["detail"].as_str().filter(|detail| !detail.is_empty());
            let text = format!(
                "[{}] {label}{}",
                check["status"]
                    .as_str()
                    .unwrap_or_default()
                    .to_ascii_uppercase(),
                detail.map_or(String::new(), |text| format!(": {text}"))
            );
            line(
                session,
                if check["status"] == "fail" {
                    Stream::Err
                } else {
                    Stream::Out
                },
                &text,
            )?;
        }
        line(
            session,
            Stream::Out,
            &language.translate(
                "cli.doctor.summary",
                &[
                    ("ok", &ok.to_string()),
                    ("warnings", &warnings.to_string()),
                    ("skipped", &skipped.to_string()),
                    ("failed", &failed.to_string()),
                ],
            ),
        )?;
    }
    result.errors = if json_output {
        result
            .items
            .iter()
            .filter(|check| check["status"] == "fail")
            .map(|check| check["detail"].as_str().unwrap_or_default().to_owned())
            .collect()
    } else {
        Vec::new()
    };
    result.summary = json!({"checks":result.items.len(),"ok":ok,"warnings":warnings,"skipped":skipped,"failed":failed});
    Ok((i32::from(failed != 0), result))
}

async fn daemon_command(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("daemon");
    result.inputs = json!({"action": options.action});
    match options.action.as_str() {
        "start" => result.summary = host.watch.start_async(cwd, host.engine(cwd)?, !options.no_tray).await?,
        // The launcher/pipe handles shutdown before dispatching CLI requests.
        "stop" => return Err(invalid("daemon stop requires the persistent control channel")),
        "startup" => {
            let action = &options.paths[0];
            result.inputs["startup_action"] = json!(action);
            result.summary = match action.as_str() {
                "enable" => json!({"enabled":true,"command":windows::startup_enable()?}),
                "disable" => json!({"enabled":false,"changed":windows::startup_disable()?}),
                _ => {
                    let value = windows::startup_status()?;
                    if !options.json {
                        let message = if value.is_some() {
                            "cli.daemon.startup_enabled"
                        } else {
                            "cli.daemon.startup_disabled"
                        };
                        line(session, Stream::Out, language.text(message))?;
                    }
                    json!({"enabled":value.is_some(),"command":value.unwrap_or_default()})
                }
            };
        }
        _ => unreachable!(),
    }
    Ok((0, result))
}

async fn watch_command(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("watch");
    result.inputs = json!({"action": options.action});
    let mut code = 0;
    match options.action.as_str() {
        "enable" | "disable" => result.summary = host.watch.set_enabled_async(cwd, host.engine(cwd)?, options.action == "enable").await?,
        "reload" => result.summary = host.watch.reload_async().await?,
        "add" => {
            let requested = watch_targets(cwd, options);
            let output = options.output.as_deref();
            result.inputs = json!({"action": "add", "paths": requested, "output_dir": output});
            if output.is_some() && requested.len() != 1 {
                result
                    .errors
                    .push(language.text("cli.watch.output_dir_single_path").into());
                return Ok((2, result));
            }
            result.inputs["deep_detect"] = json!(options.deep.then_some(true));
            let paths = targets(cwd, options)?;
            result.summary =
                host.watch
                    .add_async(cwd, &paths, output, options.deep, options.recursive).await?;
            result.items = result.summary["added"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            if result.items.is_empty()
                && result.summary["updated"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
            {
                if let Some(rejected) = result.summary["rejected"]
                    .as_array()
                    .filter(|items| !items.is_empty())
                {
                    let paths = rejected
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join("\n");
                    result.errors.push(
                        language.translate("cli.watch.add_all_rejected", &[("paths", &paths)]),
                    );
                    code = 1;
                }
            }
        }
        "remove" => {
            let paths = targets(cwd, options)?;
            result.inputs["paths"] = json!(watch_targets(cwd, options));
            result.summary = host.watch.remove_async(cwd, &paths).await?;
            result.items = result.summary["removed"]
                .as_array()
                .cloned()
                .unwrap_or_default();
        }
        "list" | "status" => {
            let (path, roots) = host.watch.roots(cwd)?;
            result.items = roots.into_iter().map(|path| json!(path)).collect();
            result.summary = if options.action == "list" {
                json!({"roots_path": path, "count": result.items.len()})
            } else {
                let mut status = host.watch.status(cwd)?;
                status["count"] = json!(result.items.len());
                if !options.json {
                    let message = if status["enabled"] == true {
                        "cli.watch.running"
                    } else {
                        "cli.watch.stopped"
                    };
                    line(session, Stream::Out, language.text(message))?;
                }
                status
            };
        }
        "relog" => {
            let rebuilt = host.watch.rebuild_log_async(cwd).await?;
            result.summary = json!({"rebuilt": rebuilt});
            let key = if rebuilt {
                "cli.watch.relog_done"
            } else {
                "cli.watch.relog_failed"
            };
            let message = language.text(key).to_owned();
            if rebuilt {
                result.logs.push(message);
            } else {
                result.errors.push(message);
                code = 1;
            }
        }
        _ => unreachable!(),
    }
    Ok((code, result))
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/cli/option_tests.rs"]
mod option_tests;

#[cfg(test)]
#[path = "../../tests/unit/runtime/cli/recursive_prompt_tests.rs"]
mod recursive_prompt_tests;
