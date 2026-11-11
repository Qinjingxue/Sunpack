use super::{watch, windows, Session, Stream};
use crate::core::config::{self, CleanupMode, Config, Recursion};
use crate::core::i18n::Language;
use crate::core::{passwords, resources};
use crate::pipeline::{
    ArchiveResult, Cancellation, CleanupStatus, Engine, Event, FailureKind, InputError,
    InputErrorKind, Mode, Observer, Outcome, Request, TaskId,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

mod live;
mod reporting;

pub(super) struct Host {
    engine: OnceLock<Arc<Engine>>,
    passwords: Mutex<Option<Arc<passwords::BuiltinStore>>>,
    idle: Mutex<Duration>,
    pub(super) watch: watch::Watch,
}

impl Host {
    pub(super) fn new() -> Self {
        Self::with_wake(|| {})
    }

    pub(super) fn with_wake(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            engine: OnceLock::new(),
            passwords: Mutex::default(),
            idle: Mutex::new(Duration::from_secs(30)),
            watch: watch::Watch::new(Arc::new(wake)),
        }
    }

    pub(super) fn idle_after(&self) -> Duration {
        *self.idle.lock().unwrap()
    }

    pub(super) fn configure_idle(&self, settings: &Config) {
        if let Ok(idle) =
            Duration::try_from_secs_f64(settings.performance.persistent_server_idle_seconds)
        {
            *self.idle.lock().unwrap() = idle;
        }
    }

    fn engine(&self, cwd: &Path) -> io::Result<Arc<Engine>> {
        if let Some(engine) = self.engine.get() {
            return Ok(Arc::clone(engine));
        }
        let worker = resources::worker_path(cwd)?;
        Ok(Arc::clone(
            self.engine.get_or_init(|| Arc::new(Engine::new(worker))),
        ))
    }

    fn passwords(&self, cwd: &Path) -> io::Result<Arc<passwords::BuiltinStore>> {
        let source = passwords::BuiltinStore::shared(cwd)?;
        let mut held = self.passwords.lock().unwrap();
        if held
            .as_ref()
            .is_none_or(|previous| previous.path() != source.path())
        {
            *held = Some(Arc::clone(&source));
        }
        Ok(source)
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
    direct: bool,
    flatten: Option<bool>,
    depth: Option<String>,
    cleanup: Option<String>,
    output: Option<String>,
    password_file: Option<String>,
    passwords: Vec<Arc<str>>,
    prompt_passwords: bool,
    no_builtins: bool,
    no_tray: bool,
    once: bool,
    start: bool,
    rule_stdin: bool,
}

const COMMANDS: &[(&str, &str)] = &[
    ("extract", "e"),
    ("watch", "w"),
    ("scan", "s"),
    ("passwords", "pw"),
    ("config", "cfg"),
    ("doctor", "d"),
    ("version", "ver"),
];

impl Options {
    fn parse(argv: &[String]) -> io::Result<Self> {
        let mut args: VecDeque<_> = argv.iter().map(|arg| Cow::Borrowed(arg.as_str())).collect();
        let Some(command) = args.pop_front() else {
            return Ok(Self {
                help: true,
                ..Self::default()
            });
        };
        if matches!(command.as_ref(), "-h" | "--help") {
            return Ok(Self {
                help: true,
                ..Self::default()
            });
        }
        let command = COMMANDS
            .iter()
            .find(|(name, alias)| command.as_ref() == *name || command.as_ref() == *alias)
            .map(|(name, _)| *name)
            .ok_or_else(|| invalid(format!("invalid choice: {command}")))?;
        let mut options = Self {
            command,
            ..Self::default()
        };
        let mut positional = false;
        let mut supplied = false;
        let mut after_action = false;
        while let Some(mut arg) = args.pop_front() {
            supplied = true;
            if arg == "--" && !positional {
                positional = true;
                continue;
            }
            if positional || !looks_like_option(&arg) {
                if matches!(command, "watch" | "config") && options.action.is_empty() {
                    options.action = match (command, arg.as_ref()) {
                        ("watch", "rm") => "remove".into(),
                        ("watch", "ls") => "list".into(),
                        ("watch", "st") => "status".into(),
                        _ => arg.into_owned(),
                    };
                } else {
                    after_action = true;
                    options.paths.push(arg.into_owned());
                }
                continue;
            }
            if !arg.starts_with("--") && arg.len() > 2 && arg.as_bytes()[1].is_ascii() {
                if b"pPocr".contains(&arg.as_bytes()[1]) {
                    if arg.as_bytes()[2] != b'=' {
                        arg.to_mut().insert(2, '=');
                    }
                } else if b"jvRdfFash".contains(&arg.as_bytes()[1]) {
                    args.push_front(Cow::Owned(format!("-{}", &arg[2..])));
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
                            .filter(|value| !looks_like_option(value))
                            .map(Cow::into_owned)
                    })
                    .ok_or_else(|| invalid(format!("{flag} expects a value")))
            };
            let archives = matches!(command, "extract" | "scan");
            let watch_add = command == "watch" && options.action == "add";
            let watch_start = command == "watch" && options.action == "start";
            let common = archives || command == "watch";
            let passwords = archives || command == "passwords";
            match flag {
                "-h" | "--help" => {
                    if inline.is_some() {
                        return Err(invalid(format!("{flag} does not take a value")));
                    }
                    options.help = true;
                    return Ok(options);
                }
                "-j" | "--json" if command != "version" => options.json = true,
                "-v" | "--verbose" if common => options.verbose = true,
                "--pause" if common => options.pause = true,
                "--no-pause" if common => options.no_pause = true,
                "-R" | "--recursive" if archives || watch_add => options.recursive = true,
                "-d" | "--deep-detect" if archives || watch_add => options.deep = true,
                "--direct" | "--direct-file" if command == "extract" => options.direct = true,
                "-f" | "--flatten" if command == "extract" && options.flatten != Some(false) => {
                    options.flatten = Some(true)
                }
                "-F" | "--no-flatten" if command == "extract" && options.flatten != Some(true) => {
                    options.flatten = Some(false)
                }
                "-r" | "--recur" if command == "extract" => {
                    let value = take()?.trim().to_owned();
                    Recursion::parse(&value)?;
                    options.depth = Some(value);
                    continue;
                }
                "-c" | "--cleanup" if command == "extract" => {
                    let value = take()?.trim().to_ascii_lowercase();
                    CleanupMode::parse(&value)?;
                    options.cleanup = Some(value);
                    continue;
                }
                "-o" | "--out-dir" if command == "extract" || watch_add => {
                    options.output = Some(take()?);
                    continue;
                }
                "-p" | "--password" if passwords => {
                    options.passwords.push(take()?.into());
                    continue;
                }
                "-P" | "--pw-file" if passwords => {
                    options.password_file = Some(take()?);
                    continue;
                }
                "-a" | "--ask-pw" if passwords => options.prompt_passwords = true,
                "--no-builtin-pw" | "--no-bpw" if passwords => options.no_builtins = true,
                "--once" if watch_start => options.once = true,
                "--no-tray" if watch_start => options.no_tray = true,
                "-s" | "--start" if watch_add => options.start = true,
                "--scan-rule-stdin" if command == "config" && options.action == "validate" => {
                    options.rule_stdin = true
                }
                _ => return Err(invalid(format!("unrecognized argument: {arg}"))),
            }
            if inline.is_some() {
                return Err(invalid(format!("{flag} does not take a value")));
            }
        }
        if options.no_pause && options.pause {
            return Err(invalid("--pause and --no-pause are mutually exclusive"));
        }
        let wants_paths = match (command, options.action.as_str()) {
            ("extract" | "scan", "") => true,
            ("watch", "add" | "remove" | "startup") => true,
            ("watch", "start" | "status" | "stop" | "reload" | "list" | "rebuild-log" | "")
            | ("config", "show" | "validate" | "")
            | ("passwords" | "doctor" | "version", "") => false,
            _ => return Err(invalid(format!("invalid action: {}", options.action))),
        };
        if wants_paths && options.paths.is_empty() {
            if !supplied || (command == "watch" && !after_action) {
                options.help = true;
            } else {
                return Err(invalid("the following arguments are required: paths"));
            }
        } else if !wants_paths && !options.paths.is_empty() {
            return Err(invalid(format!(
                "unrecognized arguments: {}",
                options.paths.join(" ")
            )));
        }
        if matches!(command, "watch" | "config") && options.action.is_empty() {
            options.help = true;
        }
        if options.action == "startup"
            && !options.help
            && (options.paths.len() != 1
                || !matches!(options.paths[0].as_str(), "enable" | "disable" | "status"))
        {
            return Err(invalid("startup expects enable, disable, or status"));
        }
        Ok(options)
    }
}

fn looks_like_option(arg: &str) -> bool {
    let Some(value) = arg.strip_prefix('-') else {
        return false;
    };
    // Numeric negative values can be passed as separate arguments, including passwords.
    !value.is_empty()
        && !value.bytes().all(|byte| byte.is_ascii_digit())
        && !value.split_once('.').is_some_and(|(integer, fraction)| {
            !fraction.is_empty()
                && integer
                    .bytes()
                    .chain(fraction.bytes())
                    .all(|byte| byte.is_ascii_digit())
        })
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
    let mut help = String::new();
    use std::fmt::Write;
    let mut entry = |option: &str, description: &str| {
        writeln!(help, "  {option:<36} {}", language.text(description)).unwrap();
    };
    if options.command.is_empty() {
        for (command, alias) in COMMANDS {
            entry(
                &format!("{command} ({alias})"),
                &format!("cli.{command}.help"),
            );
        }
    } else if options.command == "watch" && options.action.is_empty() {
        for action in [
            "start",
            "add",
            "remove",
            "list",
            "reload",
            "rebuild-log",
            "stop",
            "status",
            "startup",
        ] {
            entry(action, &format!("cli.watch.{}", action.replace('-', "_")));
        }
    } else if options.command == "config" && options.action.is_empty() {
        entry("show", "cli.config.show_help");
        entry("validate", "cli.config.validate_help");
    } else if options.command == "watch" {
        match options.action.as_str() {
            "add" => {
                entry("paths", "cli.watch.paths");
                entry("-o/--out-dir OUTPUT_DIR", "cli.watch.output_dir");
                entry("-s/--start", "cli.watch.start_after_add");
                entry("-R/--recursive", "cli.recursive_scan");
                entry("-d/--deep-detect", "cli.watch.deep_detect");
            }
            "remove" => entry("paths", "cli.watch.paths"),
            "start" => {
                entry("--once", "cli.watch.once");
                entry("--no-tray", "cli.watch.no_tray");
            }
            "startup" => entry("action", "cli.watch.startup_action"),
            _ => {}
        }
    } else if matches!(options.command, "scan" | "extract") {
        entry("paths", &format!("cli.{}.paths", options.command));
        entry("-R/--recursive", "cli.recursive_scan");
        entry("-d/--deep-detect", "cli.deep_detect");
        if options.command == "extract" {
            entry("--direct-file/--direct", "cli.extract.direct_file");
            entry("-o/--out-dir DIR", "cli.output_dir");
            entry("-f/--flatten", "cli.flatten");
            entry("-F/--no-flatten", "cli.no_flatten");
            entry("-r/--recur ROUNDS", "cli.recursive_extract");
            entry("-c/--cleanup MODE", "cli.archive_cleanup_mode");
        }
    }
    if matches!(options.command, "scan" | "extract" | "passwords") {
        entry("-p/--password PASSWORD", "cli.password");
        entry("-P/--pw-file FILE", "cli.password_file");
        entry("-a/--ask-pw", "cli.prompt_passwords");
        entry("--no-builtin-pw/--no-bpw", "cli.no_builtin_passwords");
    }
    if !matches!(options.command, "" | "version") {
        entry("-j/--json", "cli.json");
    }
    if matches!(options.command, "scan" | "extract" | "watch") {
        entry("-v/--verbose", "cli.verbose");
        entry("--no-pause", "cli.no_pause");
        entry("--pause", "cli.pause");
    }
    entry("-h/--help", "cli.help");
    session.write(Stream::Out, help.as_bytes())
}

#[derive(Serialize)]
struct CommandResult {
    command: &'static str,
    inputs: Value,
    summary: Value,
    errors: Vec<String>,
    items: Vec<Value>,
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
            tasks: Vec::new(),
            logs: Vec::new(),
        }
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

pub(super) fn run(
    host: &Host,
    cwd: &Path,
    args: Vec<String>,
    session: &dyn Session,
    cancel: Cancellation,
) -> io::Result<i32> {
    if args
        .first()
        .is_some_and(|arg| arg == "--cancel-watch-batch")
    {
        return Ok(match args.get(1) {
            Some(id) if host.watch.cancel_batch(id) => 0,
            _ => 1,
        });
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(error) => {
            line(session, Stream::Err, &format!("sunpack: error: {error}"))?;
            return Ok(2);
        }
    };
    if options.help {
        help(&options, config::load_language(cwd), session)?;
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
    drop(args);
    let generation = config::generation(cwd);
    let language = generation.language();
    let execution = match options.command {
        "scan" | "extract" => generation.normalized(true).and_then(|config| {
            host.configure_idle(&config);
            archives(host, cwd, &options, session, language, &cancel, config)
        }),
        "passwords" => generation
            .normalized(true)
            .and_then(|config| show_passwords(host, cwd, &options, session, language, config)),
        "config" => show_config(cwd, &options, session, language),
        "version" => show_version(cwd, session),
        "doctor" => doctor(cwd, session, options.json, language),
        "watch" => watch_command(host, cwd, &options, session, language),
        _ => unreachable!(),
    };
    let (code, result) = match execution {
        Ok(value) => value,
        Err(_) if cancel.cancelled() => {
            let mut result = CommandResult::new(options.command);
            result
                .errors
                .push(language.text("interrupt.finished").to_owned());
            result.summary = json!({"interrupted": true});
            (130, result)
        }
        Err(error) => {
            let mut result = CommandResult::new(options.command);
            result
                .errors
                .push(language.translate("cli.operation_failed", &[("error", &error.to_string())]));
            let code = if options.command == "watch" { 1 } else { 2 };
            (code, result)
        }
    };
    if options.json {
        write_json(session, &result)?;
    } else {
        for error in &result.errors {
            line(session, Stream::Err, error)?;
        }
        for log in &result.logs {
            line(session, Stream::Out, log)?;
        }
        if options.pause && code != 130 && (options.command != "extract" || code != 0) {
            let _ = session.read_line(language.text("cli.pause_prompt"))?;
        }
    }
    Ok(code)
}

pub(super) fn resolve(cwd: &Path, value: &str) -> io::Result<PathBuf> {
    let path = Path::new(value);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    std::path::absolute(joined)
}

fn targets(cwd: &Path, options: &Options) -> io::Result<Vec<PathBuf>> {
    options
        .paths
        .iter()
        .map(|path| resolve(cwd, path))
        .collect()
}

fn prompt_passwords(session: &dyn Session, language: Language) -> io::Result<Vec<Arc<str>>> {
    line(session, Stream::Out, language.text("cli.password_prompt"))?;
    let mut passwords = Vec::new();
    while let Some(value) = session.read_line(language.text("cli.password_input_prompt"))? {
        let value = value.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            break;
        }
        passwords.push(Arc::from(value));
    }
    Ok(passwords)
}

fn cli_passwords(
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<Vec<Arc<str>>> {
    let mut result = options.passwords.clone();
    if let Some(file) = &options.password_file {
        result = crate::password::lists::read_password_file(resolve(cwd, file)?, Some(result))?;
    }
    if options.prompt_passwords {
        result.extend(prompt_passwords(session, language)?);
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

fn confirm(session: &dyn Session, language: Language, prompt: &str) -> io::Result<bool> {
    while let Some(answer) = session.read_line(prompt)? {
        match answer.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" | "" => return Ok(false),
            _ => line(session, Stream::Out, language.text("cli.answer_yes_no"))?,
        }
    }
    Ok(false)
}

pub(super) fn depth(value: Recursion) -> usize {
    match value {
        Recursion::Infinite | Recursion::Prompt => usize::MAX,
        Recursion::Fixed(rounds) => rounds.saturating_sub(1),
    }
}

fn path_key(path: &Path) -> String {
    crate::watch_store::watch_path_key(&path.to_string_lossy())
}

fn password_failure(archive: &ArchiveResult) -> bool {
    archive
        .failure
        .as_ref()
        .is_some_and(|failure| is_password_failure(failure.kind))
}

fn is_password_failure(kind: FailureKind) -> bool {
    matches!(
        kind,
        FailureKind::PasswordRequired
            | FailureKind::WrongPassword
            | FailureKind::PasswordInconclusive
    )
}

fn failure_message(failure: &crate::pipeline::Failure, language: Language) -> &str {
    if is_password_failure(failure.kind) {
        language.text("failure.password_not_in_list")
    } else {
        &failure.message
    }
}

#[derive(Serialize)]
struct FailureReport<'a> {
    kind: FailureKind,
    message: &'a str,
    details: FailureDetails<'a>,
}

#[derive(Serialize)]
struct FailureDetails<'a> {
    path: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    promoted_nested_input: Option<bool>,
}

#[derive(Default)]
struct ArchiveSummary {
    success: usize,
    partial: usize,
    failed: usize,
    input_errors: usize,
    processed: usize,
    nested: usize,
    depth: usize,
    recovered: Vec<Value>,
    errors: Vec<String>,
}

impl ArchiveSummary {
    fn collect<'a>(
        archives: impl IntoIterator<Item = &'a ArchiveResult>,
        language: Language,
        json: bool,
    ) -> Self {
        let mut groups: BTreeMap<(String, usize), Vec<&ArchiveResult>> = BTreeMap::new();
        for archive in archives {
            groups
                .entry((path_key(&archive.path), archive.depth))
                .or_default()
                .push(archive);
        }
        let mut summary = Self {
            processed: groups.len(),
            ..Self::default()
        };
        for ((_, depth), entries) in &groups {
            summary.depth = summary.depth.max(*depth);
            summary.nested += usize::from(*depth > 1);
            let failure = entries
                .iter()
                .find_map(|entry| (!entry.partial).then_some(entry.failure.as_ref()).flatten());
            if let Some(failure) = failure {
                let invalid = failure.kind == FailureKind::InvalidInput;
                summary.input_errors += usize::from(invalid);
                summary.failed += usize::from(!invalid);
                let message = failure_message(failure, language);
                let text = format!("{}: {message}", entries[0].path.display());
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
                let outputs = entries
                    .iter()
                    .filter_map(|entry| entry.output.clone())
                    .collect::<Vec<_>>();
                let output = crate::pipeline::common_ancestor(&outputs).unwrap_or_default();
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
                let mut recovery = json!({"archive": entries[0].path, "out_dir": output, "complete_files": complete});
                if let Some(warning) = entries
                    .iter()
                    .filter_map(|entry| entry.failure.as_ref())
                    .find(|failure| failure.kind == FailureKind::MissingVolume)
                {
                    recovery["warning"] = json!({"kind": warning.kind, "message": warning.message});
                }
                summary.recovered.push(recovery);
            } else {
                summary.success += 1;
            }
        }
        summary
    }
}

fn input_error_message(error: &InputError, language: Language, json: bool) -> String {
    let text = if let Some(operation) = &error.scan_operation {
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
        (false, InputErrorKind::InvalidInput) => {
            language.translate("report.input_error", &[("task", &text)])
        }
        _ => text,
    }
}

struct Progress<'a> {
    session: &'a dyn Session,
    watch: &'a watch::Watch,
    cancel: &'a Cancellation,
    language: Language,
    display: Mutex<Display>,
    reporting: reporting::Reports,
    branches: Mutex<HashMap<PathBuf, (PathBuf, u64, String)>>,
    prompt: bool,
    visible: bool,
    verbose: bool,
}

#[derive(Default)]
struct Display {
    panel: Option<live::Panel>,
    prompting: bool,
    deferred: Vec<u8>,
}

impl Progress<'_> {
    fn run<T>(&self, execute: impl FnOnce() -> T) -> T {
        if !self.visible {
            return execute();
        }
        self.reporting.serve(
            |event| self.display_event(event),
            |id, archives| self.finish_scope(id, archives),
            execute,
        )
    }

    fn clear_panel(&self) -> io::Result<()> {
        let mut display = self.display.lock().unwrap();
        if let Some(mut panel) = display.panel.take() {
            // The launcher can already have printed its interrupt message.
            // In that case the old cursor position no longer belongs to us.
            if !self.cancel.cancelled() {
                panel.clear(self.session)?;
            }
        }
        Ok(())
    }

    fn display_event(&self, event: Event) {
        if self.cancel.cancelled() {
            return;
        }
        if self.session.interactive() {
            let mut display = self.display.lock().unwrap();
            if self.cancel.cancelled() {
                return;
            }
            let prompting = display.prompting;
            display
                .panel
                .get_or_insert_with(live::Panel::default)
                .update(self.session, self.language, event, prompting);
        } else if let Event::ResourceWait { path, state, .. } = event {
            if !state.disk {
                return;
            }
            let (status, hint) = live::wait_status(state, self.language);
            let filename = path
                .file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy();
            let _ = line(
                self.session,
                Stream::Err,
                &format!("{filename}: {status} — {hint}"),
            );
        }
    }

    fn finish_scope(&self, id: TaskId, archives: &[ArchiveResult]) -> io::Result<()> {
        let report = (!archives.is_empty()).then(|| ScopeReport::new(archives, self));
        let mut display = self.display.lock().unwrap();
        if self.cancel.cancelled() {
            return Ok(());
        }
        if let Some(panel) = &mut display.panel {
            panel.remove(id);
        }
        if display.prompting {
            if let Some(report) = report {
                report.write(&mut display.deferred)?;
            }
        } else {
            if let Some(panel) = &mut display.panel {
                panel.clear(self.session)?;
            }
            if let Some(report) = report {
                let mut writer = BufWriter::new(SessionWriter(self.session));
                report.write(&mut writer)?;
                writer.flush()?;
            }
            if let Some(panel) = &mut display.panel {
                panel.redraw(self.session, self.language, true);
            }
        }
        Ok(())
    }
}

impl Observer for Progress<'_> {
    fn worker_updates(&self) -> crate::pipeline::WorkerUpdates {
        use crate::pipeline::WorkerUpdates;
        if !self.visible {
            WorkerUpdates::None
        } else if self.session.interactive() {
            WorkerUpdates::All
        } else {
            WorkerUpdates::Resources
        }
    }

    fn notify(&self, event: Event) {
        if self.visible && !self.cancel.cancelled() {
            self.reporting.notify(event);
        }
    }

    fn archive_branch(&self, parent: &ArchiveResult, child: &ArchiveResult) {
        if self.visible {
            self.branches.lock().unwrap().insert(
                child.path.clone(),
                (parent.path.clone(), parent.offset, parent.format.clone()),
            );
        }
    }

    async fn scope_finished(
        &self,
        id: TaskId,
        archives: Vec<ArchiveResult>,
    ) -> io::Result<Vec<ArchiveResult>> {
        if self.visible {
            self.reporting.finish(id, archives).await
        } else {
            Ok(archives)
        }
    }

    fn allow_recursive(&self, depth: usize, pending: usize) -> bool {
        if !self.prompt {
            return true;
        }
        if !self.visible {
            return false;
        }
        let prompt = self.language.translate(
            "recursion.prompt",
            &[
                ("count", &pending.to_string()),
                ("round", &depth.saturating_sub(1).to_string()),
            ],
        );
        {
            let mut display = self.display.lock().unwrap();
            if let Some(panel) = &mut display.panel {
                let _ = panel.clear(self.session);
            }
            display.prompting = true;
        }
        let confirmed = confirm(self.session, self.language, &prompt).unwrap_or(false);
        let mut display = self.display.lock().unwrap();
        display.prompting = false;
        if !display.deferred.is_empty() {
            let deferred = std::mem::take(&mut display.deferred);
            let _ = self.session.write(Stream::Out, &deferred);
        }
        if !self.cancel.cancelled() {
            if let Some(panel) = &mut display.panel {
                panel.redraw(self.session, self.language, true);
            }
        }
        confirmed
    }

    fn register_output(&self, _archive: &ArchiveResult, output: &Path) -> io::Result<()> {
        self.watch.register_external_output(output)
    }

    fn before_flatten(&self, output: &Path, work: &Path, leaf: &Path) -> io::Result<()> {
        self.watch.prepare_external_flatten(output, work, leaf)
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

struct ScopeReport<'a> {
    archives: &'a [ArchiveResult],
    unicode: bool,
    language: Language,
    verbose: bool,
    groups: Vec<std::ops::Range<usize>>,
    children: Vec<Vec<usize>>,
    roots: Vec<usize>,
}

impl<'a> ScopeReport<'a> {
    fn new(archives: &'a [ArchiveResult], progress: &Progress<'a>) -> Self {
        let mut report = Self {
            archives,
            unicode: progress.session.unicode(),
            language: progress.language,
            verbose: progress.verbose,
            groups: Vec::new(),
            children: Vec::new(),
            roots: Vec::new(),
        };
        if archives.len() == 1 {
            return report;
        }
        let mut index = HashMap::new();
        for (position, item) in archives.iter().enumerate() {
            index.insert(
                (item.path.as_path(), item.offset, item.format.as_str()),
                position,
            );
            if let Some(original) = &item.promotion_original_path {
                index.insert(
                    (original.as_path(), item.offset, item.format.as_str()),
                    position,
                );
            }
        }
        report.children.resize_with(archives.len(), Vec::new);
        let mut branches = progress.branches.lock().unwrap();
        let mut start = 0;
        while let Some(item) = archives.get(start) {
            let end = start
                + archives[start..]
                    .iter()
                    .take_while(|next| next.path == item.path && next.depth == item.depth)
                    .count();
            let group = report.groups.len();
            report.groups.push(start..end);
            let parent = branches
                .remove(&item.path)
                .and_then(|(path, offset, format)| {
                    index
                        .get(&(path.as_path(), offset, format.as_str()))
                        .copied()
                });
            if let Some(parent) = parent.filter(|&parent| archives[parent].depth < item.depth) {
                report.children[parent].push(group);
            } else {
                report.roots.push(group);
            }
            start = end;
        }
        report
    }

    fn write(&self, writer: &mut impl Write) -> io::Result<()> {
        let mut prefix = String::new();
        if self.archives.len() == 1 {
            Self::title(writer, "", "", &Self::name(&self.archives[0]))?;
            return self.status_and_children(writer, 0, &mut prefix);
        }
        for &root in &self.roots {
            self.group(writer, root, &mut prefix, None)?;
        }
        Ok(())
    }

    fn name(archive: &ArchiveResult) -> Cow<'_, str> {
        archive
            .path
            .file_name()
            .unwrap_or(archive.path.as_os_str())
            .to_string_lossy()
    }

    fn group(
        &self,
        writer: &mut impl Write,
        group: usize,
        prefix: &mut String,
        last: Option<bool>,
    ) -> io::Result<()> {
        let range = self.groups[group].clone();
        let (edge, continuation) = last.map_or(("", ""), |last| tree_edge(self.unicode, last));
        let name = Self::name(&self.archives[range.start]);
        let len = prefix.len();
        Self::title(writer, prefix, edge, &name)?;
        prefix.push_str(continuation);
        if range.len() == 1 {
            self.status_and_children(writer, range.start, prefix)?;
        } else {
            let end = range.end;
            for (number, position) in range.enumerate() {
                let item = &self.archives[position];
                let label = self
                    .language
                    .translate("cli.scan.segment", &[("index", &(number + 1).to_string())]);
                let label = format!(
                    "{label} ({}) [{}, {})",
                    item.format,
                    item.offset,
                    end_offset(item)
                );
                let (edge, continuation) = tree_edge(self.unicode, position + 1 == end);
                let segment_prefix = prefix.len();
                Self::title(writer, prefix, edge, &label)?;
                prefix.push_str(continuation);
                self.status_and_children(writer, position, prefix)?;
                prefix.truncate(segment_prefix);
            }
        }
        prefix.truncate(len);
        Ok(())
    }

    fn title(writer: &mut impl Write, prefix: &str, edge: &str, label: &str) -> io::Result<()> {
        let label = if label.contains(['\r', '\n']) {
            Cow::Owned(label.replace(['\r', '\n'], " "))
        } else {
            Cow::Borrowed(label)
        };
        writeln!(writer, "{prefix}{edge}{label}")
    }

    fn status_and_children(
        &self,
        writer: &mut impl Write,
        position: usize,
        prefix: &mut String,
    ) -> io::Result<()> {
        let item = &self.archives[position];
        let (status, progress) = if item.partial {
            ("report.status.partial", "")
        } else if item.failure.is_some() {
            ("report.status.error", "")
        } else {
            ("report.status.complete", " [####################] 100%")
        };
        writeln!(
            writer,
            "{prefix}  [{}]{progress}",
            self.language.text(status)
        )?;
        if let Some(failure) = item
            .failure
            .as_ref()
            .filter(|_| !item.partial || self.verbose)
        {
            if !is_password_failure(failure.kind) {
                Self::title(
                    writer,
                    prefix,
                    "  ",
                    failure_message(failure, self.language),
                )?;
            }
        }
        if let Some(output) = item.output.as_ref().filter(|_| self.verbose) {
            let detail = self.language.translate(
                "report.detail.output",
                &[("output", &output.to_string_lossy())],
            );
            Self::title(writer, prefix, "  ", &detail)?;
        }
        if let Some(children) = self.children.get(position) {
            for (i, &child) in children.iter().enumerate() {
                self.group(writer, child, prefix, Some(i + 1 == children.len()))?;
            }
        }
        Ok(())
    }
}

fn archive_request_error(
    error: io::Error,
    inputs: &[PathBuf],
    command: &'static str,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
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

fn archives(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
    cancel: &Cancellation,
    mut settings: Config,
) -> io::Result<(i32, CommandResult)> {
    let inputs = targets(cwd, options)?;
    let engine = host.engine(cwd)?;
    let reservation = match engine.reserve_foreground(&inputs, cancel) {
        Ok(reservation) => reservation,
        Err(error) => return archive_request_error(error, &inputs, options.command, language),
    };
    let mut overrides = serde_json::Map::new();
    if let Some(value) = &options.depth {
        settings.recursive_extract = Recursion::parse(value)?;
        overrides.insert("recursive_extract".into(), json!(value));
    }
    if let Some(value) = &options.cleanup {
        settings.post_extract.archive_cleanup_mode = CleanupMode::parse(value)?;
        overrides.insert("archive_cleanup_mode".into(), json!(value));
    }
    if let Some(flatten) = options.flatten {
        settings.post_extract.flatten_single_directory = flatten;
        overrides.insert("flatten_single_directory".into(), json!(flatten));
    }
    let output = options
        .output
        .as_deref()
        .map(|value| resolve(cwd, value))
        .transpose()?;
    if let Some(path) = &output {
        overrides.insert("output_dir".into(), json!(path));
    }
    let scan = options.command == "scan";
    let mut candidate_paths = inputs.clone();
    let mut user = cli_passwords(cwd, options, session, language)?;
    let builtin = if options.no_builtins {
        None
    } else {
        Some(host.passwords(cwd)?.snapshot_for_request())
    };
    let clipboard = cli_clipboard(&settings);
    if cancel.cancelled() {
        return Err(io::ErrorKind::Interrupted.into());
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
    let progress = Progress {
        session,
        watch: &host.watch,
        cancel,
        language,
        display: Mutex::default(),
        reporting: reporting::Reports::default(),
        branches: Mutex::default(),
        prompt: settings.recursive_extract == Recursion::Prompt,
        visible: !options.json && !scan,
        verbose: options.verbose,
    };
    let max_depth = depth(settings.recursive_extract);
    let settings = Arc::new(settings);
    if !host.watch.is_running() {
        windows::configure_priority(&engine, settings.runtime.process_mode);
    }
    let _foreground = windows::Foreground::enter(&engine, &host.watch);
    let mut result = CommandResult::new(options.command);
    let mut retries = 0;
    let mut all_archives = BTreeMap::new();
    let mut all_errors: BTreeMap<_, InputError> = BTreeMap::new();
    let mut cleanup = BTreeMap::new();
    let mut checkpoints = Vec::new();
    let mut promoted_sources = Vec::new();
    let began = Instant::now();
    loop {
        let mut request = Request::new(
            std::mem::take(&mut candidate_paths),
            if scan { Mode::Scan } else { Mode::Extract },
        );
        request.output_root = output.clone();
        request.output_base = common_root.clone();
        request.max_depth = max_depth;
        request.recursive = options.recursive;
        request.direct = options.direct;
        request.deep = options.deep;
        request.passwords = user.iter().chain(&clipboard).cloned().collect();
        request.password_snapshot = builtin.clone();
        request.config = Arc::clone(&settings);
        request.cancel = cancel.clone();
        request.checkpoints = std::mem::take(&mut checkpoints);
        request.promoted_sources = std::mem::take(&mut promoted_sources);
        let current = progress.run(|| engine.run_reserved(request, &progress, &reservation));
        let cleared = progress.clear_panel();
        let current = match current {
            Ok(outcome) => outcome,
            Err(error) => return archive_request_error(error, &inputs, options.command, language),
        };
        cleared?;
        if cancel.cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if scan {
            return report_scan(current, inputs, options, session, language);
        }
        if options.json {
            let counts = ArchiveSummary::collect(&current.archives, language, true);
            let scan_errors = current
                .errors
                .iter()
                .filter(|error| error.kind == InputErrorKind::FilesystemScan)
                .map(InputError::count)
                .sum::<usize>();
            let invalid_inputs = current
                .errors
                .iter()
                .filter(|error| error.kind == InputErrorKind::InvalidInput);
            let input_errors = invalid_inputs.clone().count() + counts.input_errors;
            let failures = current
                .archives
                .iter()
                .filter_map(|archive| {
                    let failure = archive.failure.as_ref()?;
                    Some(FailureReport {
                        kind: failure.kind,
                        message: failure_message(failure, language),
                        details: FailureDetails {
                            path: &archive.path,
                            promoted_nested_input: archive.promoted.then_some(true),
                        },
                    })
                })
                .chain(invalid_inputs.map(|error| FailureReport {
                    kind: FailureKind::InvalidInput,
                    message: &error.message,
                    details: FailureDetails {
                        path: &error.path,
                        promoted_nested_input: None,
                    },
                }))
                .collect::<Vec<_>>();
            result.tasks.push(json!({
                "success_count": counts.success, "failed_count": counts.failed,
                "input_error_count": input_errors, "scan_error_count": scan_errors,
                "processed_count": counts.processed, "partial_success_count": counts.partial,
                "recovered_outputs": counts.recovered, "wrong_password_failure": current.archives.iter().any(password_failure),
                "failures": failures,
            }));
        }
        checkpoints = current.checkpoints;
        promoted_sources = current.promoted_sources;
        for receipt in current.cleanup_results {
            cleanup.insert(path_key(&receipt.path), receipt);
        }
        for archive in current.archives {
            if !options.json
                && !archive.partial
                && password_failure(&archive)
                && archive.path.exists()
            {
                candidate_paths.push(archive.path.clone());
            }
            all_archives.insert(
                (
                    path_key(&archive.path),
                    archive.offset,
                    archive.format.clone(),
                ),
                archive,
            );
        }
        for error in current.errors {
            let omitted = error.scan_operation.as_deref() == Some("report_omitted");
            let key = (
                path_key(&error.path),
                error.kind as u8,
                error.scan_operation.clone(),
                if omitted {
                    String::new()
                } else {
                    error.message.clone()
                },
            );
            match all_errors.entry(key) {
                std::collections::btree_map::Entry::Occupied(mut prior) => {
                    if error.count() > prior.get().count() {
                        prior.insert(error);
                    }
                }
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(error);
                }
            }
        }
        if candidate_paths.is_empty() {
            break;
        }
        let retry = confirm(
            session,
            language,
            language.text("cli.password_retry_prompt"),
        )?;
        if cancel.cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if !retry {
            break;
        }
        let additional = prompt_passwords(session, language)?;
        if cancel.cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
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
        retries += 1;
    }
    let counts = ArchiveSummary::collect(all_archives.values(), language, options.json);
    result.errors = counts.errors;
    let scan_errors = all_errors
        .values()
        .filter(|error| error.kind == InputErrorKind::FilesystemScan)
        .map(InputError::count)
        .sum::<usize>();
    let input_errors = all_errors
        .values()
        .filter(|error| error.kind == InputErrorKind::InvalidInput)
        .count()
        + counts.input_errors;
    result.errors.extend(
        all_errors
            .values()
            .filter(|error| error.kind != InputErrorKind::Cleanup)
            .map(|error| input_error_message(error, language, options.json)),
    );
    if !options.json && scan_errors != 0 {
        result
            .errors
            .push(language.text("report.scan_incomplete").into());
    }
    if options.json {
        result.inputs = json!({
            "paths": inputs, "common_root": common_root, "json": options.json, "verbose": options.verbose,
            "direct_file": options.direct, "deep_detect": options.deep, "config_overrides": overrides,
        });
        result.summary = json!({
            "success_count": counts.success, "failed_count": counts.failed, "scan_error_count": scan_errors,
            "scan_failures": all_errors.values().filter(|error| error.kind == InputErrorKind::FilesystemScan).collect::<Vec<_>>(),
            "input_error_count": input_errors, "processed_count": counts.processed,
            "partial_success_count": counts.partial, "recovered_outputs": counts.recovered, "use_builtin_passwords": !options.no_builtins,
            "password_retry_count": retries, "cleanup_results": cleanup.values().collect::<Vec<_>>(),
        });
        let failure_details: Vec<_> = all_archives
            .values()
            .filter_map(|entry| {
                let failure = entry.failure.as_ref()?;
                failure.evidence.as_ref()?;
                Some(
                    json!({"path": entry.path, "depth": entry.depth, "offset": entry.offset,
                "end_offset": entry.end_offset, "partial": entry.partial, "failure": failure}),
                )
            })
            .collect();
        if !failure_details.is_empty() {
            result.summary["failure_details"] = Value::Array(failure_details);
        }
        result.items.push(password_item(
            &user,
            &clipboard,
            &engine.recent_passwords(),
            builtin.as_deref(),
            !options.no_builtins,
        ));
    } else {
        line(session, Stream::Out, &format!("\n{}", "-".repeat(54)))?;
        let elapsed = began.elapsed().as_secs();
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
                    ("failed", &counts.failed.to_string()),
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
        let mut outputs = all_archives
            .values()
            .filter(|item| item.depth == 1 && (item.failure.is_none() || item.partial))
            .filter_map(|item| item.output.as_deref())
            .peekable();
        if outputs.peek().is_some() {
            let location = crate::pipeline::common_ancestor(outputs);
            let display = location.as_deref().map_or_else(
                || Cow::Borrowed(language.text("report.multiple_locations")),
                Path::to_string_lossy,
            );
            line(
                session,
                Stream::Out,
                &language.translate("report.output", &[("output", &display)]),
            )?;
        }
        for recovery in &counts.recovered {
            let archive = recovery["archive"].as_str().unwrap_or_default();
            let name = Path::new(archive)
                .file_name()
                .unwrap_or(std::ffi::OsStr::new(archive))
                .to_string_lossy();
            let complete = recovery["complete_files"]
                .as_u64()
                .unwrap_or_default()
                .to_string();
            line(
                session,
                Stream::Out,
                &language.translate(
                    "report.partial",
                    &[("archive", &name), ("complete_files", &complete)],
                ),
            )?;
            if let Some(warning) = recovery["warning"]["message"].as_str() {
                line(
                    session,
                    Stream::Out,
                    &language.translate("report.partial_warning", &[("warning", warning)]),
                )?;
            }
        }
        if counts.partial > 0 && result.errors.is_empty() {
            line(
                session,
                Stream::Out,
                language.text("report.partial_complete"),
            )?;
        }
        let cleanup_failures = cleanup
            .values()
            .filter(|receipt| receipt.status == CleanupStatus::Failed)
            .count();
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
        }
        line(session, Stream::Out, &"-".repeat(54))?;
    }
    Ok((i32::from(!result.errors.is_empty()), result))
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
        .map(InputError::count)
        .sum::<usize>();
    let input_errors = outcome
        .errors
        .iter()
        .filter(|error| error.kind == InputErrorKind::InvalidInput)
        .count();
    let mut rows: Vec<_> = outcome
        .archives
        .into_iter()
        .map(|entry| (path_key(&entry.path), entry))
        .collect();
    rows.sort_unstable_by(|(ka, a), (kb, b)| {
        ka.cmp(kb)
            .then(a.offset.cmp(&b.offset))
            .then(a.format.cmp(&b.format))
    });
    let mut result = CommandResult::new("scan");
    let mut failed = 0;
    let mut archive_input_errors = 0;
    let mut has_archive_errors = false;
    let mut start = 0;
    while start < rows.len() {
        let key = &rows[start].0;
        let end = start
            + rows[start..]
                .iter()
                .take_while(|(path, _)| path == key)
                .count();
        let group = &rows[start..end];
        if let Some(failure) = group.iter().find_map(|(_, entry)| entry.failure.as_ref()) {
            has_archive_errors = true;
            if failure.kind == FailureKind::InvalidInput {
                archive_input_errors += 1;
            } else {
                failed += 1;
            }
        }
        if !options.json {
            line(session, Stream::Out, &group[0].1.path.to_string_lossy())?;
        }
        for (index, (_, entry)) in group.iter().enumerate() {
            let embedded = entry.offset != 0 || entry.end_offset.is_some();
            let show_password = entry.encrypted == Some(true)
                || entry.password.is_some()
                || password_failure(entry);
            let plan = entry.volume_attempts.as_deref();
            let completeness = if plan.is_some() {
                Some(if entry.volume_completeness.as_deref() == Some("missing") {
                    "missing"
                } else {
                    "pending"
                })
            } else {
                entry.volume_completeness.as_deref()
            };
            let show_parts =
                plan.is_none() && (entry.source_paths.len() > 1 || completeness.is_some());
            if let Some(failure) = &entry.failure {
                let text = format!("{}: {}", entry.path.display(), failure.message);
                if options.json {
                    result.errors.push(text);
                } else if !(password_failure(entry) && entry.password.is_none())
                    && !(failure.kind == FailureKind::MissingVolume
                        && entry.volume_completeness.as_deref() == Some("missing"))
                {
                    let error =
                        language.translate("cli.scan.error", &[("error", &failure.message)]);
                    let text = if embedded {
                        format!(
                            "{}: [{}, {}): {error}",
                            entry.path.display(),
                            entry.offset,
                            end_offset(entry)
                        )
                    } else {
                        format!("{}: {error}", entry.path.display())
                    };
                    line(session, Stream::Err, &text)?;
                }
            }
            if options.json {
                let input_id = format!(
                    "{}|{}|{}",
                    path_key(&entry.path),
                    entry.format,
                    entry.offset
                );
                let mut item =
                    json!({"main_path": entry.path, "format": entry.format, "input_id": input_id});
                let obj = item.as_object_mut().unwrap();
                if let Some(failure) = entry
                    .failure
                    .as_ref()
                    .filter(|failure| failure.evidence.is_some())
                {
                    obj.insert("failure".into(), json!(failure));
                }
                if embedded {
                    obj.insert("offset".into(), json!(entry.offset));
                    obj.insert("end_offset".into(), json!(entry.end_offset));
                }
                if show_password {
                    obj.insert("password_used".into(), json!(entry.password));
                }
                if let Some(plan) = plan {
                    obj.insert("volume_attempts".into(), json!(plan));
                } else if show_parts {
                    obj.insert("all_parts".into(), json!(entry.source_paths));
                }
                if let Some(value) = completeness {
                    obj.insert("volume_completeness".into(), json!(value));
                }
                if options.verbose {
                    obj.insert("discovery_source".into(), json!(entry.discovery_source));
                    if let Some(flags) = &entry.damage_flags {
                        obj.insert("damage_flags".into(), json!(flags));
                    }
                }
                if let Some(failure) = &entry.failure {
                    obj.insert("error".into(), json!(failure.message));
                    obj.insert("error_kind".into(), json!(failure.kind));
                }
                result.items.push(item);
            } else {
                let multiple = group.len() > 1;
                let last = index + 1 == group.len();
                let (edge, prefix) = if !multiple {
                    ("", "  ")
                } else {
                    tree_edge(session.unicode(), last)
                };
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
                let format = language.translate("cli.scan.format", &[("format", &entry.format)]);
                line(session, Stream::Out, &format!("{prefix}{format}"))?;
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
                        crate::pipeline::DiscoverySource::Direct => "direct",
                    };
                    let text = language.translate("cli.scan.source", &[("source", source)]);
                    line(session, Stream::Out, &format!("{prefix}{text}"))?;
                    if let Some(flags) = &entry.damage_flags {
                        let text =
                            language.translate("cli.scan.damage", &[("flags", &flags.join(", "))]);
                        line(session, Stream::Out, &format!("{prefix}{text}"))?;
                    }
                }
            }
        }
        start = end;
    }
    for error in outcome.errors {
        result
            .errors
            .push(input_error_message(&error, language, options.json));
    }
    if !options.json && scan_errors != 0 {
        result
            .errors
            .push(language.text("report.scan_incomplete").into());
    }
    if options.json {
        result.inputs = json!({"paths": inputs, "deep_detect": options.deep});
        result.summary = json!({
            "archive_count": rows.len(), "failed_count": failed,
            "scan_error_count": scan_errors, "input_error_count": input_errors + archive_input_errors,
        });
    }
    Ok((
        i32::from(has_archive_errors || !result.errors.is_empty()),
        result,
    ))
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

fn password_item(
    user: &[Arc<str>],
    clipboard: &[Arc<str>],
    recent: &[Arc<str>],
    snapshot: Option<&passwords::PasswordSnapshot>,
    use_builtin: bool,
) -> Value {
    let builtin = snapshot.map_or(&[][..], passwords::PasswordSnapshot::global);
    let configured = user
        .iter()
        .chain(clipboard)
        .map(Arc::as_ref)
        .chain(builtin.iter().map(AsRef::as_ref));
    let mut eligible_recent = HashSet::new();
    if !recent.is_empty() {
        let mut wanted: HashSet<&str> = recent.iter().map(AsRef::as_ref).collect();
        for value in configured.clone() {
            if wanted.remove(value) {
                eligible_recent.insert(value);
                if wanted.is_empty() {
                    break;
                }
            }
        }
    }
    let mut seen = HashSet::new();
    let combined: Vec<_> = recent
        .iter()
        .map(AsRef::as_ref)
        .filter(|value| eligible_recent.contains(value))
        .chain(configured)
        .filter(|value| seen.insert(*value))
        .collect();
    json!({"user_passwords":user,"recent_passwords":recent,"clipboard_passwords":clipboard,
        "builtin_passwords":builtin,"use_builtin_passwords":use_builtin,"combined_passwords":combined})
}

fn show_passwords(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
    settings: Config,
) -> io::Result<(i32, CommandResult)> {
    let user = cli_passwords(cwd, options, session, language)?;
    let clipboard = cli_clipboard(&settings);
    let snapshot = if options.no_builtins {
        None
    } else {
        Some(host.passwords(cwd)?.snapshot_for_request())
    };
    let item = password_item(
        &user,
        &clipboard,
        &[],
        snapshot.as_deref(),
        !options.no_builtins,
    );
    let count = |field: &str| item[field].as_array().map_or(0, Vec::len);
    let mut result = CommandResult::new("passwords");
    result.inputs = json!({"json":options.json,"use_builtin_passwords":!options.no_builtins});
    result.summary = json!({
        "user_password_count": count("user_passwords"), "recent_password_count": 0,
        "clipboard_password_count": count("clipboard_passwords"), "builtin_password_count": count("builtin_passwords"),
        "combined_password_count": count("combined_passwords"),
    });
    if !options.json {
        line(session, Stream::Out, language.text("cli.passwords.summary"))?;
        for (key, field) in [
            ("user_input", "user_passwords"),
            ("recent", "recent_passwords"),
            ("clipboard", "clipboard_passwords"),
            ("builtin", "builtin_passwords"),
            ("final_order", "combined_passwords"),
        ] {
            let value = item[field]
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(|value| {
                            format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let text = language.translate(
                &format!("cli.passwords.{key}"),
                &[("value", &format!("[{value}]"))],
            );
            line(session, Stream::Out, &text)?;
        }
    }
    result.items.push(item);
    Ok((0, result))
}

fn show_config(
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("config");
    result.inputs = json!({"action": options.action});
    if options.rule_stdin {
        let input = session.read_line("")?.ok_or(io::ErrorKind::UnexpectedEof)?;
        let rule = serde_json::from_str(&input)?;
        config::PathRule::parse(&rule)?;
        result.summary = json!({"valid": true});
        return Ok((0, result));
    }
    let (path, payload) = config::load_raw(cwd)?;
    result.summary = json!({"config_path": path, "changed": false});
    if let Err(error) = Config::parse(&payload) {
        if options.action == "show" {
            return Err(error);
        }
        let message = language.translate(
            "cli.config.validation_error",
            &[("error", &error.to_string())],
        );
        result.summary["valid"] = Value::Bool(false);
        result.errors.push(message);
        result
            .items
            .push(json!({"ok": false, "errors":[error.to_string()], "warnings": []}));
        return Ok((2, result));
    }
    if options.action == "show" {
        if !options.json {
            write_json(session, &payload)?;
        }
        result.items.push(payload);
    } else {
        if !options.json {
            line(
                session,
                Stream::Out,
                language.text("cli.config.valid_config"),
            )?;
        }
        result
            .items
            .push(json!({"ok": true, "errors": [], "warnings": []}));
    }
    Ok((0, result))
}

fn show_version(cwd: &Path, session: &dyn Session) -> io::Result<(i32, CommandResult)> {
    let path = std::env::current_exe()?.with_file_name("VERSION.txt");
    let text = std::fs::read_to_string(path)
        .or_else(|_| std::fs::read_to_string(cwd.join("VERSION.txt")))?;
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
    session: &dyn Session,
    json_output: bool,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("doctor");
    result.items = super::doctor::checks(cwd)?;
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

fn watch_command(
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
        "start" if options.once => {
            code = host.watch.run_once(cwd, host.engine(cwd)?)?;
            result.inputs["once"] = Value::Bool(true);
            result.summary = json!({"exit_code": code});
        }
        "start" => result.summary = host.watch.start(cwd, host.engine(cwd)?, !options.no_tray)?,
        "stop" => result.summary = host.watch.stop()?,
        "reload" => result.summary = host.watch.reload()?,
        "add" => {
            let paths = targets(cwd, options)?;
            let output = options.output.as_deref();
            result.inputs = json!({
                "action": "add", "paths": paths, "output_dir": output,
                "deep_detect": options.deep.then_some(true),
            });
            if output.is_some() && paths.len() != 1 {
                result
                    .errors
                    .push(language.text("cli.watch.output_dir_single_path").into());
                return Ok((2, result));
            }
            result.summary =
                host.watch
                    .add(cwd, &paths, output, options.deep, options.recursive)?;
            result.summary["start_requested"] = Value::Bool(options.start);
            if options.start && !host.watch.is_running() {
                result.summary["start"] = host.watch.start(cwd, host.engine(cwd)?, true)?;
                let (_, effective) = host.watch.roots(cwd)?;
                let effective: HashSet<_> = effective.iter().map(|path| path_key(path)).collect();
                let mut rejected = Vec::new();
                for name in ["added", "updated"] {
                    if let Some(paths) = result.summary[name].as_array_mut() {
                        paths.retain(|path| {
                            let present = path.as_str().is_some_and(|value| {
                                effective.contains(&path_key(Path::new(value)))
                            });
                            if !present {
                                rejected.push(path.clone());
                            }
                            present
                        });
                    }
                }
                if let Some(previous) = result.summary["rejected"].as_array_mut() {
                    previous.extend(rejected);
                }
            }
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
            result.inputs["paths"] = json!(paths);
            result.summary = host.watch.remove(cwd, &paths)?;
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
                    let message = if status["running"] == true {
                        "cli.watch.running"
                    } else {
                        "cli.watch.stopped"
                    };
                    line(session, Stream::Out, language.text(message))?;
                }
                status
            };
        }
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
                            "cli.watch.startup_enabled"
                        } else {
                            "cli.watch.startup_disabled"
                        };
                        line(session, Stream::Out, language.text(message))?;
                    }
                    json!({"enabled":value.is_some(),"command":value.unwrap_or_default()})
                }
            };
        }
        "rebuild-log" => {
            let rebuilt = host.watch.rebuild_log(cwd)?;
            result.summary = json!({"rebuilt": rebuilt});
            let key = if rebuilt {
                "cli.watch.rebuild_log_done"
            } else {
                "cli.watch.rebuild_log_failed"
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
