use super::{watch, windows, Session, Stream};
use crate::core::config::{self, CleanupMode, Config, Recursion};
use crate::core::i18n::Language;
use crate::core::{passwords, resources};
use crate::pipeline::{
    ArchiveResult, Cancellation, CleanupStatus, Engine, Event, FailureKind, InputErrorKind, Mode,
    Observer, Outcome, Request,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

pub(super) struct Host {
    engine: OnceLock<Arc<Engine>>,
    passwords: Mutex<Option<Arc<passwords::BuiltinStore>>>,
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
            watch: watch::Watch::new(Arc::new(wake)),
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
    passwords: Vec<String>,
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
    fn parse(argv: Vec<String>) -> io::Result<Self> {
        let mut args = VecDeque::from(argv);
        let Some(command) = args.pop_front() else {
            return Ok(Self {
                help: true,
                ..Self::default()
            });
        };
        if matches!(command.as_str(), "-h" | "--help") {
            return Ok(Self {
                help: true,
                ..Self::default()
            });
        }
        let command = COMMANDS
            .iter()
            .find(|(name, alias)| command == *name || command == *alias)
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
            if positional || !arg.starts_with('-') || arg == "-" {
                if matches!(command, "watch" | "config") && options.action.is_empty() {
                    options.action = match (command, arg.as_str()) {
                        ("watch", "rm") => "remove".into(),
                        ("watch", "ls") => "list".into(),
                        ("watch", "st") => "status".into(),
                        _ => arg,
                    };
                } else {
                    after_action = true;
                    options.paths.push(arg);
                }
                continue;
            }
            if !arg.starts_with("--") && arg.len() > 2 && arg.as_bytes()[1].is_ascii() {
                if b"pPocr".contains(&arg.as_bytes()[1]) {
                    if arg.as_bytes()[2] != b'=' {
                        arg.insert(2, '=');
                    }
                } else if b"jvRdfFash".contains(&arg.as_bytes()[1]) {
                    args.push_front(format!("-{}", &arg[2..]));
                    arg.truncate(2);
                }
            }
            after_action |= !options.action.is_empty();
            let (flag, inline) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(flag, value)| (flag, Some(value)));
            let mut take = || {
                inline
                    .map(str::to_owned)
                    .or_else(|| args.pop_front())
                    .ok_or_else(|| invalid(format!("{flag} expects a value")))
            };
            let archives = matches!(command, "extract" | "scan");
            let watch_add = command == "watch" && options.action == "add";
            let watch_start = command == "watch" && options.action == "start";
            let common = archives || command == "watch";
            let passwords = archives || command == "passwords";
            match flag {
                "-h" | "--help" => {
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
                    let value = take()?;
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
                    options.passwords.push(take()?);
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
    let language = config::load_language(cwd);
    let options = match Options::parse(args) {
        Ok(options) => options,
        Err(error) => {
            line(session, Stream::Err, &format!("sunpack: error: {error}"))?;
            return Ok(2);
        }
    };
    if options.help {
        help(&options, language, session)?;
        return Ok(0);
    }
    let execution = match options.command {
        "scan" | "extract" => archives(host, cwd, &options, session, language, &cancel),
        "passwords" => show_passwords(host, cwd, &options, session, language),
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
        if options.pause {
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

fn prompt_passwords(session: &dyn Session, language: Language) -> io::Result<Vec<String>> {
    line(session, Stream::Out, language.text("cli.password_prompt"))?;
    let mut passwords = Vec::new();
    while let Some(value) = session.read_line(language.text("cli.password_input_prompt"))? {
        let value = value.trim_end_matches(['\r', '\n']);
        if value.is_empty() {
            break;
        }
        passwords.push(value.to_owned());
    }
    Ok(passwords)
}

fn cli_passwords(
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<Vec<String>> {
    let mut result = options.passwords.clone();
    if let Some(file) = &options.password_file {
        result = crate::password::lists::read_password_file(
            resolve(cwd, file)?,
            Some(result.into_iter().map(Arc::from).collect()),
        )?
        .into_iter()
        .map(|value| value.to_string())
        .collect();
    }
    if options.prompt_passwords {
        if options.json {
            return Err(invalid(
                language.text("cli.json_password_prompt_unavailable"),
            ));
        }
        result.extend(prompt_passwords(session, language)?);
    }
    dedupe(&mut result);
    Ok(result)
}

fn dedupe(values: &mut Vec<String>) {
    let mut seen = HashSet::with_capacity(values.len());
    let mut keep = values
        .iter()
        .map(|value| seen.insert(value.as_str()))
        .collect::<Vec<_>>()
        .into_iter();
    values.retain(|_| keep.next().unwrap_or(false));
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

fn common_root(paths: &[PathBuf]) -> PathBuf {
    let mut root = paths
        .first()
        .and_then(|path| path.parent())
        .unwrap_or(Path::new(""))
        .to_owned();
    for path in paths.iter().skip(1) {
        while !crate::watch_store::is_path_under(&path_key(path), &path_key(&root)) {
            if !root.pop() {
                return root;
            }
        }
    }
    root
}

fn password_failure(archive: &ArchiveResult) -> bool {
    archive.failure.as_ref().is_some_and(|failure| {
        matches!(
            failure.kind,
            FailureKind::PasswordRequired
                | FailureKind::WrongPassword
                | FailureKind::PasswordInconclusive
        )
    })
}

#[derive(Default)]
struct ArchiveSummary {
    success: usize,
    partial: usize,
    failed: usize,
    processed: usize,
    recovered: Vec<Value>,
    errors: Vec<String>,
}

impl ArchiveSummary {
    fn collect<'a>(
        archives: impl IntoIterator<Item = &'a ArchiveResult>,
        language: Language,
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
        for entries in groups.values() {
            let failure = entries
                .iter()
                .find_map(|entry| (!entry.partial).then_some(entry.failure.as_ref()).flatten());
            if let Some(failure) = failure {
                summary.failed += 1;
                let message = if matches!(
                    failure.kind,
                    FailureKind::PasswordRequired
                        | FailureKind::WrongPassword
                        | FailureKind::PasswordInconclusive
                ) {
                    language.text("failure.password_not_in_list")
                } else {
                    failure.message.as_str()
                };
                summary
                    .errors
                    .push(format!("{}: {message}", entries[0].path.display()));
            } else if entries.iter().any(|entry| entry.partial) {
                summary.partial += 1;
                let outputs = entries
                    .iter()
                    .filter_map(|entry| entry.output.clone())
                    .collect::<Vec<_>>();
                let output = if outputs.len() == 1 {
                    outputs.first().cloned().unwrap_or_default()
                } else {
                    common_root(&outputs)
                };
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
                    recovery["warning"] = json!(warning);
                }
                summary.recovered.push(recovery);
            } else {
                summary.success += 1;
            }
        }
        summary
    }
}

struct Progress<'a> {
    session: &'a dyn Session,
    watch: &'a watch::Watch,
    language: Language,
    last: Mutex<Option<Instant>>,
    prompt: bool,
    visible: bool,
}

impl Observer for Progress<'_> {
    fn notify(&self, event: Event) {
        if !self.visible || !self.session.interactive() {
            return;
        }
        match event {
            Event::Progress {
                path,
                completed_bytes,
                total_bytes,
            } if total_bytes != 0 => {
                let mut last = self.last.lock().unwrap();
                let now = Instant::now();
                if last.is_some_and(|last| now.duration_since(last) < Duration::from_millis(100)) {
                    return;
                }
                *last = Some(now);
                let width = self.session.columns().saturating_sub(35).clamp(6, 40);
                let filled = ((completed_bytes as u128 * width as u128 / total_bytes as u128)
                    as usize)
                    .min(width);
                let filename = path
                    .file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy();
                let available = self.session.columns().saturating_sub(width + 10);
                let filename: String = filename.chars().take(available).collect();
                let percent = (completed_bytes as u128 * 100 / total_bytes as u128).min(100);
                let bar = format!(
                    "\r\x1b[2K{filename} [{}{}] {percent:3}%",
                    "=".repeat(filled),
                    " ".repeat(width - filled)
                );
                let _ = self.session.write(Stream::Out, bar.as_bytes());
            }
            Event::Finished { .. } => {
                let _ = self.session.write(Stream::Out, b"\r\x1b[2K");
            }
            _ => {}
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
        confirm(self.session, self.language, &prompt).unwrap_or(false)
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

fn archives(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
    cancel: &Cancellation,
) -> io::Result<(i32, CommandResult)> {
    let inputs = targets(cwd, options)?;
    let mut settings = config::load(cwd)?;
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
        Some(host.passwords(cwd)?.reload()?)
    };
    let clipboard = if settings.passwords.clipboard_passwords_enabled {
        passwords::clipboard_passwords()
    } else {
        Vec::new()
    };
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
        }
        if session.interactive() {
            line(session, Stream::Out, language.text("interrupt.hint"))?;
        }
    }
    let progress = Progress {
        session,
        watch: &host.watch,
        language,
        last: Mutex::new(None),
        prompt: settings.recursive_extract == Recursion::Prompt,
        visible: !options.json,
    };
    let max_depth = depth(settings.recursive_extract);
    let settings = Arc::new(settings);
    let engine = host.engine(cwd)?;
    if !host.watch.is_running() {
        windows::configure_priority(&engine, settings.runtime.process_mode);
    }
    let _foreground = windows::Foreground::enter(&engine);
    let mut result = CommandResult::new(options.command);
    let mut retries = 0;
    let mut all_archives = BTreeMap::new();
    let mut all_errors = BTreeMap::new();
    let mut cleanup = BTreeMap::new();
    let mut checkpoints = Vec::new();
    let began = Instant::now();
    loop {
        let mut request = Request::new(
            std::mem::take(&mut candidate_paths),
            if scan { Mode::Scan } else { Mode::Extract },
        );
        request.output_root = output.clone();
        request.max_depth = max_depth;
        request.recursive = options.recursive;
        request.direct = options.direct;
        request.deep = options.deep;
        request.passwords = user.clone();
        request.passwords.extend(clipboard.iter().cloned());
        request.password_snapshot = builtin.clone();
        request.config = Arc::clone(&settings);
        request.cancel = cancel.clone();
        request.checkpoints = std::mem::take(&mut checkpoints);
        let current = match engine.run_with(request, &progress) {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(conflict) = error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<crate::pipeline::BusyConflict>())
                {
                    let watch_busy = conflict.origin == crate::pipeline::Origin::Watch;
                    let status = if watch_busy { "watch_busy" } else { "busy" };
                    let key = if watch_busy {
                        "cli.watch_busy"
                    } else {
                        "cli.archive_busy"
                    };
                    let mut result = CommandResult::new(options.command);
                    result.inputs = json!({"paths":inputs});
                    result.summary = json!({"status":status,"conflicts":conflict.paths});
                    result.errors.push(language.text(key).to_owned());
                    return Ok((1, result));
                }
                return Err(error);
            }
        };
        if cancel.cancelled() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if scan {
            return report_scan(current, inputs, options, session, language);
        }
        let counts = ArchiveSummary::collect(&current.archives, language);
        let scan_errors = current
            .errors
            .iter()
            .filter(|error| error.kind == InputErrorKind::FilesystemScan)
            .count();
        let input_errors = current
            .errors
            .iter()
            .filter(|error| error.kind == InputErrorKind::InvalidInput)
            .count();
        result.tasks.push(json!({
            "success_count": counts.success, "failed_count": counts.failed,
            "input_error_count": input_errors, "scan_error_count": scan_errors,
            "processed_count": counts.processed, "partial_success_count": counts.partial,
            "recovered_outputs": counts.recovered, "wrong_password_failure": current.archives.iter().any(password_failure),
            "failures": current.archives.iter().filter_map(|entry| entry.failure.as_ref()).collect::<Vec<_>>(),
        }));
        checkpoints = current.checkpoints;
        for receipt in current.cleanup_results {
            cleanup.insert(path_key(&receipt.path), receipt);
        }
        for archive in current.archives {
            if !archive.partial && password_failure(&archive) && archive.path.exists() {
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
            all_errors.insert((path_key(&error.path), error.kind as u8), error);
        }
        if candidate_paths.is_empty()
            || options.json
            || !confirm(
                session,
                language,
                language.text("cli.password_retry_prompt"),
            )?
        {
            break;
        }
        let additional = prompt_passwords(session, language)?;
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
    let counts = ArchiveSummary::collect(all_archives.values(), language);
    result.errors = counts.errors;
    for item in all_archives.values() {
        if item.failure.is_none() || item.partial {
            if !options.json {
                if let Some(output) = &item.output {
                    line(
                        session,
                        Stream::Out,
                        &format!("{} → {}", item.path.display(), output.display()),
                    )?;
                }
            }
        }
    }
    let scan_errors = all_errors
        .values()
        .filter(|error| error.kind == InputErrorKind::FilesystemScan)
        .count();
    let input_errors = all_errors
        .values()
        .filter(|error| error.kind == InputErrorKind::InvalidInput)
        .count();
    result.errors.extend(
        all_errors
            .values()
            .filter(|error| error.kind != InputErrorKind::Cleanup)
            .map(|error| format!("{}: {}", error.path.display(), error.message)),
    );
    result.inputs = json!({
        "paths": inputs, "common_root": common_root(&inputs), "json": options.json, "verbose": options.verbose,
        "direct_file": options.direct, "deep_detect": options.deep, "config_overrides": overrides,
    });
    result.summary = json!({
        "success_count": counts.success, "failed_count": counts.failed, "scan_error_count": scan_errors,
        "scan_failures": all_errors.values().filter(|error| error.kind == InputErrorKind::FilesystemScan).collect::<Vec<_>>(),
        "input_error_count": input_errors, "processed_count": counts.processed,
        "partial_success_count": counts.partial, "recovered_outputs": counts.recovered, "use_builtin_passwords": !options.no_builtins,
        "password_retry_count": retries, "cleanup_results": cleanup.values().collect::<Vec<_>>(),
    });
    if !options.json {
        line(session, Stream::Out, &format!("\n{}", "-".repeat(54)))?;
        let duration = format!("{:.2}s", began.elapsed().as_secs_f64());
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
        if let Some(output) = output.as_deref() {
            line(
                session,
                Stream::Out,
                &language.translate("report.output", &[("output", &output.to_string_lossy())]),
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
            line(
                session,
                Stream::Err,
                &language.translate(
                    "cleanup.incomplete",
                    &[("count", &cleanup_failures.to_string())],
                ),
            )?;
        }
    }
    result.items.push(password_item(
        &user,
        &clipboard,
        builtin.as_deref(),
        !options.no_builtins,
    ));
    Ok((i32::from(!result.errors.is_empty()), result))
}

fn report_scan(
    outcome: Outcome,
    inputs: Vec<PathBuf>,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let failed = outcome.failed();
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
    result.inputs = json!({"paths": inputs, "deep_detect": options.deep});
    result.summary = json!({
        "archive_count": rows.len(), "failed_count": failed,
        "scan_error_count": scan_errors, "input_error_count": input_errors,
    });
    let mut start = 0;
    while start < rows.len() {
        let key = &rows[start].0;
        let end = start
            + rows[start..]
                .iter()
                .take_while(|(path, _)| path == key)
                .count();
        let group = &rows[start..end];
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
                } else if !password_failure(entry)
                    && !(failure.kind == FailureKind::MissingVolume
                        && entry.volume_completeness.as_deref() == Some("missing"))
                {
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
                } else if session.unicode() {
                    if last {
                        ("└─ ", "   ")
                    } else {
                        ("├─ ", "│  ")
                    }
                } else if last {
                    ("\\---", "    ")
                } else {
                    ("+---", "|   ")
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
            .push(format!("{}: {}", error.path.display(), error.message));
    }
    Ok((i32::from(failed != 0), result))
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
    user: &[String],
    clipboard: &[String],
    snapshot: Option<&passwords::PasswordSnapshot>,
    use_builtin: bool,
) -> Value {
    let builtin = snapshot.map_or(&[][..], passwords::PasswordSnapshot::global);
    let mut seen = HashSet::new();
    let combined: Vec<_> = user
        .iter()
        .chain(clipboard)
        .map(String::as_str)
        .chain(builtin.iter().map(AsRef::as_ref))
        .filter(|value| seen.insert(*value))
        .collect();
    let builtin: Vec<_> = builtin.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
    json!({"user_passwords":user,"recent_passwords":[],"clipboard_passwords":clipboard,
        "builtin_passwords":builtin,"use_builtin_passwords":use_builtin,"combined_passwords":combined})
}

fn show_passwords(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let settings = config::load(cwd)?;
    let user = cli_passwords(cwd, options, session, language)?;
    let clipboard = if settings.passwords.clipboard_passwords_enabled {
        passwords::clipboard_passwords()
    } else {
        Vec::new()
    };
    let snapshot = if options.no_builtins {
        None
    } else {
        Some(host.passwords(cwd)?.reload()?)
    };
    let item = password_item(&user, &clipboard, snapshot.as_deref(), !options.no_builtins);
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
    if options.action == "show" {
        if !options.json {
            write_json(session, &payload)?;
        }
        result.items.push(payload);
    } else {
        if let Err(error) = Config::parse(&payload) {
            let message = language.translate(
                "cli.config.validation_error",
                &[("error", &error.to_string())],
            );
            result.summary["valid"] = Value::Bool(false);
            result.errors.push(message);
            result
                .items
                .push(json!({"ok": false, "errors":[error.to_string()]}));
            return Ok((2, result));
        }
        if !options.json {
            line(
                session,
                Stream::Out,
                language.text("cli.config.valid_config"),
            )?;
        }
        result.items.push(json!({"ok": true, "errors": []}));
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
            if output.is_some() && paths.len() != 1 {
                return Err(invalid(language.text("cli.watch.output_dir_single_path")));
            }
            result.inputs = json!({"action": "add", "paths": paths, "output_dir": output, "deep_detect": options.deep});
            result.summary =
                host.watch
                    .add(cwd, &paths, output, options.deep, options.recursive)?;
            result.summary["start_requested"] = Value::Bool(options.start);
            if options.start && !host.watch.is_running() {
                result.summary["start"] = host.watch.start(cwd, host.engine(cwd)?, true)?;
            }
            result.items = result.summary["added"]
                .as_array()
                .cloned()
                .unwrap_or_default();
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
