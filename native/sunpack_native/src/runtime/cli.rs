use super::{watch, windows, Session, Stream};
use crate::core::config::{self, CleanupMode, Config, Recursion};
use crate::core::i18n::Language;
use crate::core::{passwords, resources};
use crate::io::cancellation::is_cancellation;
use crate::pipeline::{
    ArchiveResult, Cancellation, CleanupStatus, Engine, Event, FailureKind, InputError,
    InputErrorKind, Mode, Observer, Outcome, Request, TaskId, TaskStatus,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, BufWriter, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

mod live;
mod failures;
mod json;
pub(super) mod reporting;

pub(super) struct Host {
    pub(super) scheduler: Arc<crate::pipeline::Scheduler>,
    engine: OnceLock<Arc<Engine>>,
    passwords: Mutex<Option<Arc<passwords::BuiltinStore>>>,
    idle: Mutex<Duration>,
    pub(super) watch: Arc<watch::Watch>,
}

impl Host {
    pub(super) fn new() -> Self {
        Self::with_wake(|| {})
    }

    pub(super) fn with_wake(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self {
            scheduler: crate::pipeline::Scheduler::new(),
            engine: OnceLock::new(),
            passwords: Mutex::default(),
            idle: Mutex::new(Duration::from_secs_f64(config::default_idle_seconds())),
            watch: Arc::new(watch::Watch::new(Arc::new(wake))),
        }
    }

    pub(super) fn idle_after(&self) -> Duration {
        *self.idle.lock().unwrap()
    }

    pub(super) fn configure_idle(&self, settings: &Config) {
        if let Some(idle) = settings
            .performance
            .persistent_server_idle_seconds
            .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
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
            self.engine.get_or_init(|| Arc::new(Engine::with_scheduler(worker, Arc::clone(&self.scheduler)))),
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
        let mut unrecognized = Vec::new();
        let command = loop {
            let Some(arg) = args.pop_front() else {
                if !unrecognized.is_empty() { return Err(parser_error("", "", "the following arguments are required: command")); }
                return Ok(Self { help: true, ..Self::default() });
            };
            if arg == "--" {
                break args.pop_front().ok_or_else(|| parser_error("", "", "the following arguments are required: command"))?;
            }
            if !looks_like_option(&arg) { break arg; }
            if arg.starts_with("-h") && !arg.starts_with("--") {
                validate_short_cluster(&arg, args.front().map(|arg| arg.as_ref()), "", "")?;
                return Ok(Self { help: true, ..Self::default() });
            }
            let (flag, inline) = arg.split_once('=').map_or((arg.as_ref(), None), |(f, v)| (f, Some(v)));
            if flag == "-h" || flag == "--help" {
                if let Some(value) = inline { return Err(explicit_argument("", "", flag, value)); }
                return Ok(Self { help: true, ..Self::default() });
            }
            unrecognized.push(arg.into_owned());
        };
        let command = COMMANDS
            .iter()
            .find(|(name, alias)| command.as_ref() == *name || command.as_ref() == *alias)
            .map(|(name, _)| *name)
            .ok_or_else(|| invalid_choice("", "", "command", &command, "extract, e, watch, w, scan, s, passwords, pw, config, cfg, doctor, d, version, ver"))?;
        let mut options = Self {
            command,
            ..Self::default()
        };
        let mut positional = false;
        let mut supplied = false;
        let mut after_action = false;
        let mut paths_closed = false;
        // argparse reports unknown arguments only after processing actions;
        // a later help action may exit successfully first.
        while let Some(mut arg) = args.pop_front() {
            supplied = true;
            if arg == "--" && !positional {
                if paths_closed { unrecognized.push("--".to_owned()); }
                after_action |= !options.action.is_empty();
                positional = true;
                continue;
            }
            if positional || !looks_like_option(&arg) {
                if matches!(command, "watch" | "config") && options.action.is_empty() {
                    // argparse's selected subparser installs fresh common defaults.
                    // main restores only exact raw argv flags after parsing below.
                    options.json = false;
                    options.verbose = false;
                    options.pause = false;
                    options.no_pause = false;
                    positional = false;
                    let action = match (command, arg.as_ref()) {
                        ("watch", "rm") => "remove".into(),
                        ("watch", "ls") => "list".into(),
                        ("watch", "st") => "status".into(),
                        _ => arg.into_owned(),
                    };
                    if !matches!((command, action.as_str()),
                        ("watch", "add" | "remove" | "startup" | "start" | "status" | "stop" | "reload" | "list" | "rebuild-log")
                        | ("config", "show" | "validate"))
                    {
                        return Err(invalid_choice(command, "", &format!("{command}_action"), &action, if command == "watch" { "start, add, remove, rm, list, ls, reload, rebuild-log, stop, status, st, startup" } else { "show, validate" }));
                    }
                    options.action = action;
                } else {
                    if paths_closed {
                        unrecognized.push(arg.into_owned());
                        continue;
                    }
                    after_action = true;
                    if !matches!(command, "extract" | "scan")
                        && !(command == "watch" && matches!(options.action.as_str(), "add" | "remove" | "startup"))
                    {
                        unrecognized.push(arg.into_owned());
                        continue;
                    }
                    if command == "watch" && options.action == "startup" {
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
                    .ok_or_else(|| argument_error(command, &options.action, flag, "expected one argument"))
            };
            let archives = matches!(command, "extract" | "scan");
            let watch_add = command == "watch" && options.action == "add";
            let watch_start = command == "watch" && options.action == "start";
            let common = archives || command == "watch";
            let passwords = archives || command == "passwords";
            match flag {
                "-h" | "--help" => {
                    if let Some(value) = inline {
                        return Err(explicit_argument(command, &options.action, flag, value));
                    }
                    options.help = true;
                    break;
                }
                "-j" | "--json" if command != "version" => options.json = true,
                "-v" | "--verbose" if common => options.verbose = true,
                "--pause" if common => {
                    if let Some(value) = inline { return Err(explicit_argument(command, &options.action, flag, value)); }
                    if options.no_pause { return Err(argument_error(command, &options.action, "--pause", "not allowed with argument --no-pause")); }
                    options.pause = true;
                }
                "--no-pause" if common => {
                    if let Some(value) = inline { return Err(explicit_argument(command, &options.action, flag, value)); }
                    if options.pause { return Err(argument_error(command, &options.action, "--no-pause", "not allowed with argument --pause")); }
                    options.no_pause = true;
                }
                "-R" | "--recursive" if archives || watch_add => options.recursive = true,
                "-d" | "--deep-detect" if archives || watch_add => options.deep = true,
                "--direct" | "--direct-file" if command == "extract" => options.direct = true,
                "-f" | "--flatten" if command == "extract" => {
                    if let Some(value) = inline { return Err(explicit_argument(command, &options.action, flag, value)); }
                    if options.flatten == Some(false) { return Err(argument_error(command, &options.action, "-f", "not allowed with argument -F/--no-flatten")); }
                    options.flatten = Some(true)
                }
                "-F" | "--no-flatten" if command == "extract" => {
                    if let Some(value) = inline { return Err(explicit_argument(command, &options.action, flag, value)); }
                    if options.flatten == Some(true) { return Err(argument_error(command, &options.action, "-F", "not allowed with argument -f/--flatten")); }
                    options.flatten = Some(false)
                }
                "-r" | "--recur" if command == "extract" => {
                    let value = take()?.trim().to_owned();
                    Recursion::parse(&value).map_err(|error| argument_error(command, &options.action, flag, &error.to_string()))?;
                    options.depth = Some(value);
                    continue;
                }
                "-c" | "--cleanup" if command == "extract" => {
                    let value = take()?.trim().to_ascii_lowercase();
                    CleanupMode::parse(&value).map_err(|error| argument_error(command, &options.action, flag, &error.to_string()))?;
                    options.cleanup = Some(value);
                    continue;
                }
                "-o" | "--out-dir" if command == "extract" || watch_add => {
                    // Extract treats an empty destination as absent; watch must
                    // retain explicit presence for its single-root validation.
                    options.output = Some(take()?).filter(|value| command != "extract" || !value.is_empty());
                    continue;
                }
                "-p" | "--password" if passwords => {
                    options.passwords.push(take()?.into());
                    continue;
                }
                "-P" | "--pw-file" if passwords => {
                    options.password_file = Some(take()?).filter(|value| !value.is_empty());
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
                _ => {
                    unrecognized.push(arg.into_owned());
                    continue;
                }
            }
            if let Some(value) = inline {
                return Err(explicit_argument(command, &options.action, flag, value));
            }
        }
        let wants_paths = match (command, options.action.as_str()) {
            ("extract" | "scan", "") => true,
            ("watch", "add" | "remove" | "startup") => true,
            ("watch", "start" | "status" | "stop" | "reload" | "list" | "rebuild-log" | "")
            | ("config", "show" | "validate" | "")
            | ("passwords" | "doctor" | "version", "") => false,
            _ => return Err(invalid(format!("invalid action: {}", options.action))),
        };
        if options.help {
            return Ok(options);
        }
        if options.no_pause && options.pause {
            return Err(argument_error(command, &options.action, "--no-pause", "not allowed with argument --pause"));
        }
        if wants_paths && options.paths.is_empty() {
            if !supplied || (command == "watch" && !after_action) {
                options.help = true;
            } else {
                return Err(parser_error(command, &options.action, if options.action == "startup" { "the following arguments are required: action" } else { "the following arguments are required: paths" }));
            }
        }
        if matches!(command, "watch" | "config") && options.action.is_empty() {
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
        // Deliberately match main's raw argv restoration, including option-
        // shaped positional paths after `--`. Do not rewrite the values themselves.
        for argument in argv {
            match argument.as_str() {
                "-j" | "--json" => options.json = true,
                "-v" | "--verbose" => options.verbose = true,
                "--pause" => options.pause = true,
                _ => {}
            }
        }
        Ok(options)
    }
}

// argparse validates the arity of an entire short-option cluster before
// executing any of its actions, including help. Unknown suffixes are deferred.
fn validate_short_cluster(arg: &str, next: Option<&str>, command: &str, action: &str) -> io::Result<()> {
    if !arg.starts_with('-') || arg.starts_with("--") || arg.len() <= 2 { return Ok(()); }
    let archives = matches!(command, "extract" | "scan");
    let common = archives || command == "watch";
    let passwords = archives || command == "passwords";
    let watch_add = command == "watch" && action == "add";
    for index in 1..arg.len() {
        let flag = arg.as_bytes()[index];
        let takes_value = match flag {
            b'h' => false,
            b'j' if !command.is_empty() && command != "version" => false,
            b'v' if common => false,
            b'R' | b'd' if archives || watch_add => false,
            b'f' | b'F' if command == "extract" => false,
            b'a' if passwords => false,
            b's' if watch_add => false,
            b'r' | b'c' if command == "extract" => true,
            b'o' if command == "extract" || watch_add => true,
            b'p' | b'P' if passwords => true,
            _ => break,
        };
        let tail = &arg[index + 1..]; // recognized option letters are ASCII
        if takes_value {
            if tail.is_empty() && next.is_none_or(looks_like_option) {
                return Err(argument_error(command, action, &format!("-{}", char::from(flag)), "expected one argument"));
            }
            break;
        }
        if tail.starts_with('=') || tail.starts_with('-') {
            return Err(explicit_argument(command, action, &format!("-{}", char::from(flag)), tail.strip_prefix('=').unwrap_or(tail)));
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

fn argument_name(flag: &str) -> &str {
    match flag {
        "-h" | "--help" => "-h/--help",
        "-j" | "--json" => "-j/--json",
        "-v" | "--verbose" => "-v/--verbose",
        "-p" | "--password" => "-p/--password",
        "-P" | "--pw-file" => "-P/--pw-file",
        "-a" | "--ask-pw" => "-a/--ask-pw",
        "--no-builtin-pw" | "--no-bpw" => "--no-builtin-pw/--no-bpw",
        "-R" | "--recursive" => "-R/--recursive",
        "-d" | "--deep-detect" => "-d/--deep-detect",
        "-r" | "--recur" => "-r/--recur",
        "-c" | "--cleanup" => "-c/--cleanup",
        "-o" | "--out-dir" => "-o/--out-dir",
        "-f" | "--flatten" => "-f/--flatten",
        "-F" | "--no-flatten" => "-F/--no-flatten",
        "-s" | "--start" => "-s/--start",
        "--direct-file" | "--direct" => "--direct-file/--direct",
        _ => flag,
    }
}

fn argument_error(command: &str, action: &str, flag: &str, message: &str) -> io::Error {
    parser_error(command, action, format!("argument {}: {message}", argument_name(flag)))
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
    let mut optional = vec![("-h/--help".to_owned(), "cli.help".to_owned())];
    if options.command.is_empty() {
        for (command, alias) in COMMANDS {
            positional.push((format!("{command} ({alias})"), format!("cli.{command}.help")));
        }
    } else {
        if options.command != "version" {
            optional.push(("-j/--json".into(), "cli.json".into()));
        }
        if matches!(options.command, "scan" | "extract" | "watch") {
            optional.extend([
                ("-v/--verbose".into(), "cli.verbose".into()),
                ("--no-pause".into(), "cli.no_pause".into()),
                ("--pause".into(), "cli.pause".into()),
            ]);
        }
        if matches!(options.command, "scan" | "extract") {
            positional.push(("paths".into(), format!("cli.{}.paths", options.command)));
            optional.extend([
                ("-R/--recursive".into(), "cli.recursive_scan".into()),
                ("-d/--deep-detect".into(), "cli.deep_detect".into()),
            ]);
        }
        if matches!(options.command, "scan" | "extract" | "passwords") {
            optional.extend([
                ("-p/--password PASSWORD".into(), "cli.password".into()),
                ("-P/--pw-file PASSWORD_FILE".into(), "cli.password_file".into()),
                ("-a/--ask-pw".into(), "cli.prompt_passwords".into()),
                ("--no-builtin-pw/--no-bpw".into(), "cli.no_builtin_passwords".into()),
            ]);
        }
        match options.command {
            "extract" => optional.extend([
                ("-r/--recur RECURSIVE_EXTRACT".into(), "cli.recursive_extract".into()),
                ("-c/--cleanup ARCHIVE_CLEANUP_MODE".into(), "cli.archive_cleanup_mode".into()),
                ("-o/--out-dir OUTPUT_DIR".into(), "cli.output_dir".into()),
                ("-f/--flatten".into(), "cli.flatten".into()),
                ("-F/--no-flatten".into(), "cli.no_flatten".into()),
                ("--direct-file/--direct".into(), "cli.extract.direct_file".into()),
            ]),
            "watch" => match options.action.as_str() {
                "" => {
                    for (action, label) in [
                        ("start", "start"), ("add", "add"), ("remove", "remove (rm)"),
                        ("list", "list (ls)"), ("reload", "reload"), ("rebuild-log", "rebuild-log"),
                        ("stop", "stop"), ("status", "status (st)"), ("startup", "startup"),
                    ] {
                        positional.push((label.into(), format!("cli.watch.{}", action.replace('-', "_"))));
                    }
                }
                "add" => {
                    positional.push(("paths".into(), "cli.watch.paths".into()));
                    optional.extend([
                        ("-o/--out-dir OUTPUT_DIR".into(), "cli.watch.output_dir".into()),
                        ("-s/--start".into(), "cli.watch.start_after_add".into()),
                        ("-R/--recursive".into(), "cli.recursive_scan".into()),
                        ("-d/--deep-detect".into(), "cli.watch.deep_detect".into()),
                    ]);
                }
                "remove" => positional.push(("paths".into(), "cli.watch.paths".into())),
                "startup" => positional.push(("action".into(), "cli.watch.startup_action".into())),
                "start" => optional.extend([
                    ("--once".into(), "cli.watch.once".into()),
                    ("--no-tray".into(), "cli.watch.no_tray".into()),
                ]),
                _ => {}
            },
            "config" if options.action.is_empty() => positional.extend([
                ("show".into(), "cli.config.show_help".into()),
                ("validate".into(), "cli.config.validate_help".into()),
            ]),
            _ => {}
        }
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
    tasks: Vec<Value>,
    logs: Vec<String>,
    config_order: Option<config::order::Order>,
    emitted_errors: usize,
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
            config_order: None,
            emitted_errors: 0,
        }
    }

    fn emit_errors(&mut self, session: &dyn Session) -> io::Result<()> {
        for error in &self.errors[self.emitted_errors..] {
            line(session, Stream::Err, error)?;
            self.emitted_errors += 1;
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

pub(super) async fn run(
    host: &Host,
    cwd: &Path,
    args: Vec<String>,
    owned_session: Arc<dyn Session>,
    cancel: Cancellation,
) -> io::Result<i32> {
    let session = owned_session.as_ref();
    crate::pipeline::stage("cli", &Cancellation::new()).await?;
    if args
        .first()
        .is_some_and(|arg| arg == "--cancel-watch-batch")
    {
        return Ok(match args.get(1) {
            Some(id) if host.watch.cancel_batch_async(id).await => 0,
            _ => 1,
        });
    }
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(error) => {
            line(session, Stream::Err, &error.to_string())?;
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
        if options.passwords.is_empty() {
            result.inputs = json!({"argv": args});
        }
        result
            .errors
            .push(language.text("cli.json_password_prompt_unavailable").into());
        write_json(session, &result)?;
        return Ok(2);
    }
    // main's archive dispatch errors retain argv, but config/password handlers
    // catch their own failures and return an empty command-input envelope.
    let error_argv = (options.json && matches!(options.command, "scan" | "extract")
        && options.passwords.is_empty()).then_some(args);
    let generation = config::generation(cwd);
    let language = generation.language();
    let execution = match options.command {
        "scan" | "extract" => match generation.normalized(true) {
            Ok(config) => {
                host.configure_idle(&config);
                archives(host, cwd, &options, Arc::clone(&owned_session), language, &cancel, config).await
            }
            Err(error) => Err(error),
        },
        "passwords" => match generation.normalized(true) {
            Ok(config) => show_passwords(host, cwd, &options, session, language, config).await,
            Err(error) => Err(error),
        },
        "config" => show_config(cwd, &options, session, language).await,
        "version" => show_version(session),
        "doctor" => doctor(cwd, session, options.json, language),
        "watch" => watch_command(host, cwd, &options, session, language, &cancel).await,
        _ => unreachable!(),
    };
    crate::pipeline::stage("cli_output", &Cancellation::new()).await?;
    let (code, mut result) = match execution {
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
                "watch" => (1, "cli.operation_failed"),
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
            && session.input_is_terminal()
            && code != 130
            && (options.command != "extract" || code != 0)
        {
            let _ = session.aread_line(language.text("cli.pause_prompt")).await?;
        }
    }
    session.drain().await?;
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
    let mut result = CommandResult::new(options.command);
    if let Some(paths) = inputs {
        result.inputs = json!({"paths": paths});
    }
    result.summary = json!({"interrupted": true, "cleanup_complete": clean});
    result.errors = cleanup_errors;
    Ok((130, result))
}

pub(super) fn resolve(cwd: &Path, value: &str) -> io::Result<PathBuf> {
    let path = Path::new(value);
    if path.is_absolute() {
        return std::path::absolute(path);
    }
    let mut components = path.components();
    let relative = match (components.next(), cwd.components().next()) {
        (Some(Component::Prefix(target)), Some(Component::Prefix(base)))
            if matches!((target.kind(), base.kind()),
                (Prefix::Disk(target), Prefix::Disk(base) | Prefix::VerbatimDisk(base))
                    if target.eq_ignore_ascii_case(&base)) =>
        {
            // A same-drive relative path uses the requesting client's directory.
            components.as_path()
        }
        _ => path,
    };
    std::path::absolute(cwd.join(relative))
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

// Retry inputs are physical paths, even when a formerly nested carrier is
// retried as a root and its successful segments collapse to a sparse summary.
fn remove_replaced_archives(
    archives: &mut BTreeMap<(String, u64, String), ArchiveResult>,
    current: &[ArchiveResult],
) {
    let replaced: std::collections::HashSet<_> = current.iter()
        .map(|archive| path_key(&archive.path)).collect();
    archives.retain(|(path, _, _), _| !replaced.contains(path));
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
                let message = failures::carrier_message(entries, language);
                let path = &entries[0].path;
                let task = if invalid || entries.iter().any(|entry| entry.promoted) {
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
                    .find(|failure| failure.kind == FailureKind::MissingVolume
                        || failure.evidence.as_deref().is_some_and(|e| e.possible_missing_volume))
                {
                    recovery["warning"] = json!({"kind": warning.kind, "message": failure_message(warning, language)});
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

struct Progress {
    session: Arc<dyn Session>,
    watch: Arc<watch::Watch>,
    cancel: Cancellation,
    language: Language,
    display: Mutex<Display>,
    reporting: reporting::Reports,
    branches: Mutex<HashMap<PathBuf, (PathBuf, u64, String)>>,
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
    deferred: Vec<u8>,
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

    fn finish_scope(&self, id: TaskId, archives: &[ArchiveResult]) -> io::Result<()> {
        let mut display = self.display.lock().unwrap();
        if self.cancel.cancelled() {
            return Ok(());
        }
        // Do not render the completion events only to immediately clear them.
        self.apply_events(&mut display, false);
        // main flushes its existing task rows. In particular, skipped preflight
        // segments are display facts, not synthetic successful ArchiveResults.
        let retained_display = !archives.is_empty() && display.panel.as_ref().is_some_and(|panel| panel.retains_scope(id));
        if retained_display {
            // This path writes the retained task tree instead of ScopeReport,
            // but the completed scope still owns and releases its branch links.
            let mut branches = self.branches.lock().unwrap();
            for archive in archives { branches.remove(&archive.path); }
        }
        let report = (!retained_display && !archives.is_empty()).then(|| {
            let latest = display.panel.as_ref().map(|panel| panel.scope_progress(id)).unwrap_or_default();
            ScopeReport::new(archives, self, latest)
        });
        if display.prompting {
            let Display { panel, deferred, .. } = &mut *display;
            if retained_display {
                panel.as_ref().unwrap().write_scope(id, self.session.unicode(), self.language, deferred)?;
            } else if let Some(report) = report { report.write(deferred)?; }
        } else {
            if let Some(panel) = &mut display.panel { panel.clear(self.session.as_ref())?; }
            if retained_display || report.is_some() {
                let mut writer = BufWriter::new(SessionWriter(self.session.as_ref()));
                if retained_display {
                    display.panel.as_ref().unwrap().write_scope(id, self.session.unicode(), self.language, &mut writer)?;
                } else if let Some(report) = report { report.write(&mut writer)?; }
                writer.flush()?;
            }
        }
        if let Some(panel) = &mut display.panel { panel.remove(id); }
        if !display.prompting {
            if let Some(panel) = &mut display.panel { panel.redraw(self.session.as_ref(), self.language, true); }
        }
        Ok(())
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
            crate::pipeline::stage("report", &Cancellation::new()).await?;
            self.finish_scope(id, &archives)?;
        }
        Ok(archives)
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
        let mut display = self.display.lock().unwrap();
        display.prompting = false;
        if !display.deferred.is_empty() {
            let deferred = std::mem::take(&mut display.deferred);
            let _ = self.session.write(Stream::Out, &deferred);
        }
        if !self.cancel.cancelled() {
            if let Some(panel) = &mut display.panel {
                panel.redraw(self.session.as_ref(), self.language, true);
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

    fn after_flatten(&self, old: &Path, output: &Path) -> io::Result<()> {
        self.watch.finish_external_flatten(output)?;
        if self.visible {
            // Use the same lock order as flush_events. A queued Finished must
            // not restore its old path after the visible rows were relocated.
            let mut display = self.display.lock().unwrap();
            self.reporting.relocate_outputs(old, output);
            if let Some(panel) = &mut display.panel {
                panel.relocate_outputs(old, output);
            }
        }
        Ok(())
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
    progress: HashMap<(PathBuf, Option<u64>), (u64, u64)>,
    archives: &'a [ArchiveResult],
    unicode: bool,
    language: Language,
    verbose: bool,
    groups: Vec<std::ops::Range<usize>>,
    children: Vec<Vec<usize>>,
    roots: Vec<usize>,
}

impl<'a> ScopeReport<'a> {
    fn new(archives: &'a [ArchiveResult], progress: &Progress, latest: HashMap<(PathBuf, Option<u64>), (u64, u64)>) -> Self {
        let mut report = Self {
            progress: latest,
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
        enum Visit {
            Group(usize, Option<bool>),
            Segment(usize, usize, bool),
            Archive(usize, bool),
            Restore(usize),
        }
        let mut prefix = String::new();
        let mut pending = Vec::new();
        if self.archives.len() == 1 {
            Self::title(writer, "", "", &Self::name(&self.archives[0]))?;
            pending.push(Visit::Archive(0, false));
        } else {
            pending.extend(self.roots.iter().rev().map(|&root| Visit::Group(root, None)));
        }
        while let Some(visit) = pending.pop() {
            match visit {
                Visit::Restore(len) => prefix.truncate(len),
                Visit::Group(group, last) => {
                    let range = self.groups[group].clone();
                    let (edge, continuation) = last.map_or(("", ""), |last| tree_edge(self.unicode, last));
                    Self::title(writer, &prefix, edge, &Self::name(&self.archives[range.start]))?;
                    pending.push(Visit::Restore(prefix.len()));
                    prefix.push_str(continuation);
                    if range.len() == 1 {
                        pending.push(Visit::Archive(range.start, false));
                    } else {
                        let result = crate::pipeline::TaskCompletion::from_group(&self.archives[range.clone()]);
                        if result.status == TaskStatus::Failed {
                            let status = live::status_text(self.language.text(task_status_key(result.status)), None, "", None);
                            writeln!(writer, "{prefix}  {status}")?;
                            if let Some(detail) = task_detail(result.status, result.failure.as_ref(), None, false, self.verbose, self.language) {
                                Self::title(writer, &prefix, "  ", &detail)?;
                            }
                        }
                        let end = range.end;
                        for (number, position) in range.enumerate().rev() {
                            pending.push(Visit::Segment(position, number + 1, position + 1 == end));
                        }
                    }
                }
                Visit::Segment(position, number, last) => {
                    let item = &self.archives[position];
                    let label = self.language.translate("cli.scan.segment", &[("index", &number.to_string())]);
                    let label = format!("{label} ({}) [{}, {})", item.format, item.offset, end_offset(item));
                    let (edge, continuation) = tree_edge(self.unicode, last);
                    Self::title(writer, &prefix, edge, &label)?;
                    pending.push(Visit::Restore(prefix.len()));
                    prefix.push_str(continuation);
                    pending.push(Visit::Archive(position, true));
                }
                Visit::Archive(position, segment) => {
                    self.status(writer, position, &prefix, segment)?;
                    if let Some(children) = self.children.get(position) {
                        for (index, &child) in children.iter().enumerate().rev() {
                            pending.push(Visit::Group(child, Some(index + 1 == children.len())));
                        }
                    }
                }
            }
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

    fn title(writer: &mut impl Write, prefix: &str, edge: &str, label: &str) -> io::Result<()> {
        let label = single_line(label);
        writeln!(writer, "{prefix}{edge}{label}")
    }

    fn status(
        &self,
        writer: &mut impl Write,
        position: usize,
        prefix: &str,
        segment: bool,
    ) -> io::Result<()> {
        let item = &self.archives[position];
        let status = task_status_key(TaskStatus::of(item));
        let last = if item.partial || item.failure.is_some() {
            [&item.path].into_iter().chain(item.promotion_original_path.iter()).find_map(|path| {
                self.progress.get(&(path.clone(), Some(item.offset)))
                    .or_else(|| self.progress.get(&(path.clone(), None))).copied()
            })
        } else { Some((1, 1)) };
        let status = live::status_text(self.language.text(status), last, "", None);
        writeln!(writer, "{prefix}  {status}")?;
        if let Some(detail) = task_detail(TaskStatus::of(item), item.failure.as_ref(), None, segment, self.verbose, self.language) {
            Self::title(writer, prefix, "  ", &detail)?;
        }
        if let Some(output) = item.output.as_ref().filter(|_| self.verbose) {
            let detail = self.language.translate(
                "report.detail.output",
                &[("output", &output.to_string_lossy())],
            );
            Self::title(writer, prefix, "  ", &detail)?;
        }
        Ok(())
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
    discovery: Option<(crate::pipeline::DiscoverySource, &'a Path)>,
    segment: bool, verbose: bool, language: Language,
) -> Option<Cow<'a, str>> {
    let failure = failure?;
    let discovery = discovery.or_else(|| match failure.context.as_deref() {
        Some(crate::pipeline::FailureContext::Discovery { discovery, path, .. }) => Some((*discovery, path.as_path())),
        _ => None,
    });
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
    let builtin = if options.no_builtins {
        None
    } else {
        Some(host.passwords(cwd)?.snapshot_for_request())
    };
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
    let progress = Arc::new(Progress {
        session: Arc::clone(&owned_session),
        watch: Arc::clone(&host.watch),
        cancel: cancel.clone(),
        language,
        display: Mutex::default(),
        reporting: reporting::Reports::default(),
        branches: Mutex::default(),
        prompt: settings.recursive_extract == Recursion::Prompt,
        visible: !options.json && !scan,
        verbose: options.verbose,
    });
    let max_depth = depth(settings.recursive_extract);
    let settings = Arc::new(settings);
    if !host.watch.is_running() {
        windows::configure_priority_async(&engine, settings.runtime.process_mode).await;
    }
    let foreground = windows::Foreground::enter_async(&engine, &host.watch).await;
    let execution = async {
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
        progress.reporting.reopen();
        let _report_close = ReportClose(&progress.reporting);
        let reporting = if progress.visible {
            let progress = Arc::clone(&progress);
            Some(engine.spawn_control(crate::pipeline::Origin::Foreground, &Cancellation::new(), async move {
                progress.reporting.serve_async(|| progress.flush_events()).await;
            }))
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
                .filter(|receipt| {
                    receipt.mode == "rollback" && receipt.status == CleanupStatus::Failed
                })
                .map(|receipt| format!("{}: {}", receipt.path.display(), receipt.message))
                .collect();
            return interrupted(options, session, language, Some(&inputs), errors);
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
            let mut failures = failures::collect(&current.archives, language);
            failures.extend(invalid_inputs.map(failures::Report::invalid));
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
        remove_replaced_archives(&mut all_archives, &current.archives);
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
        retries += 1;
    }
    crate::pipeline::stage("cli_output", &Cancellation::new()).await?;
    let counts = ArchiveSummary::collect(all_archives.values(), language, options.json);
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
    // main emits scan failures before discovered target failures.
    for kind in [InputErrorKind::FilesystemScan, InputErrorKind::InvalidInput] {
        result.errors.extend(all_errors.values().filter(|error| error.kind == kind)
            .map(|error| input_error_message(error, language, options.json)));
    }
    result.errors.extend(counts.errors);
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
            "scan_failures": all_errors.values().filter(|error| error.kind == InputErrorKind::FilesystemScan).map(|error| failures::Report::filesystem_scan(error, language)).collect::<Vec<_>>(),
            "input_error_count": input_errors, "processed_count": counts.processed,
            "partial_success_count": counts.partial, "recovered_outputs": counts.recovered, "use_builtin_passwords": !options.no_builtins,
            "password_retry_count": retries, "cleanup_results": cleanup.values().collect::<Vec<_>>(),
        });
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
        result.emit_errors(session)?;
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
            for receipt in cleanup.values().filter(|receipt| receipt.status == CleanupStatus::Failed) {
                line(session, Stream::Err, &format!("  {}: {}", receipt.path.display(), receipt.message))?;
            }
        }
        line(session, Stream::Out, &"-".repeat(54))?;
    }
    Ok((i32::from(!result.errors.is_empty()), result))
    };
    let result = settle_unwind(execution).await;
    foreground.finish_async().await;
    match result { Ok(result) => result, Err(panic) => std::panic::resume_unwind(panic) }
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
            if options.json {
                if let Some(failure) = &entry.failure {
                    result.errors.push(format!("{}: {}", entry.path.display(), failure_message(failure, language)));
                }
            }
            if options.json {
                let input_id = format!(
                    "{}|{}|{}",
                    path_key(&entry.path),
                    entry.format,
                    entry.offset
                );
                let mut item = json!({"main_path": entry.path, "input_id": input_id});
                let obj = item.as_object_mut().unwrap();
                if !entry.format.is_empty() {
                    obj.insert("format".into(), json!(entry.format));
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
                    if let Some(flags) = entry.damage_flags.as_ref().filter(|flags| !flags.is_empty()) {
                        obj.insert("damage_flags".into(), json!(flags));
                    }
                }
                if let Some(failure) = &entry.failure {
                    obj.insert("error".into(), json!(failure_message(failure, language)));
                    obj.insert("error_kind".into(), json!(failure.kind));
                }
                result.items.push(item);
            } else {
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
                    if !(password_failure(entry) && entry.password.is_none())
                        && !(failure.kind == FailureKind::MissingVolume
                            && entry.volume_completeness.as_deref() == Some("missing"))
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
                        crate::pipeline::DiscoverySource::Direct => "direct",
                    };
                    let text = language.translate("cli.scan.source", &[("source", source)]);
                    line(session, Stream::Out, &format!("{prefix}{text}"))?;
                    if let Some(flags) = entry.damage_flags.as_ref().filter(|flags| !flags.is_empty()) {
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

// The command displays Python-style list values, as main does. Escape only
// their textual representation; the candidates themselves remain unchanged.
fn password_repr(value: &str) -> String {
    static NON_PRINTABLE: OnceLock<regex::Regex> = OnceLock::new();
    let non_printable = NON_PRINTABLE.get_or_init(|| regex::Regex::new(r"[\p{C}\p{Z}]").unwrap());
    let quote = if value.contains('\'') && !value.contains('"') { '"' } else { '\'' };
    let mut text = String::with_capacity(value.len() + 2);
    text.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => text.push_str("\\\\"),
            '\t' => text.push_str("\\t"),
            '\n' => text.push_str("\\n"),
            '\r' => text.push_str("\\r"),
            c if c == quote => { text.push('\\'); text.push(c); }
            c if c != ' ' && non_printable.is_match(c.encode_utf8(&mut [0; 4])) => {
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
                        .map(password_repr)
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

async fn show_config(
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("config");
    result.inputs = json!({"action": options.action});
    if options.rule_stdin {
        let input = session.aread_line("").await?.ok_or(io::ErrorKind::UnexpectedEof)?;
        crate::pipeline::stage("cli", &Cancellation::new()).await?;
        let rule = serde_json::from_str(&input)?;
        config::PathRule::parse(&rule)?.compile()?;
        result.summary = json!({"valid": true});
        return Ok((0, result));
    }
    crate::pipeline::stage("cli", &Cancellation::new()).await?;
    let (path, payload, order) = if options.action == "show" {
        let (path, payload, order) = config::load_raw_ordered(cwd)?;
        (path, payload, Some(order))
    } else {
        let (path, payload) = config::load_raw(cwd)?;
        (path, payload, None)
    };
    result.summary = json!({"config_path": path, "changed": false});
    let errors = match Config::parse(&payload)? {
        _ if options.action == "show" => {
            // The persistent runtime validates configuration before dispatch,
            // even when show returns the original, unnormalized document.
            if !options.json {
                write_json(session, &config::order::Ordered(&payload, order.as_ref().unwrap()))?;
            }
            result.config_order = order;
            result.items.push(payload);
            return Ok((0, result));
        }
        settings => settings.validate_scan_filters(),
    };
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

async fn watch_command(
    host: &Host,
    cwd: &Path,
    options: &Options,
    session: &dyn Session,
    language: Language,
    cancel: &Cancellation,
) -> io::Result<(i32, CommandResult)> {
    let mut result = CommandResult::new("watch");
    result.inputs = json!({"action": options.action});
    let mut code = 0;
    match options.action.as_str() {
        "start" if options.once => {
            code = host.watch.run_once_async(cwd, host.engine(cwd)?, cancel).await?;
            result.inputs["once"] = Value::Bool(true);
            result.summary = json!({"exit_code": code});
        }
        "start" => result.summary = host.watch.start_async(cwd, host.engine(cwd)?, !options.no_tray).await?,
        "stop" => result.summary = host.watch.stop_async().await?,
        "reload" => result.summary = host.watch.reload_async().await?,
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
                    .add_async(cwd, &paths, output, options.deep, options.recursive).await?;
            result.summary["start_requested"] = Value::Bool(options.start);
            if options.start && !host.watch.is_running() {
                result.summary["start"] = host.watch.start_async(cwd, host.engine(cwd)?, true).await?;
                crate::pipeline::stage("cli", &Cancellation::new()).await?;
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
            let rebuilt = host.watch.rebuild_log_async(cwd).await?;
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

#[cfg(test)]
mod option_tests {
    use super::*;

    #[test]
    fn password_display_escapes_controls_without_changing_candidates() {
        assert_eq!(password_repr("a\t\0\n\r\\z"), "'a\\t\\x00\\n\\r\\\\z'");
        assert_eq!(password_repr("can't"), "\"can't\"");
        assert_eq!(password_repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(password_repr("\u{4e2d}\u{6587}\u{2028}"), "'\u{4e2d}\u{6587}\\u2028'");
    }

    // One parser-level regression covers resolution, value consumption and
    // subparser boundaries; no worker/filesystem is needed for these failures.
    #[test]
    fn argparse_option_resolution_and_boundaries() {
        let parse = |args: &[&str]| Options::parse(&args.iter().map(|s| (*s).into()).collect::<Vec<_>>());
        let value = parse(&["extract", "--no-builtin-pw", "--password=-secret", "--out-dir=dest", "file.zip"]).unwrap();
        assert!(value.no_builtins);
        assert_eq!(value.passwords[0].as_ref(), "-secret");
        assert_eq!(value.output.as_deref(), Some("dest"));
        assert_eq!(value.paths, ["file.zip"]);
        assert!(parse(&["extract", "--direct", "file.zip"]).unwrap().direct);
        for args in [
            vec!["extract", "a.zip", "--cle", "d"],
            vec!["scan", "a.zip", "--recurs"],
            vec!["--hel"],
        ] { assert!(parse(&args).is_err(), "{args:?}"); }
        assert!(parse(&["watch", "--json", "status"]).unwrap().json);
        assert!(parse(&["watch", "--verbose", "status"]).unwrap().verbose);
        assert!(parse(&["config", "-j", "show"]).unwrap().json);
        let value = parse(&["extract", "--", "--json", "--verbose", "--pause"]).unwrap();
        assert!(value.json && value.verbose && value.pause);
        assert_eq!(value.paths, ["--json", "--verbose", "--pause"]);
        // Only exact argv tokens restore flags. Attached passwords remain data.
        for password in ["--json", "-j", "--verbose", "-v", "--pause"] {
            let token = format!("--password={password}");
            let value = parse(&["extract", &token, "a.zip"]).unwrap();
            assert_eq!(value.passwords[0].as_ref(), password);
            assert!(!value.json && !value.verbose && !value.pause);
        }
        let value = parse(&["watch", "-jv", "status"]).unwrap();
        assert!(!value.json && !value.verbose);
        let value = parse(&["watch", "-j", "-v", "status"]).unwrap();
        assert!(value.json && value.verbose);
        let value = parse(&["watch", "-jv", "status", "-j"]).unwrap();
        assert!(value.json && !value.verbose);
        let value = parse(&["watch", "--pause", "start", "--no-pause"]).unwrap();
        assert!(value.pause && value.no_pause);
        let value = parse(&["extract", "--pw-file=", "--out-dir=", "a.zip"]).unwrap();
        assert!(value.password_file.is_none());
        assert!(value.output.is_none());
        // Watch checks whether --out-dir was supplied, including an empty
        // value, before accepting multiple roots. Do not apply extract's
        // empty-output normalization to this command.
        for args in [
            vec!["watch", "add", "A", "B", "--out-dir="],
            vec!["watch", "add", "A", "B", "--out-dir", ""],
        ] {
            let value = parse(&args).unwrap();
            assert_eq!(value.output.as_deref(), Some(""));
            assert_eq!(value.paths, ["A", "B"]);
        }
        assert!(parse(&["watch", "add", "A", "B"]).unwrap().output.is_none());

        for args in [
            vec!["extract", "--dire", "file.zip"], // prefixes are not declared options
            vec!["extract", "--recu", "file.zip"],
            vec!["extract", "--no-b", "file.zip"],
            vec!["watch", "--on", "start"], // action-only flag at parent scope
            vec!["extract", "--json=true", "file.zip"],
            vec!["extract", "--pass", "--json", "file.zip"],
            vec!["extract", "a.zip", "-v", "b.zip"],
            vec!["extract", "a.zip", "-v", "--", "b.zip"],
        ] { assert!(parse(&args).is_err(), "{args:?}"); }
        let value = parse(&["extract", "-vpsecret", "-p", "-.5", "-p", "-with space", "--", "--no-b"]).unwrap();
        assert!(value.verbose);
        assert_eq!(value.passwords.iter().map(|s| s.as_ref()).collect::<Vec<_>>(), ["secret", "-.5", "-with space"]);
        assert_eq!(value.paths, ["--no-b"]);
        for password in ["-１２３", "-١٢٣", "-१२३", "-.１２", "-١.٢", "-1\n", "-.1\n", "-１２\n"] {
            let value = parse(&["passwords", "--no-bpw", "--password", password, "--json"]).unwrap();
            assert_eq!(value.passwords[0].as_ref(), password);
        }
        for password in ["-²", "-\n", "-1\n\n", "-1\r\n"] {
            assert!(parse(&["passwords", "--password", password]).is_err());
        }
        assert_eq!(parse(&["extract", "a.zip", "--", "-b.zip"]).unwrap().paths, ["a.zip", "-b.zip"]);
        let value = parse(&["watch", "--json", "--", "start", "--once"]).unwrap();
        assert!(value.once);
        assert!(value.json); // main restores explicitly supplied parent flags
        assert!(parse(&["watch", "start", "--json"]).unwrap().json);
        assert!(parse(&["config", "validate", "--scan-rule-stdin"]).unwrap().rule_stdin);
        assert_eq!(parse(&["--", "extract", "file.zip"]).unwrap().paths, ["file.zip"]);
        assert!(parse(&["--he"]).is_err());
        assert!(parse(&["extract", "--he"]).is_err());
        for args in [
            vec!["extract", "a.zip", "-v", "b.zip", "--help"],
            vec!["extract", "--unknown", "--help"],
            vec!["extract", "--dire", "--help"],
            vec!["--unknown", "--help"],
            vec!["-hx"],
            vec!["extract", "-hx"],
            vec!["extract", "-hp", "secret"],
            vec!["extract", "-hvpsecret"],
            vec!["extract", "-hFf"],
            vec!["--unknown", "extract", "--help"],
            vec!["watch", "--once", "start", "--help"],
            vec!["watch", "start", "--unknown", "--help"],
            vec!["watch", "--help", "invalid"],
            vec!["--unknown", "extract"],
            vec!["watch", "--unknown", "add"],
            vec!["--unknown", "watch"],
        ] { assert!(parse(&args).unwrap().help, "{args:?}"); }
        for args in [
            vec!["extract", "--password", "--help"],
            vec!["extract", "-hp", "--help"],
            vec!["extract", "-hvp", "--help"],
            vec!["extract", "-hj=true"],
            vec!["-h=foo"],
            vec!["extract", "--json=true", "--help"],
            vec!["extract", "--pause", "--no-pause", "--help"],
            vec!["extract", "-f", "-F", "--help"],
            vec!["watch", "invalid", "--help"],
            vec!["config", "invalid", "--help"],
        ] { assert!(parse(&args).is_err(), "{args:?}"); }
    }
}

#[cfg(test)]
mod recursive_prompt_tests {
    use super::*;

    #[derive(Default)]
    struct Input {
        interactive: bool,
        ascii: bool,
        cancel_input: bool,
        reads: std::sync::atomic::AtomicUsize,
        answers: Mutex<VecDeque<String>>,
        stdout: Mutex<Vec<u8>>,
        stderr: Mutex<Vec<u8>>,
        combined: Mutex<Vec<u8>>,
    }
    impl Session for Input {
        fn write(&self, stream: Stream, bytes: &[u8]) -> io::Result<()> {
            self.combined.lock().unwrap().extend_from_slice(bytes);
            match stream {
                Stream::Out => self.stdout.lock().unwrap().extend_from_slice(bytes),
                Stream::Err => self.stderr.lock().unwrap().extend_from_slice(bytes),
            }
            Ok(())
        }
        fn read_line(&self, prompt: &str) -> io::Result<Option<String>> {
            self.write(Stream::Out, prompt.as_bytes())?;
            self.reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.cancel_input { return Err(crate::io::cancellation::cancelled_io()); }
            Ok(self.answers.lock().unwrap().pop_front())
        }
        fn interactive(&self) -> bool { self.interactive }
        fn input_is_terminal(&self) -> bool { false }
        fn unicode(&self) -> bool { !self.ascii }
        fn terminal_size(&self) -> (usize, usize) { (80, 25) }
    }

    // Covers localized help grouping and the noninteractive disk warning, which
    // final archive-tree tests cannot observe.
    #[test]
    fn help_sections_and_disk_wait_text_match_main() {
        for language in [Language::En, Language::Zh] {
            let snapshots: Value = serde_json::from_str(include_str!("../../../../tests/data/cli_help_main.json")).unwrap();
            let pages = snapshots[if language == Language::En { "en" } else { "zh" }].as_object().unwrap();
            for (command, expected) in pages {
                let input = Input::default();
                let mut arguments: Vec<_> = command.split_whitespace().map(str::to_owned).collect();
                arguments.push("--help".into());
                let options = Options::parse(&arguments).unwrap();
                help(&options, language, &input).unwrap();
                let text = String::from_utf8(input.stdout.lock().unwrap().clone()).unwrap();
                assert_eq!(text, expected.as_str().unwrap(), "{language:?} {command}");
            }
            for volume_error in [None, Some(5)] {
                let input = Arc::new(Input::default());
                let progress = Progress {
                    session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                    cancel: Cancellation::new(), language,
                    display: Mutex::default(), reporting: reporting::Reports::default(),
                    branches: Mutex::default(), prompt: false, visible: true, verbose: false,
                };
                progress.notify(Event::Queued { id: 1, parent: None, path: "input.zip".into(), depth: 1, segment: None });
                progress.notify(Event::ResourceWait {
                    id: 1, path: "input.zip".into(),
                    state: crate::pipeline::ResourceWait { disk: true, memory: true, volume_error, ..Default::default() },
                });
                progress.flush_events();
                let text = String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap();
                let hint = match volume_error {
                    Some(error) => language.translate("report.status.disk_unavailable", &[("error", &error.to_string())]),
                    None => language.text("report.status.disk_resume_hint").into(),
                };
                assert_eq!(text, format!("input.zip: {hint}\n"));
                for memory in [false, true, false] {
                    progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(),
                        state: crate::pipeline::ResourceWait { disk: true, memory, volume_error, ..Default::default() }, });
                    progress.flush_events();
                }
                assert_eq!(String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap(), text);
                progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(), state: Default::default() });
                progress.flush_events();
                progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(),
                    state: crate::pipeline::ResourceWait { disk: true, memory: false, volume_error, ..Default::default() }, });
                progress.flush_events();
                assert_eq!(String::from_utf8(input.stderr.lock().unwrap().clone()).unwrap(), text.repeat(2));
            }
        }
    }

    #[test]
    fn disk_episode_survives_worker_and_reporting_coalescing() {
        let frames = crate::pipeline::coalesced_wait_batches(&[
            vec![json!({"type":"progress", "event":"space_blocked", "episode_id":1})],
            vec![json!({"type":"progress", "event":"space_resumed", "episode_id":1}),
                 json!({"type":"progress", "event":"space_blocked", "episode_id":2})],
            vec![json!({"type":"progress", "event":"space_resumed", "episode_id":2})],
            vec![json!({"type":"progress", "event":"space_blocked", "episode_id":3})],
            vec![json!({"type":"native_memory", "event":"memory_blocked", "episode_id":7})],
        ]);
        for language in [Language::En, Language::Zh] {
            let input = Arc::new(Input::default());
            let progress = Progress {
                session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                cancel: Cancellation::new(), language,
                display: Mutex::default(), reporting: reporting::Reports::default(),
                branches: Mutex::default(), prompt: false, visible: true, verbose: false,
            };
            progress.notify(Event::Queued { id: 1, parent: None, path: "input.zip".into(), depth: 1, segment: None });
            let emit = |state| progress.notify(Event::ResourceWait { id: 1, path: "input.zip".into(), state });
            let expected = format!("input.zip: {}\n", language.text("report.status.disk_resume_hint"));
            emit(frames[0]);
            progress.flush_events();
            assert_eq!(*input.stderr.lock().unwrap(), expected.as_bytes());
            // Resume and new wait were already merged inside the worker mailbox.
            emit(frames[1]);
            progress.flush_events();
            assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(2).as_bytes());
            // Reports overwrites resume before display, while retaining episode 3.
            emit(frames[2]);
            emit(frames[3]);
            progress.flush_events();
            assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(3).as_bytes());
            emit(frames[4]);
            progress.flush_events();
            assert_eq!(*input.stderr.lock().unwrap(), expected.repeat(3).as_bytes());
        }
    }

    #[test]
    fn parser_errors_match_main_text_stream_and_exit_code() {
        // Captured by executing main's real parser classes, registrations and
        // value converters. Usage is suppressed; diagnostics remain on stderr.
        let cases: &[(&[&str], &str)] = &[
            (&["extract", "x", "-p"], "sunpack extract: error: argument -p/--password: expected one argument\n"),
            (&["e", "x", "--password"], "sunpack extract: error: argument -p/--password: expected one argument\n"),
            (&["passwords", "--json=x"], "sunpack passwords: error: argument -j/--json: ignored explicit argument 'x'\n"),
            (&["scan", "x", "--pause", "--no-pause"], "sunpack scan: error: argument --no-pause: not allowed with argument --pause\n"),
            (&["extract", "x", "-F", "-f"], "sunpack extract: error: argument -f/--flatten: not allowed with argument -F/--no-flatten\n"),
            (&["extract", "x", "--foo", "--bar"], "sunpack: error: unrecognized arguments: --foo --bar\n"),
            (&["nonsense"], "sunpack: error: argument command: invalid choice: 'nonsense' (choose from extract, e, watch, w, scan, s, passwords, pw, config, cfg, doctor, d, version, ver)\n"),
            (&["watch", "nonsense"], "sunpack watch: error: argument watch_action: invalid choice: 'nonsense' (choose from start, add, remove, rm, list, ls, reload, rebuild-log, stop, status, st, startup)\n"),
            (&["config", "nonsense"], "sunpack config: error: argument config_action: invalid choice: 'nonsense' (choose from show, validate)\n"),
            (&["watch", "--json"], "sunpack watch: error: the following arguments are required: watch_action\n"),
            (&["config", "--json"], "sunpack config: error: the following arguments are required: config_action\n"),
            (&["watch", "startup", "nonsense"], "sunpack watch startup: error: argument action: invalid choice: 'nonsense' (choose from enable, disable, status)\n"),
            (&["watch", "startup", "enable", "disable"], "sunpack: error: unrecognized arguments: disable\n"),
            (&["scan", "-j"], "sunpack scan: error: the following arguments are required: paths\n"),
            (&["--foo"], "sunpack: error: the following arguments are required: command\n"),
            (&["--"], "sunpack: error: the following arguments are required: command\n"),
            (&["version", "-h=x"], "sunpack version: error: argument -h/--help: ignored explicit argument 'x'\n"),
            (&["extract", "x", "-h=x"], "sunpack extract: error: argument -h/--help: ignored explicit argument 'x'\n"),
            (&["scan", "x", "-jp"], "sunpack scan: error: argument -p/--password: expected one argument\n"),
            (&["scan", "x", "-junknown"], "sunpack: error: unrecognized arguments: -unknown\n"),
            (&["extract", "x", "-r", "0"], "sunpack extract: error: argument -r/--recur: recursive_extract must be \"*\", \"?\", or a positive integer\n"),
            (&["extract", "x", "--recur=bad"], "sunpack extract: error: argument -r/--recur: recursive_extract must be \"*\", \"?\", or a positive integer\n"),
            (&["extract", "x", "-c", "bad"], "sunpack extract: error: argument -c/--cleanup: archive_cleanup_mode must be one of: d, r, k\n"),
            (&["scan", "x", "-j=thing"], "sunpack scan: error: argument -j/--json: ignored explicit argument 'thing'\n"),
            (&["watch", "rm", "--pause", "--no-pause"], "sunpack watch remove: error: argument --no-pause: not allowed with argument --pause\n"),
            (&["watch", "--foo", "nonsense"], "sunpack watch: error: argument watch_action: invalid choice: 'nonsense' (choose from start, add, remove, rm, list, ls, reload, rebuild-log, stop, status, st, startup)\n"),
            (&["extract", "--foo"], "sunpack extract: error: the following arguments are required: paths\n"),
            (&["extract", "--foo", "--bar"], "sunpack extract: error: the following arguments are required: paths\n"),
            (&["--foo", "scan", "x", "--bar"], "sunpack: error: unrecognized arguments: --foo --bar\n"),
            (&["watch", "startup", "--json"], "sunpack watch startup: error: the following arguments are required: action\n"),
            (&["watch", "startup", "bad", "--help"], "sunpack watch startup: error: argument action: invalid choice: 'bad' (choose from enable, disable, status)\n"),
        ];
        let host = Host::new();
        for &(args, expected) in cases {
            let input = Arc::new(Input::default());
            let code = run_console(&host, Path::new("."),
                args.iter().map(|arg| (*arg).to_owned()).collect(),
                input.clone(), Cancellation::new()).unwrap();
            assert_eq!(code, 2, "{args:?}");
            assert!(input.stdout.lock().unwrap().is_empty(), "{args:?}");
            assert_eq!(&*input.stderr.lock().unwrap(), expected.as_bytes(), "{args:?}");
        }
    }

    #[test]
    fn failed_request_drains_and_joins_queued_progress_before_unwinding() {
        let reports = Arc::new(reporting::Reports::default());
        reports.notify(Event::Working { id: 7 });
        // Capture the failure before releasing the request's reporter lifetime.
        let failure = crate::pipeline::block_on(settle_unwind(async { panic!("request failure") }));
        assert!(failure.is_err());
        reports.close();
        let scheduler = crate::pipeline::Scheduler::new();
        let (sent, received) = std::sync::mpsc::channel();
        let service = Arc::clone(&reports);
        let output = scheduler.submit(1, crate::pipeline::Origin::Foreground, &Cancellation::new(), move |_| Box::pin(async move {
            service.serve_async(|| {
                for event in service.take_events() { sent.send(event).unwrap(); }
            }).await;
        }));
        output.join().unwrap();
        assert!(matches!(received.try_recv().unwrap(), Event::Working { id: 7 }));
        assert!(received.try_recv().is_err());
        assert!(reports.take_events().is_empty());
    }

    #[test]
    fn retry_replaces_all_carrier_segments_when_nested_input_becomes_root() {
        fn archive(path: &str, depth: usize, offset: u64, failed: bool) -> ArchiveResult {
            ArchiveResult {
                path: path.into(), format: "zip".into(), output: None,
                failure: failed.then(|| crate::pipeline::Failure::new(FailureKind::WrongPassword, "password")),
                files: 0, bytes: 0, encrypted: None, depth, offset, end_offset: None,
                volume_completeness: None, volume_attempts: None, source_paths: vec![],
                password: None, discovery_source: crate::pipeline::DiscoverySource::Direct,
                damage_flags: None, partial: false, retained: false, recovered_complete_files: 0,
                promoted: false, promotion_original_path: None,
            }
        }
        let mut all = BTreeMap::new();
        for item in [archive("C:/data/Carrier.bin", 2, 100, true),
                     archive("C:/data/Carrier.bin", 2, 900, true),
                     archive("C:/data/other.zip", 1, 0, false)] {
            all.insert((path_key(&item.path), item.offset, item.format.clone()), item);
        }
        let current = [archive("c:/DATA/carrier.bin", 1, 100, false)];
        remove_replaced_archives(&mut all, &current);
        for item in current {
            all.insert((path_key(&item.path), item.offset, item.format.clone()), item);
        }
        assert_eq!(all.len(), 2);
        let summary = ArchiveSummary::collect(all.values(), Language::En, true);
        assert_eq!(summary.success, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.nested, 0);
        assert!(summary.errors.is_empty());
    }

    #[test]
    fn settled_failure_and_partial_trees_keep_the_last_known_progress() {
        for (partial, known, interactive) in [
            (false, true, true), (true, true, true), (false, false, true),
            (false, true, false), (true, true, false), (false, false, false),
        ] {
            let input = Arc::new(Input { interactive, ..Input::default() });
            let progress = Progress {
                session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                cancel: Cancellation::new(), language: Language::En,
                display: Mutex::default(), reporting: reporting::Reports::default(),
                branches: Mutex::default(), prompt: false, visible: true, verbose: false,
            };
            assert!(matches!(progress.worker_updates(), crate::pipeline::WorkerUpdates::All));
            progress.notify(Event::Queued { id: 7, parent: None, path: "embedded.bin".into(), depth: 1, segment: None });
            if known {
                progress.notify(Event::Progress { id: 7, path: "embedded.bin".into(), completed_bytes: 40, total_bytes: 100 });
            }
            progress.flush_events();
            if !interactive { assert!(input.stdout.lock().unwrap().is_empty()); }
            input.stdout.lock().unwrap().clear();
            let archive = ArchiveResult {
                path: "embedded.bin".into(), format: "zip".into(), output: None,
                failure: Some(crate::pipeline::Failure::new(FailureKind::Damaged, "damage")),
                files: 0, bytes: 0, encrypted: None, depth: 1, offset: 123,
                end_offset: None, volume_completeness: None, volume_attempts: None,
                source_paths: vec![], password: None, discovery_source: crate::pipeline::DiscoverySource::Direct,
                damage_flags: None, partial, retained: false, recovered_complete_files: 0,
                promoted: false, promotion_original_path: None,
            };
            progress.finish_scope(7, &[archive]).unwrap();
            let text = String::from_utf8(input.stdout.lock().unwrap().clone()).unwrap();
            let status = Language::En.text(if partial { "report.status.partial" } else { "report.status.error" });
            let expected = if known { " [########------------]  40%" } else { " [--------------------]  --%" };
            assert!(text.contains(&format!("[{status}]{expected}")), "{text}");
            assert!(!text.contains("100%"), "{text}");
            if !interactive { assert!(!text.contains('\x1b'), "{text}"); }
            input.stdout.lock().unwrap().clear();
            progress.flush_events();
            assert!(input.stdout.lock().unwrap().is_empty());
        }
    }

    fn report_archive(path: &str, offset: u64) -> ArchiveResult {
        ArchiveResult {
            path: path.into(), format: "zip".into(), output: None, failure: None,
            files: 0, bytes: 0, encrypted: None, depth: 1, offset,
            end_offset: None, volume_completeness: None, volume_attempts: None,
            source_paths: vec![], password: None, discovery_source: crate::pipeline::DiscoverySource::Direct,
            damage_flags: None, partial: false, retained: false, recovered_complete_files: 0,
            promoted: false, promotion_original_path: None,
        }
    }

    // Checks the carrier/segment hierarchy in both final output modes, including
    // failed parent status and the shared two-space detail indentation.
    #[test]
    fn carrier_final_and_scan_reports_keep_parent_status_and_detail_indentation() {
        for ascii in [false, true] {
            let input = Arc::new(Input { ascii, ..Input::default() });
            let progress = Progress {
                session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                cancel: Cancellation::new(), language: Language::En,
                display: Mutex::default(), reporting: reporting::Reports::default(),
                branches: Mutex::default(), prompt: false, visible: true, verbose: false,
            };
            let mut archives = vec![
                report_archive("carrier.bin", 10), report_archive("carrier.bin", 20),
                report_archive("child.zip", 0), report_archive("other.zip", 0),
            ];
            archives[2].depth = 2;
            progress.archive_branch(&archives[0], &archives[2]);
            archives[1].failure = Some(crate::pipeline::Failure::new(FailureKind::Damaged, "damage"));
            let report = ScopeReport::new(&archives, &progress, HashMap::new());
            let mut bytes = Vec::new();
            report.write(&mut bytes).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            let error = Language::En.text("report.status.error");
            assert!(text.starts_with(&format!("carrier.bin\n  [{error}]")), "{text}");
            assert_eq!(text.matches(&format!("[{error}]")).count(), 2, "{text}");
            let (_, continuation) = tree_edge(!ascii, false);
            let (edge, _) = tree_edge(!ascii, true);
            assert!(text.contains(&format!("\n{continuation}{edge}child.zip\n")), "{text}");
            let segment = Language::En.translate("cli.scan.segment", &[("index", "2")]);
            assert!(text.find("child.zip").unwrap() < text.find(&segment).unwrap(), "{text}");
            assert!(text.find(&segment).unwrap() < text.find("\nother.zip\n").unwrap(), "{text}");
            let options = Options::parse(&["scan".into(), "carrier.bin".into()]).unwrap();
            input.combined.lock().unwrap().clear();
            let mut outcome = Outcome::default();
            outcome.archives = archives;
            report_scan(outcome, vec![], &options, input.as_ref(), Language::En).unwrap();
            let text = String::from_utf8(input.stdout.lock().unwrap().clone()).unwrap();
            let combined = String::from_utf8(input.combined.lock().unwrap().clone()).unwrap();
            let segment = Language::En.translate("cli.scan.segment", &[("index", "2")]);
            let error = Language::En.translate("cli.scan.error", &[("error", Language::En.text("failure.damaged"))]);
            assert!(combined.find(&segment).unwrap() < combined.find(&error).unwrap(), "{combined}");
            let format = Language::En.translate("cli.scan.format", &[("format", "zip")]);
            for last in [false, true] {
                let (_, continuation) = tree_edge(!ascii, last);
                assert!(text.lines().any(|line| line == format!("{continuation}  {format}")), "{text}");
            }
        }
    }

    #[test]
    fn final_failure_summary_uses_main_names_and_emits_errors_once() {
        let mut archive = report_archive("C:/inputs/blocked.zip", 0);
        archive.failure = Some(crate::pipeline::Failure::new(FailureKind::Damaged, "native detail"));
        let summary = ArchiveSummary::collect([&archive], Language::En, true);
        assert_eq!(summary.errors, [format!("blocked.zip [{}]", Language::En.text("failure.damaged"))]);
        archive.promoted = true;
        let summary = ArchiveSummary::collect([&archive], Language::En, true);
        assert_eq!(summary.errors, [format!("C:/inputs/blocked.zip [{}]", Language::En.text("failure.damaged"))]);
        archive.promoted = false;
        let mut sibling = report_archive("C:/inputs/blocked.zip", 10);
        sibling.failure = Some(crate::pipeline::Failure::new(FailureKind::WrongPassword, "native password"));
        let summary = ArchiveSummary::collect([&archive, &sibling], Language::En, false);
        let message = format!("blocked.zip [{}]", Language::En.text("failure.embedded_extract_failed"));
        assert_eq!(summary.errors, [Language::En.translate("report.failed", &[("task", &message)])]);
        let input = Input::default();
        let mut result = CommandResult::new("extract");
        result.errors = summary.errors;
        result.emit_errors(&input).unwrap();
        line(&input, Stream::Out, &"-".repeat(54)).unwrap();
        result.emit_errors(&input).unwrap();
        let text = String::from_utf8(input.combined.lock().unwrap().clone()).unwrap();
        assert_eq!(text, format!("{}\n{}\n", result.errors[0], "-".repeat(54)));
        assert!(!serde_json::to_value(&result).unwrap().as_object().unwrap().contains_key("emitted_errors"));
    }

    #[test]
    fn scan_json_keeps_main_sparse_fields_without_internal_failure_evidence() {
        let options = Options::parse(&["scan".into(), "--json".into(), "-v".into(), "input.bin".into()]).unwrap();
        let mut archive = report_archive("input.bin", 0);
        archive.format.clear();
        archive.damage_flags = Some(vec![]);
        let mut failure = crate::pipeline::Failure::new(FailureKind::Damaged, "damage");
        failure.evidence = Some(Box::new(crate::pipeline::FailureEvidence {
            stage: Some("item_extract".into()), ..Default::default()
        }));
        archive.failure = Some(failure);
        let mut outcome = Outcome::default();
        outcome.archives.push(archive);
        let (_, report) = report_scan(outcome, vec![], &options, &Input::default(), Language::En).unwrap();
        let item = &report.items[0];
        assert!(item.get("format").is_none());
        assert!(item.get("damage_flags").is_none());
        assert!(item.get("failure").is_none());
        assert_eq!(item["error_kind"], "damaged");
        assert_eq!(item["error"], Language::En.text("failure.damaged"));
        assert_eq!(item["discovery_source"], "direct");
    }

    // Rendering must not consume a native call frame per nesting level. The
    // small thread stack catches recursive traversal without Windows fixtures.
    #[test]
    fn deeply_nested_final_tree_uses_an_explicit_traversal_stack() {
        std::thread::Builder::new().stack_size(128 * 1024).spawn(|| {
            let count = 2048;
            let archives: Vec<_> = (0..count).map(|i| report_archive(&format!("{i}.zip"), 0)).collect();
            let report = ScopeReport {
                progress: HashMap::new(), archives: &archives, unicode: true,
                language: Language::En, verbose: false,
                groups: (0..count).map(|i| i..i + 1).collect(),
                children: (0..count).map(|i| if i + 1 < count { vec![i + 1] } else { vec![] }).collect(),
                roots: vec![0],
            };
            report.write(&mut io::sink()).unwrap();
        }).unwrap().join().unwrap();
    }

    #[test]
    fn scope_completion_flushes_queued_panel_events_before_removing_the_scope() {
        let input = Arc::new(Input { interactive: true, ..Input::default() });
        let progress = Progress {
            session: input.clone(), watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
            cancel: Cancellation::new(), language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            branches: Mutex::default(), prompt: false, visible: true, verbose: false,
        };
        progress.notify(Event::Queued { id: 7, parent: None, path: "test.zip".into(), depth: 1, segment: None });
        progress.finish_scope(7, &[]).unwrap();
        input.stdout.lock().unwrap().clear();
        progress.flush_events();
        assert!(input.stdout.lock().unwrap().is_empty(), "a queued old event must not resurrect a completed scope");
    }

    #[test]
    fn retained_skipped_scope_releases_only_its_branch_links() {
        for prompting in [false, true] {
            let session = Arc::new(Input::default());
            let progress = Progress {
                session, watch: Arc::new(watch::Watch::new(Arc::new(|| {}))),
                cancel: Cancellation::new(), language: Language::En,
                display: Mutex::default(), reporting: reporting::Reports::default(),
                branches: Mutex::default(), prompt: false, visible: true, verbose: false,
            };
            progress.display.lock().unwrap().prompting = prompting;
            let parent = report_archive("parent.zip", 0);
            let mut child = report_archive("child.zip", 0);
            child.depth = 2;
            let other = report_archive("other.zip", 0);
            progress.archive_branch(&parent, &child);
            progress.archive_branch(&parent, &other);
            progress.notify(Event::Queued { id: 1, parent: None, path: parent.path.clone(), depth: 1, segment: None });
            progress.notify(Event::Queued { id: 2, parent: Some(1), path: child.path.clone(), depth: 2, segment: None });
            progress.notify(Event::Finished { id: 2, path: child.path.clone(), depth: 2,
                result: crate::pipeline::TaskCompletion { discovery: None, status: TaskStatus::Skipped,
                    failure: None, output: None } });
            progress.finish_scope(1, &[parent, child]).unwrap();
            let branches = progress.branches.lock().unwrap();
            assert_eq!(branches.len(), 1);
            assert!(branches.contains_key(&other.path));
            let display = progress.display.lock().unwrap();
            assert!(!display.panel.as_ref().unwrap().retains_scope(1));
        }
    }

    #[test]
    fn cancelling_password_prompt_returns_interrupted_not_usage() {
        let host = Host::new();
        // Prompt cancellation must finish before any worker can be started.
        assert!(host.engine.set(Arc::new(Engine::with_scheduler(
            PathBuf::from("missing-worker-for-cancelled-prompt.exe"), Arc::clone(&host.scheduler),
        ))).is_ok());
        let input = Arc::new(Input { cancel_input: true, ..Input::default() });
        let cwd = std::env::current_dir().unwrap();
        let result = crate::pipeline::block_on(run(
            &host, &cwd,
            vec!["extract".into(), "--ask-pw".into(), "--no-pause".into(), "cancelled.zip".into()],
            input.clone(), Cancellation::new(),
        ));
        assert_eq!(input.reads.load(std::sync::atomic::Ordering::Relaxed), 1);
        assert_eq!(result.unwrap(), 130);
    }

    #[test]
    fn connection_command_future_can_move_between_shared_executor_polls() {
        fn assert_send(_: impl std::future::Future + Send) {}
        let host = Host::new();
        let input: Arc<dyn Session> = Arc::new(Input::default());
        assert_send(run(&host, Path::new("."), vec!["version".into()], input, Cancellation::new()));
    }

    #[test]
    fn json_recursion_reads_authorization_without_polluting_stdout() {
        let input = Arc::new(Input::default());
        input.answers.lock().unwrap().extend(["invalid".into(), "yes".into(), "n".into()]);
        let watch = Arc::new(watch::Watch::new(Arc::new(|| {})));
        let cancel = Cancellation::default();
        let progress = Progress {
            session: input.clone(), watch, cancel, language: Language::En,
            display: Mutex::default(), reporting: reporting::Reports::default(),
            branches: Mutex::default(), prompt: true, visible: false, verbose: false,
        };
        assert!(crate::pipeline::block_on(progress.allow_recursive_async(2, 1)));
        assert!(!crate::pipeline::block_on(progress.allow_recursive_async(3, 1)));
        assert!(input.answers.lock().unwrap().is_empty());
        assert!(input.stdout.lock().unwrap().is_empty());
        assert!(!input.stderr.lock().unwrap().is_empty());
    }
}
