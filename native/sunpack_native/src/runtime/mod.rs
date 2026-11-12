//! Windows runtime shared by the launcher, Watch, and the command line.

#[cfg(windows)]
mod cli;
#[cfg(windows)]
mod doctor;
#[cfg(windows)]
mod failure;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod toast;
#[cfg(windows)]
mod tray;
#[cfg(windows)]
mod watch;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
use std::io::{self, BufRead, IsTerminal, Write};
#[cfg(windows)]
static RUNTIME_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[cfg(windows)]
pub fn main() -> i32 {
    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return 3;
        }
    };
    let mut identity = None;
    let mut args = Vec::new();
    for arg in std::env::args().skip(1) {
        if let Some(id) = arg.strip_prefix("--_sunpack-runtime-id=") {
            if identity.is_some() || !valid_identity(id) {
                eprintln!("Invalid SunPack runtime identity");
                return 2;
            }
            identity = Some(id.to_owned());
        } else {
            args.push(arg);
        }
    }
    let runtime_id = identity.as_deref().unwrap_or("v2-0000000000000000");
    let _ = RUNTIME_ID.set(runtime_id.to_owned());
    let result = match args.first().map(String::as_str) {
        Some("--persistent-server") => pipe::serve(&cwd, runtime_id).map(|()| 0),
        Some("--persistent-shutdown") => pipe::shutdown(&cwd, runtime_id).map(|()| 0),
        Some("--toast-activated") => windows::activate_toast(&cwd, runtime_id),
        Some("watch" | "w")
            if !args
                .iter()
                .any(|arg| matches!(arg.as_str(), "--once" | "-h" | "--help")) =>
        {
            windows::launch_watch_request(&cwd, &args)
        }
        _ => {
            let host = cli::Host::new();
            let session = Console {
                interactive: windows::enable_console_updates(),
            };
            let cancel = crate::pipeline::Cancellation::new();
            let _control = windows::ConsoleControl::install(cancel.clone());
            cli::run_console(&host, &cwd, args, std::sync::Arc::new(session), cancel)
        }
    };
    result.unwrap_or_else(|error| {
        eprintln!("{error}");
        3
    })
}

#[cfg(not(windows))]
pub fn main() -> i32 {
    eprintln!("SunPack requires Windows");
    3
}

#[cfg(windows)]
fn valid_identity(id: &str) -> bool {
    id.strip_prefix("v2-").is_some_and(|hash| {
        hash.len() == 16
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[cfg(windows)]
trait Session: Send + Sync {
    fn write(&self, stream: Stream, data: &[u8]) -> io::Result<()>;
    fn read_line(&self, prompt: &str) -> io::Result<Option<String>>;
    fn awrite<'a>(&'a self, stream: Stream, data: &'a [u8]) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + 'a>> {
        Box::pin(async move { self.write(stream, data) })
    }
    fn drain(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
    fn aread_line<'a>(&'a self, prompt: &'a str) -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<Option<String>>> + Send + 'a>> {
        Box::pin(async move { self.read_line(prompt) })
    }
    fn interactive(&self) -> bool;
    fn input_is_terminal(&self) -> bool;
    fn unicode(&self) -> bool;
    fn terminal_size(&self) -> (usize, usize);
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum Stream {
    Out = 1,
    Err = 2,
}

#[cfg(windows)]
struct Console {
    interactive: bool,
}

#[cfg(windows)]
impl Session for Console {
    fn write(&self, stream: Stream, data: &[u8]) -> io::Result<()> {
        match stream {
            Stream::Out => {
                let mut writer = io::stdout().lock();
                writer.write_all(data)?;
                writer.flush()
            }
            Stream::Err => {
                let mut writer = io::stderr().lock();
                writer.write_all(data)?;
                writer.flush()
            }
        }
    }

    fn read_line(&self, prompt: &str) -> io::Result<Option<String>> {
        self.write(Stream::Out, prompt.as_bytes())?;
        let mut line = String::new();
        let count = io::stdin().lock().read_line(&mut line)?;
        Ok((count != 0).then_some(line))
    }

    fn interactive(&self) -> bool {
        self.interactive
    }

    fn input_is_terminal(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn unicode(&self) -> bool {
        true
    }

    fn terminal_size(&self) -> (usize, usize) {
        windows::console_size()
    }
}
