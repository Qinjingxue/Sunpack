// External observer for the staged benchmark installation. Forward the original
// SPBF stream byte-for-byte and keep one transcript per process and direction.
use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::{self, Command, Stdio};
use std::thread;

fn relay(mut src: impl Read, mut dst: impl Write, mut log: File) -> io::Result<()> {
    let mut bytes = [0u8; 16384];
    loop {
        let count = src.read(&mut bytes)?;
        if count == 0 {
            return Ok(());
        }
        log.write_all(&bytes[..count])?;
        dst.write_all(&bytes[..count])?;
        dst.flush()?;
    }
}

fn main() -> io::Result<()> {
    let dir = env::current_exe()?.parent().unwrap().to_owned();
    let capture = std::path::PathBuf::from(env::var_os("RQ2_FRAMES").unwrap());
    let id = process::id();
    let input = File::create(capture.join(format!("{id}-in.bin")))?;
    let output = File::create(capture.join(format!("{id}-out.bin")))?;
    let mut worker = Command::new(dir.join("measured-worker.exe"))
        .args(env::args_os().skip(1))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let tx = worker.stdin.take().unwrap();
    thread::spawn(move || relay(io::stdin().lock(), tx, input));
    let result = relay(worker.stdout.take().unwrap(), io::stdout().lock(), output);
    let status = worker.wait()?;
    result?;
    process::exit(status.code().unwrap_or(1));
}
