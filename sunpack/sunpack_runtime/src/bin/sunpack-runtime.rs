#![windows_subsystem = "windows"]

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(sunpack_runtime::runtime::main() as u8)
}
