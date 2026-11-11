#![windows_subsystem = "windows"]

fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(sunpack_native::runtime::main() as u8)
}
