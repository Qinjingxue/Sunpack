use super::windows;
use crate::core::{config, i18n::Language, resources};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

fn check(name: &str, status: &str, detail: impl Into<String>) -> Value {
    json!({"name":name,"status":status,"detail":detail.into()})
}

fn checked(name: &str, result: io::Result<String>) -> Value {
    match result {
        Ok(detail) => check(name, "ok", detail),
        Err(error) => check(name, "fail", error.to_string()),
    }
}

pub(super) fn checks(cwd: &Path) -> io::Result<Vec<Value>> {
    let settings = config::load_snapshot(cwd);
    let mut checks = vec![
        checked(
            "config",
            settings
                .as_ref()
                .map(|snapshot| snapshot.sources.primary().display().to_string())
                .map_err(|error| io::Error::other(error.to_string())),
        ),
        checked(
            "native",
            std::env::current_exe().map(|path| path.display().to_string()),
        ),
        checked(
            "sevenzip_worker",
            resources::worker_path(cwd).map(|path| path.display().to_string()),
        ),
    ];
    if let Some(root) = resources::package_root() {
        checks.push(checked("data_dir", data_directory()));
        checks.push(checked(
            "broker_service",
            machine_command(
                r"SYSTEM\CurrentControlSet\Services\SunPackWatchBroker",
                "ImagePath",
                &root.join("service/sunpack-watch-broker.exe"),
                None,
            ),
        ));
        checks.push(checked(
            "toast_registration",
            machine_command(
                r"Software\Classes\CLSID\{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}\LocalServer32",
                "",
                &root.join("bin/sunpack.exe"),
                Some("--toast-activated"),
            ),
        ));
        checks.push(
            machine_path(&root)
                .unwrap_or_else(|error| check("machine_path", "fail", error.to_string())),
        );
        checks.push(
            context_menu(&root)
                .unwrap_or_else(|error| check("context_menu", "fail", error.to_string())),
        );
        checks.push(match windows::startup_status() {
            Ok(Some(command)) => match windows::startup_command() {
                Ok(expected) if normalize_command(&expected) == normalize_command(&command) => {
                    check("startup", "ok", command)
                }
                _ => check(
                    "startup",
                    "fail",
                    format!("startup command is stale: {command}"),
                ),
            },
            Ok(None) => check("startup", "skip", "disabled"),
            Err(error) => check("startup", "fail", error.to_string()),
        });
    }
    checks.push(match settings {
        Ok(settings) if settings.config.watch.toast_enabled => checked(
            "toast",
            windows::ToastLibrary::load(cwd)
                .and_then(|library| library.self_test())
                .map(|_| String::new()),
        ),
        Ok(_) => check("toast", "skip", "disabled"),
        Err(_) => check("toast", "skip", "configuration is invalid"),
    });
    match super::watch::diagnostic_roots(cwd) {
        Ok(roots) => {
            checks.extend(roots.into_iter().map(|path| {
                let exists = path.is_dir();
                let mut row = check(
                    "watch_root",
                    if exists { "ok" } else { "warn" },
                    if exists { "" } else { "directory not found" },
                );
                row["path"] = json!(path);
                row
            }));
        }
        Err(error) => checks.push(check(
            "watch_root",
            "warn",
            format!("unable to read watch roots: {error}"),
        )),
    }
    Ok(checks)
}

fn data_directory() -> io::Result<String> {
    let directory = resources::program_data_dir()?;
    let unique = windows::random_bytes::<8>()?;
    let path = directory.join(format!(
        ".sunpack-doctor-{:016x}",
        u64::from_ne_bytes(unique)
    ));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    drop(file);
    fs::remove_file(path)?;
    Ok(directory.display().to_string())
}

fn normalized_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn normalize_command(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn machine_command(
    key: &str,
    name: &str,
    target: &Path,
    argument: Option<&str>,
) -> io::Result<String> {
    let text = windows::registry_text(HKEY_LOCAL_MACHINE, key, name)?
        .ok_or_else(|| io::Error::other(format!("registry value is missing: {key}")))?;
    let normalized = text.replace('/', "\\").to_lowercase();
    if !normalized.contains(&normalized_path(&target.to_string_lossy()))
        || argument.is_some_and(|argument| !text.contains(argument))
    {
        return Err(io::Error::other(format!("registration points to: {text}")));
    }
    Ok(text)
}

fn machine_path(root: &Path) -> io::Result<Value> {
    match windows::registry_dword(
        HKEY_LOCAL_MACHINE,
        r"Software\SunPack",
        "PathAddedByInstaller",
    )? {
        None => return Ok(check("machine_path", "skip", "not enabled by installer")),
        Some(1) => {}
        Some(value) => {
            return Ok(check(
                "machine_path",
                "fail",
                format!("invalid installer marker: {value}"),
            ))
        }
    }
    let path = windows::registry_text(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "Path",
    )?
    .ok_or_else(|| io::Error::other("machine PATH is unavailable"))?;
    let entries: Vec<_> = path.split(';').map(normalized_path).collect();
    if entries.contains(&normalized_path(&root.to_string_lossy())) {
        return Ok(check(
            "machine_path",
            "fail",
            "runtime directory in PATH exposes bundled DLLs",
        ));
    }
    if !entries.contains(&normalized_path(&root.join("bin").to_string_lossy())) {
        return Ok(check(
            "machine_path",
            "fail",
            "installer marker exists but launcher directory is missing",
        ));
    }
    Ok(check(
        "machine_path",
        "ok",
        root.join("bin").display().to_string(),
    ))
}

fn context_menu(root: &Path) -> io::Result<Value> {
    let parents = [
        r"Software\Classes\Directory\shell\SunPack",
        r"Software\Classes\Directory\Background\shell\SunPack",
        r"Software\Classes\*\shell\SunPack",
    ];
    let mut count = 0;
    for parent in parents {
        count += usize::from(windows::registry_key_exists(HKEY_CURRENT_USER, parent)?);
    }
    if count == 0 {
        return Ok(check("context_menu", "skip", "not installed"));
    }
    if count != parents.len() {
        return Ok(check("context_menu", "fail", "registration is incomplete"));
    }
    let target = normalized_path(&root.join("bin/sunpack.exe").to_string_lossy());
    for class in [
        "SunPack.FolderContextMenu",
        "SunPack.BackgroundContextMenu",
        "SunPack.FileContextMenu",
    ] {
        let key = format!(r"Software\Classes\{class}\shell\DirectExtract\command");
        let command = windows::registry_text(HKEY_CURRENT_USER, &key, "")?
            .ok_or_else(|| io::Error::other(format!("missing command: {key}")))?;
        if !command.replace('/', "\\").to_lowercase().contains(&target) {
            return Ok(check(
                "context_menu",
                "fail",
                format!("command points to another launcher: {command}"),
            ));
        }
    }
    Ok(check(
        "context_menu",
        "ok",
        root.join("bin/sunpack.exe").display().to_string(),
    ))
}

pub(super) fn label(name: &str, language: Language) -> String {
    let text = match (name, language) {
        ("data_dir", Language::En) => "Program data",
        ("data_dir", Language::Zh) => "程序数据目录",
        ("broker_service", Language::En) => "Watch Broker service",
        ("broker_service", Language::Zh) => "Watch Broker 服务",
        ("toast_registration", Language::En) => "Toast registration",
        ("toast_registration", Language::Zh) => "Toast 注册",
        ("machine_path", Language::En) => "Machine PATH",
        ("machine_path", Language::Zh) => "系统 PATH",
        ("context_menu", Language::En) => "Explorer context menu",
        ("context_menu", Language::Zh) => "资源管理器右键菜单",
        ("startup", Language::En) => "Windows startup",
        ("startup", Language::Zh) => "Windows 开机启动",
        _ => {
            return language
                .text(&format!("cli.doctor.check.{name}"))
                .to_owned()
        }
    };
    text.to_owned()
}
