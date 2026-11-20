use super::windows;
use crate::core::{config::Config, i18n::Language, resources};
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

fn check(name: &str, status: &str, detail: impl Into<String>) -> Value {
    let mut row = json!({"name":name,"status":status});
    let detail = detail.into();
    if !detail.is_empty() {
        row["detail"] = json!(detail);
    }
    row
}

fn checked(name: &str, result: io::Result<String>) -> Value {
    match result {
        Ok(detail) => check(name, "ok", detail),
        Err(error) => check(name, "fail", error.to_string()),
    }
}

pub(super) fn checks(cwd: &Path, settings: io::Result<(PathBuf, Config)>, language: Language) -> Vec<Value> {
    let config_check = match &settings {
        Ok((path, settings)) => {
            let errors = settings.validate_scan_filters();
            if errors.is_empty() {
                check("config", "ok", path.display().to_string())
            } else {
                let mut row = check("config", "fail", errors.join("; "));
                row["config_path"] = json!(path);
                row["errors"] = json!(errors);
                row
            }
        }
        Err(error) => check("config", "fail", error.to_string()),
    };
    let config_valid = config_check["status"] == "ok";
    let mut checks = vec![
        config_check,
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
                language,
            ),
        ));
        checks.push(checked(
            "toast_registration",
            machine_command(
                r"Software\Classes\CLSID\{C5A6B4E9-3184-44E2-9F15-6A71804F7A36}\LocalServer32",
                "",
                &root.join("bin/sunpack.exe"),
                Some("--toast-activated"),
                language,
            ),
        ));
        checks.push(
            machine_path(&root, language)
                .unwrap_or_else(|error| check("machine_path", "fail", error.to_string())),
        );
        checks.push(
            context_menu(&root, language)
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
                    language.translate("cli.doctor.detail.startup_stale", &[("command", &command)]),
                ),
            },
            Ok(None) => check("startup", "skip", language.text("cli.doctor.detail.disabled")),
            Err(error) => check("startup", "fail", error.to_string()),
        });
    }
    checks.push(match settings {
        _ if !config_valid => check("toast", "skip", language.text("cli.doctor.detail.config_invalid")),
        Ok((_, settings)) if settings.watch.toast_enabled => checked(
            "toast",
            windows::ToastLibrary::load(cwd)
                .and_then(|library| library.self_test())
                .map(|_| String::new()),
        ),
        Ok(_) => check("toast", "skip", language.text("cli.doctor.detail.disabled")),
        Err(_) => check("toast", "skip", language.text("cli.doctor.detail.config_invalid")),
    });
    match super::watch::diagnostic_roots(cwd) {
        Ok(roots) => {
            checks.extend(roots.into_iter().map(|path| {
                let exists = path.is_dir();
                let mut row = check(
                    "watch_root",
                    if exists { "ok" } else { "warn" },
                    if exists { "" } else { language.text("cli.doctor.detail.root_missing") },
                );
                row["path"] = json!(path);
                row
            }));
        }
        Err(error) => checks.push(check(
            "watch_root",
            "warn",
            language.translate("cli.doctor.detail.roots_unreadable", &[("error", &error.to_string())]),
        )),
    }
    checks
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
    language: Language,
) -> io::Result<String> {
    registration_detail(windows::registry_text(HKEY_LOCAL_MACHINE, key, name)?, target, argument, language)
}

fn registration_detail(text: Option<String>, target: &Path, argument: Option<&str>, language: Language) -> io::Result<String> {
    let text = text.ok_or_else(|| io::Error::other(language.text(if argument.is_some() {
        "cli.doctor.detail.com_missing"
    } else {
        "cli.doctor.detail.service_missing"
    })))?;
    let normalized = text.replace('/', "\\").to_lowercase();
    if !normalized.contains(&normalized_path(&target.to_string_lossy()))
        || argument.is_some_and(|argument| !text.contains(argument))
    {
        let key = if argument.is_some() {
            "cli.doctor.detail.activation_stale"
        } else {
            "cli.doctor.detail.service_wrong_path"
        };
        return Err(io::Error::other(language.translate(key, &[("command", &text)])));
    }
    Ok(if argument.is_some() { text } else { target.display().to_string() })
}

fn machine_path(root: &Path, language: Language) -> io::Result<Value> {
    match windows::registry_dword(
        HKEY_LOCAL_MACHINE,
        r"Software\SunPack",
        "PathAddedByInstaller",
    )? {
        None => return Ok(check("machine_path", "skip", language.text("cli.doctor.detail.not_enabled_by_installer"))),
        Some(1) => {}
        Some(value) => {
            return Ok(check(
                "machine_path",
                "fail",
                language.translate("cli.doctor.detail.install_marker_invalid", &[("value", &value.to_string())]),
            ))
        }
    }
    let path = windows::registry_text(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        "Path",
    )?
    .ok_or_else(|| io::Error::other(language.text("cli.doctor.detail.path_unavailable")))?;
    let entries: Vec<_> = path.split(';').map(normalized_path).collect();
    if entries.contains(&normalized_path(&root.to_string_lossy())) {
        return Ok(check(
            "machine_path",
            "fail",
            language.text("cli.doctor.detail.path_exposes_dlls"),
        ));
    }
    if !entries.contains(&normalized_path(&root.join("bin").to_string_lossy())) {
        return Ok(check(
            "machine_path",
            "fail",
            language.text("cli.doctor.detail.install_marker_missing_launcher"),
        ));
    }
    Ok(check(
        "machine_path",
        "ok",
        root.join("bin").display().to_string(),
    ))
}

fn context_menu(root: &Path, language: Language) -> io::Result<Value> {
    let parents = [
        r"Software\Classes\Directory\shell\SunPack",
        r"Software\Classes\Directory\Background\shell\SunPack",
        r"Software\Classes\*\shell\SunPack",
    ];
    let mut count = 0;
    for parent in parents {
        count += usize::from(windows::registry_key_exists(HKEY_LOCAL_MACHINE, parent)?);
    }
    if count == 0 {
        return Ok(check("context_menu", "skip", language.text("cli.doctor.detail.not_installed")));
    }
    if count != parents.len() {
        return Ok(check("context_menu", "fail", language.text("cli.doctor.detail.menu_incomplete")));
    }
    let target = normalized_path(&root.join("bin/sunpack.exe").to_string_lossy());
    for class in [
        "SunPack.FolderContextMenu",
        "SunPack.BackgroundContextMenu",
        "SunPack.FileContextMenu",
    ] {
        let key = format!(r"Software\Classes\{class}\shell\DirectExtract\command");
        let command = windows::registry_text(HKEY_LOCAL_MACHINE, &key, "")?
            .ok_or_else(|| io::Error::other(language.translate("cli.doctor.detail.command_missing", &[("key", &key)])))?;
        if !command.replace('/', "\\").to_lowercase().contains(&target) {
            return Ok(check(
                "context_menu",
                "fail",
                language.translate("cli.doctor.detail.command_wrong_launcher", &[("command", &command)]),
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
    let key = format!("cli.doctor.check.{name}");
    language.lookup(&key).map_or(key, str::to_owned)
}

#[cfg(test)]
#[path = "../../tests/unit/runtime/doctor/tests.rs"]
mod tests;
