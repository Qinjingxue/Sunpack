use super::config::ProcessMode;
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::OsStrExt,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    os::windows::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    ptr::{null, null_mut},
    sync::Mutex,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, LUID},
    Security::{
        AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueW,
        SecurityImpersonation, TokenElevation, TokenPrimary, LUID_AND_ATTRIBUTES,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
        TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::{
            CreateProcessWithTokenW, GetCurrentProcess, OpenProcess, OpenProcessToken,
            SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS, CREATE_NO_WINDOW,
            CREATE_UNICODE_ENVIRONMENT, HIGH_PRIORITY_CLASS, LOGON_WITH_PROFILE,
            NORMAL_PRIORITY_CLASS, PROCESS_INFORMATION, PROCESS_MODE_BACKGROUND_BEGIN,
            PROCESS_MODE_BACKGROUND_END, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
        },
    },
    UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId},
};

pub(crate) struct KillOnCloseJob {
    _handle: OwnedHandle,
}

impl KillOnCloseJob {
    pub(crate) fn attach(child: &Child) -> io::Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        };
        if configured == 0
            || unsafe { AssignProcessToJobObject(handle.as_raw_handle(), child.as_raw_handle()) }
                == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { _handle: handle })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AppliedMode {
    Background,
    BelowNormal,
    Normal,
    High,
}

pub(crate) fn apply_mode(mode: ProcessMode) -> io::Result<()> {
    static APPLIED: Mutex<AppliedMode> = Mutex::new(AppliedMode::Normal);
    let mut applied = APPLIED.lock().unwrap_or_else(|error| error.into_inner());
    let requested = match mode {
        ProcessMode::Background => AppliedMode::Background,
        ProcessMode::Normal => AppliedMode::Normal,
        ProcessMode::High => AppliedMode::High,
    };
    if *applied == requested
        || (requested == AppliedMode::Background && *applied == AppliedMode::BelowNormal)
    {
        return Ok(());
    }
    let set_priority = |priority| {
        if unsafe { SetPriorityClass(GetCurrentProcess(), priority) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    if *applied == AppliedMode::Background {
        set_priority(PROCESS_MODE_BACKGROUND_END)?;
        *applied = AppliedMode::Normal;
    }
    if requested == AppliedMode::Background && *applied == AppliedMode::High {
        set_priority(NORMAL_PRIORITY_CLASS)?;
        *applied = AppliedMode::Normal;
    }
    let changed = match requested {
        AppliedMode::Background => {
            if set_priority(PROCESS_MODE_BACKGROUND_BEGIN).is_ok() {
                AppliedMode::Background
            } else {
                set_priority(BELOW_NORMAL_PRIORITY_CLASS)?;
                AppliedMode::BelowNormal
            }
        }
        AppliedMode::High => {
            set_priority(HIGH_PRIORITY_CLASS)?;
            AppliedMode::High
        }
        _ => {
            set_priority(NORMAL_PRIORITY_CLASS)?;
            AppliedMode::Normal
        }
    };
    *applied = changed;
    Ok(())
}

struct PriorityPolicy {
    configured: ProcessMode,
    foreground: usize,
    foreground_override: bool,
}

static PRIORITY: Mutex<PriorityPolicy> = Mutex::new(PriorityPolicy {
    configured: ProcessMode::Normal,
    foreground: 0,
    foreground_override: false,
});

impl PriorityPolicy {
    fn effective(&self) -> ProcessMode {
        if self.foreground_override {
            ProcessMode::High
        } else {
            self.configured
        }
    }

    fn enter_foreground(&mut self) {
        self.foreground += 1;
        self.foreground_override = true;
    }

    fn leave_foreground(&mut self) {
        self.foreground -= 1;
    }

    fn expire_foreground_override(&mut self) {
        if self.foreground == 0 {
            self.foreground_override = false;
        }
    }
}

pub(crate) fn foreground_active() -> bool {
    PRIORITY
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .foreground != 0
}

pub(crate) fn effective_mode() -> ProcessMode {
    PRIORITY
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .effective()
}

pub(crate) fn configure_mode(mode: ProcessMode) -> io::Result<()> {
    let mut priority = PRIORITY.lock().unwrap_or_else(|error| error.into_inner());
    priority.configured = mode;
    apply_mode(priority.effective())
}

pub(crate) fn expire_foreground_override() -> io::Result<()> {
    let mut priority = PRIORITY.lock().unwrap_or_else(|error| error.into_inner());
    priority.expire_foreground_override();
    apply_mode(priority.effective())
}

pub(crate) struct ForegroundPriority;

impl ForegroundPriority {
    pub(crate) fn enter() -> Self {
        let mut priority = PRIORITY.lock().unwrap_or_else(|error| error.into_inner());
        priority.enter_foreground();
        let _ = apply_mode(priority.effective());
        Self
    }
}

impl Drop for ForegroundPriority {
    fn drop(&mut self) {
        let mut priority = PRIORITY.lock().unwrap_or_else(|error| error.into_inner());
        // Watch owns expiry after its idle interval. Without Watch, the runtime
        // expires the override as soon as the last foreground request leaves.
        priority.leave_foreground();
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn process_token(process: HANDLE, access: u32) -> io::Result<OwnedHandle> {
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(process, access, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn elevated(token: &OwnedHandle) -> io::Result<bool> {
    let mut info = TOKEN_ELEVATION::default();
    let mut size = std::mem::size_of_val(&info) as u32;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut info as *mut TOKEN_ELEVATION).cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info.TokenIsElevated != 0)
}

fn interactive_token() -> io::Result<OwnedHandle> {
    let window = unsafe { GetShellWindow() };
    if window.is_null() {
        return Err(io::Error::other(
            "The interactive Windows shell is unavailable",
        ));
    }
    let mut pid = 0;
    if unsafe { GetWindowThreadProcessId(window, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let shell = process_token(process.as_raw_handle(), TOKEN_DUPLICATE | TOKEN_QUERY)?;
    let mut token = null_mut();
    if unsafe {
        DuplicateTokenEx(
            shell.as_raw_handle(),
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

fn enable_impersonation_privilege() -> io::Result<()> {
    let token = process_token(
        unsafe { GetCurrentProcess() },
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
    )?;
    let mut luid = LUID::default();
    let name = wide(OsStr::new("SeImpersonatePrivilege"));
    if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let enabled = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    if unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &enabled,
            0,
            null_mut(),
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn quoted_argument(command: &mut Vec<u16>, argument: &OsStr) {
    const QUOTE: u16 = b'"' as u16;
    const SLASH: u16 = b'\\' as u16;
    command.push(QUOTE);
    let mut slashes = 0;
    for unit in argument.encode_wide() {
        if unit == SLASH {
            slashes += 1;
            continue;
        }
        command.extend(std::iter::repeat_n(
            SLASH,
            if unit == QUOTE {
                slashes * 2 + 1
            } else {
                slashes
            },
        ));
        command.push(unit);
        slashes = 0;
    }
    command.extend(std::iter::repeat_n(SLASH, slashes * 2));
    command.push(QUOTE);
}

pub(crate) fn launch_unelevated(
    executable: &Path,
    args: &[OsString],
    cwd: &Path,
) -> io::Result<()> {
    let token = process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)?;
    if !elevated(&token)? {
        Command::new(executable)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()?;
        // Child has no blocking Drop. Close the process/thread handles now.
        return Ok(());
    }

    let shell = interactive_token()?;
    let _ = enable_impersonation_privilege();
    let executable_path = wide(executable.as_os_str());
    let working_directory = wide(cwd.as_os_str());
    let desktop = wide(OsStr::new("winsta0\\default"));
    let mut command = Vec::new();
    quoted_argument(&mut command, executable.as_os_str());
    for argument in args {
        command.push(b' ' as u16);
        quoted_argument(&mut command, argument);
    }
    command.push(0);
    let mut variables: Vec<_> = std::env::vars_os().collect();
    variables.sort_by_cached_key(|(key, _)| key.to_string_lossy().to_ascii_uppercase());
    let mut environment = Vec::new();
    for (key, value) in variables {
        environment.extend(key.encode_wide());
        environment.push(b'=' as u16);
        environment.extend(value.encode_wide());
        environment.push(0);
    }
    if environment.is_empty() {
        environment.push(0);
    }
    environment.push(0);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpDesktop: desktop.as_ptr().cast_mut(),
        ..STARTUPINFOW::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    let created = unsafe {
        CreateProcessWithTokenW(
            shell.as_raw_handle(),
            LOGON_WITH_PROFILE,
            executable_path.as_ptr(),
            command.as_mut_ptr(),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            working_directory.as_ptr(),
            &startup,
            &mut process,
        )
    };
    if created == 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        drop(OwnedHandle::from_raw_handle(process.hThread));
        drop(OwnedHandle::from_raw_handle(process.hProcess));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreground_priority_survives_completion_until_idle_maintenance() {
        // Covers retained CLI QoS, overlapping requests, and config reload with
        // one pure policy scenario; no global priority changes or timed waits.
        let mut policy = PriorityPolicy {
            configured: ProcessMode::Background,
            foreground: 0,
            foreground_override: false,
        };
        assert_eq!(policy.effective(), ProcessMode::Background);
        policy.enter_foreground();
        policy.enter_foreground();
        assert_eq!(policy.effective(), ProcessMode::High);
        policy.leave_foreground();
        policy.expire_foreground_override();
        assert_eq!(policy.effective(), ProcessMode::High);
        policy.configured = ProcessMode::Normal;
        assert_eq!(policy.effective(), ProcessMode::High);
        policy.leave_foreground();
        assert_eq!(policy.foreground, 0);
        assert_eq!(policy.effective(), ProcessMode::High);
        // A request arriving before maintenance must protect the same override.
        policy.enter_foreground();
        policy.expire_foreground_override();
        assert_eq!(policy.effective(), ProcessMode::High);
        policy.leave_foreground();
        policy.expire_foreground_override();
        assert_eq!(policy.effective(), ProcessMode::Normal);
        policy.configured = ProcessMode::Background;
        assert_eq!(policy.effective(), ProcessMode::Background);
        // The no-Watch path can expire immediately after the final release.
        policy.enter_foreground();
        policy.leave_foreground();
        policy.expire_foreground_override();
        policy.expire_foreground_override();
        assert_eq!(policy.effective(), ProcessMode::Background);
    }
}
