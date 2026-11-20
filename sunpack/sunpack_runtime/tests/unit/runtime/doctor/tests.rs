use super::*;

#[test]
fn service_and_toast_registration_keep_their_diagnostic_contracts() {
    let target = Path::new(r"C:\SunPack\service\sunpack-watch-broker.exe");
    let command = format!("\"{}\" --service", target.display());
    assert_eq!(registration_detail(Some(command), target, None, Language::En).unwrap(), target.display().to_string());
    assert_eq!(registration_detail(None, target, None, Language::En).unwrap_err().to_string(), "service is not installed");
    assert_eq!(registration_detail(Some("old.exe".into()), target, None, Language::En).unwrap_err().to_string(), "service points to: old.exe");
    let target = Path::new(r"C:\SunPack\bin\sunpack.exe");
    let argument = Some("--toast-activated");
    let command = format!("\"{}\" --toast-activated", target.display());
    assert_eq!(registration_detail(Some(command.clone()), target, argument, Language::En).unwrap(), command);
    assert_eq!(registration_detail(None, target, argument, Language::En).unwrap_err().to_string(), "machine COM registration is missing");
    assert_eq!(registration_detail(Some(target.display().to_string()), target, argument, Language::En).unwrap_err().to_string(), format!("activation command is stale: {}", target.display()));
    assert_eq!(registration_detail(None, target, argument, Language::Ko).unwrap_err().to_string(), "시스템 COM 등록이 없습니다");
}
