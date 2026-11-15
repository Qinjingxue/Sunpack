use super::*;

#[test]
fn source_layout_finds_its_own_checkout_from_the_runtime_executable() {
    let temp = env::temp_dir().join(format!("sunpack-resource-roots-{}", std::process::id()));
    let application = temp.join("application");
    std::fs::create_dir_all(application.join("sunpack")).unwrap();
    std::fs::write(application.join("sunpack/Cargo.toml"), "[workspace]").unwrap();
    let exe = application.join(".cache/rust-target/target/ci/sunpack-runtime.exe");
    assert_eq!(checkout_root(&exe), Some(application));
    std::fs::remove_dir_all(temp).unwrap();
}

#[test]
fn source_launcher_uses_the_runtime_build_profile_without_package_staging() {
    let root = Path::new("checkout");
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    for profile in ["ci", "release"] {
        let exe = root.join(".cache/rust-target").join("target").join(profile).join("sunpack-runtime.exe");
        assert_eq!(development_launcher(root, &exe).unwrap(), root.join(format!(".cache/native/{arch}/{profile}/sevenzip_bridge/Release/sunpack_launcher.exe")));
    }
    assert!(development_launcher(root, &root.join("debug/sunpack-runtime.exe")).is_err());
}

#[test]
fn toast_lookup_uses_the_runtime_architecture_and_profile() {
    let root = Path::new("checkout");
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "x64" };
    for profile in ["ci", "release"] {
        let exe = root.join(".cache/rust-target/target").join(profile).join("sunpack-runtime.exe");
        let path = development_artifact(root, &exe, "toast_host", "sunpack_toast.dll").unwrap();
        assert_eq!(path, root.join(format!(".cache/native/{arch}/{profile}/toast_host/Release/sunpack_toast.dll")));
    }
}
