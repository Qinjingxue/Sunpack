fn main() {
    let root = std::path::Path::new("../third_party/lz4");
    let mut build = cc::Build::new();
    build
        .include(root)
        .include("../lz4_stream")
        .define("XXH_NAMESPACE", "SUNPACK_LZ4_")
        .warnings(false);
    for name in ["lz4.c", "lz4hc.c", "lz4frame.c", "xxhash.c"] {
        build.file(root.join(name));
    }
    build.file("../lz4_stream/stream.c").compile("sunpack_lz4");
    println!("cargo:rerun-if-changed=../third_party/lz4");
    println!("cargo:rerun-if-changed=../lz4_stream");

    let target = std::env::var("TARGET").expect("Cargo build target");
    if target.ends_with("-windows-msvc") {
        embed_windows_resources(&target);
    }
}

fn embed_windows_resources(target: &str) {
    use std::{env, fs, path::PathBuf, process::Command};

    let root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("crate directory")).join("../..");
    let icon = root.join("sunpack.ico");
    let manifest = root.join("sunpack.manifest");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo output directory"));
    let source = out.join("sunpack.rc");
    let resource = out.join("sunpack.res");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", manifest.display());
    let quoted = |path: &std::path::Path| path.to_string_lossy().replace('\\', "/");
    fs::write(
        &source,
        format!(
            "1 ICON \"{}\"\r\n1 24 \"{}\"\r\n",
            quoted(&icon),
            quoted(&manifest)
        ),
    )
    .expect("write Windows resource script");
    let mut command = cc::windows_registry::find_tool(target, "rc.exe")
        .map(|tool| tool.to_command())
        .unwrap_or_else(|| {
            let mut command = Command::new("rc.exe");
            // Cargo can locate the linker through Visual Studio discovery even
            // in a plain PowerShell where the SDK is absent from PATH.
            if let Some(linker) = cc::windows_registry::find_tool(target, "link.exe") {
                command.envs(linker.env().iter().map(|(key, value)| (key, value)));
            }
            command
        });
    let status = command
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(&source)
        .status()
        .expect("start the Windows SDK resource compiler");
    assert!(
        status.success(),
        "Windows resource compiler failed: {status}"
    );
    println!("cargo:rustc-link-arg-bin=sunpack-runtime=/MANIFEST:NO");
    println!(
        "cargo:rustc-link-arg-bin=sunpack-runtime={}",
        resource.display()
    );
}
