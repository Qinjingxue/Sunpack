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

    let seven_zip = std::path::Path::new("../sevenzip_bridge/7z2604-src/C");
    cc::Build::new()
        .include(seven_zip)
        .file(seven_zip.join("Blake2s.c"))
        .file(seven_zip.join("CpuArch.c"))
        .file("src/password/rar_blake2sp.c")
        .warnings(false)
        .compile("sunpack_blake2sp");
    println!("cargo:rerun-if-changed={}", seven_zip.display());
    println!("cargo:rerun-if-changed=src/password/rar_blake2sp.c");

    let ppmd_header = "src/formats/seven_zip/header/ppmd.c";
    cc::Build::new()
        .include(seven_zip)
        .file(seven_zip.join("Ppmd7.c"))
        .file(seven_zip.join("Ppmd7Dec.c"))
        .file(ppmd_header)
        .warnings(false)
        .compile("sunpack_ppmd7");
    println!("cargo:rerun-if-changed={ppmd_header}");

    let cpp = seven_zip.join("../CPP");
    let deflate64_header = "src/formats/seven_zip/header/deflate64.cpp";
    let mut deflate64 = cc::Build::new();
    deflate64
        .cpp(true)
        .include(&seven_zip)
        .include(&cpp)
        .define("NOMINMAX", None)
        .define("MidAlloc", "SunpackDeflate64Alloc")
        .define("MidFree", "SunpackDeflate64Free")
        .flag_if_supported("/EHsc")
        .warnings(false);
    for name in [
        "7zip/Compress/BitlDecoder.cpp",
        "7zip/Compress/DeflateDecoder.cpp",
        "7zip/Compress/LzOutWindow.cpp",
        "7zip/Common/InBuffer.cpp",
        "7zip/Common/OutBuffer.cpp",
    ] {
        deflate64.file(cpp.join(name));
    }
    deflate64.file(deflate64_header).compile("sunpack_deflate64");
    println!("cargo:rerun-if-changed={}", cpp.display());
    println!("cargo:rerun-if-changed={deflate64_header}");

    let rar_crypto = seven_zip.join("../CPP/7zip/Crypto");
    let rar2_prefix = "src/password/rar2_crypto.cpp";
    cc::Build::new()
        .cpp(true)
        .include(&rar_crypto)
        .define("g_CrcTable", "sunpack_password_crc_table")
        .file(rar_crypto.join("Rar20Crypto.cpp"))
        .file(rar2_prefix)
        .warnings(false)
        .compile("sunpack_rar2_crypto");
    println!("cargo:rerun-if-changed={}", rar_crypto.display());
    println!("cargo:rerun-if-changed={rar2_prefix}");

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
