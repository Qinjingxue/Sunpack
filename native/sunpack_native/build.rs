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
}
