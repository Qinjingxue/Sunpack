from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from functools import lru_cache
import re
import shutil

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CACHE = ROOT / "benchmarks/.cache/hit-index"
NATIVE = ROOT / "benchmarks/native/hit_index"


def write_generated(path: Path, text: str) -> None:
    # Preserve mtimes for identical build inputs. Rewriting generated Rust on
    # every shard would relink the reference DLL and change its PE identity.
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        path.write_text(text, encoding="utf-8")


@lru_cache(maxsize=1)
def environment() -> dict[str, str]:
    env = {key.upper(): value for key, value in os.environ.items()}
    if not env.get("INCLUDE"):
        script = Path(env.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/2022/BuildTools/VC/Auxiliary/Build/vcvars64.bat"
        result = subprocess.check_output(f'cmd.exe /d /s /c ""{script}" >nul && set"')
        for line in result.decode("mbcs", errors="replace").splitlines():
            if "=" in line and not line.startswith("="):
                key, value = line.split("=", 1)
                env[key.upper()] = value
    llvm = Path(env.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/2022/BuildTools/VC/Tools/Llvm/x64/bin"
    env["PATH"] = os.pathsep.join([str(llvm), sys.base_prefix, str(Path(sys.base_prefix) / "DLLs"), env.get("PATH", "")])
    env["PYO3_PYTHON"] = sys.executable
    return env


def command(args, *, cwd=ROOT, env=None) -> str:
    args = [str(x) for x in args]
    if env is not None:
        args[0] = shutil.which(args[0], path=env.get("PATH")) or args[0]
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def sources(*, fetch: bool) -> dict:
    lock = json.loads((HERE / "sources.lock.json").read_text(encoding="utf-8"))
    for name, item in lock.items():
        path = CACHE / "sources" / name
        ready = subprocess.run(["git", "-C", str(path), "rev-parse", "--verify", "HEAD"], capture_output=True).returncode == 0 if path.exists() else False
        if not ready:
            if not fetch:
                raise RuntimeError(f"Missing {name}; use --fetch once to retrieve pinned benchmark sources")
            path.mkdir(parents=True, exist_ok=True)
            if not (path / ".git").is_dir():
                command(["git", "init", "-q", path])
                command(["git", "-C", path, "remote", "add", "origin", "https://github.com/" + item["repository"] + ".git"])
            command(["git", "-C", path, "sparse-checkout", "set", "--no-cone", "/*", "!/*/", "/src/", "/headers/", "/include/", "/cpp/", "/cmake/", "/cmake_modules/", "/tools/cmake/", "/tests/config.h.in"])
            command(["git", "-c", "http.version=HTTP/1.1", "-C", path, "fetch", "--filter=blob:none", "--depth=1", "origin", item["commit"]])
            command(["git", "-C", path, "checkout", "--detach", "FETCH_HEAD"])
        actual = command(["git", "-C", path, "rev-parse", "HEAD"]).strip()
        if actual != item["commit"] or command(["git", "-C", path, "status", "--porcelain"]).strip():
            raise RuntimeError(f"Pinned source identity mismatch or modified checkout: {path}")
        item["path"] = str(path)
    return lock


def bridge(*, source_root: Path = ROOT, meter: bool = False, destination: Path | None = None) -> Path:
    source_root = source_root.resolve()
    if source_root != ROOT and destination is None:
        raise ValueError("A candidate source root requires an explicit destination, separate from the reference probe")
    dest = (destination or CACHE / ("bridge-meter" if meter else "bridge")).resolve()
    (dest / "src/scan").mkdir(parents=True, exist_ok=True)
    native = source_root / "native/sunpack_native/src"
    root = (NATIVE / "bridge_root.rs").read_text(encoding="utf-8")
    embedded = (native / "scan/embedded.rs").read_text(encoding="utf-8")
    begin = embedded.index("#[derive(Debug, Clone, PartialEq, Eq)]\n#[repr(C)]\nstruct RawHit")
    end = embedded.index("pub(crate) struct NativeScanResult", begin)
    original_types = embedded[begin:end]
    patterns = embedded[embedded.index("const PATTERNS:"):embedded.index("#[cfg(target_arch", embedded.index("const PATTERNS:"))]
    names = re.findall(r'\([^,\n]+,\s*"([^"]+)",\s*"([^"]+)"\)', patterns)
    if len(names) != 13:
        raise RuntimeError("Signature schema changed; update protocol/adapter explicitly")
    declarations = 'const PATTERNS:[(&[u8],&str,&str);13]=[' + ','.join('(b"",'+json.dumps(name)+','+json.dumps(kind)+')' for name,kind in names) + '];\n'
    root = root.replace("// BENCHMARK_PRODUCTION_TYPES", declarations + original_types)
    for key, path in [("PATH_KEYS", native / "path_keys.rs"), ("FAST_HASH_CORE", native / "fast_hash_core.rs"), ("RESOURCE_LIFECYCLE", native / "io/resource_lifecycle.rs"), ("SCRATCH", native / "io/scratch.rs")]:
        root = root.replace(key, path.as_posix())
    write_generated(dest / "src/lib.rs", root)
    source = (native / "scan/hit_storage.rs").read_text(encoding="utf-8")
    write_generated(dest / "src/scan/hit_storage.rs", source + "\n" + (NATIVE / "bridge.rs").read_text(encoding="utf-8"))
    write_generated(dest / "Cargo.toml", '''[package]
name = "sunpack-hit-index-probe"
edition = "2021"
[lib]
crate-type = ["cdylib"]
[features]
allocation-meter = []
[dependencies]
rayon = "1.10"
serde = { version = "1", features = ["derive", "rc"] }
rmp-serde = "1"
pyo3 = { version = "0.29", features = ["extension-module"] }
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
''')
    env = environment()
    command(["cargo", "build", "--release", "--offline", "--manifest-path", dest / "Cargo.toml",
             *(["--features", "allocation-meter"] if meter else [])], env=env)
    return dest / "target/release/sunpack_hit_index_probe.dll"


def backends(*, fetch: bool) -> tuple[Path, dict]:
    pins = sources(fetch=fetch)
    build = CACHE / "cpp"
    generated = build / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    faw = (CACHE / "sources/faw/faw_encoding.h").read_text(encoding="utf-8")
    faw = faw[faw.index("unsigned int* encode("):faw.index("void show_items(")]
    # Keep the unmodified author artifact as `faw`. This separate, explicitly
    # named repair prevents a known implementation defect from becoming an
    # artificial algorithmic advantage for SunPack.
    repaired = faw.replace("unsigned int* encode(", "unsigned int* faw_repaired_encode(").replace("dif==1+tWord", "dif==tWord").replace("fWord = arr[i];", "fWord = arr[i]; fWordType = 0;")
    write_generated(generated / "faw_repaired.hpp", repaired)
    write_generated(generated / "faw-repair.json", json.dumps({"upstream_commit": pins["faw"]["commit"], "changes": ["FR continuation: dif==1+tWord -> dif==tWord", "reset fWordType when establishing a new base word"], "label": "faw-repaired; locally repaired artifact, not unchanged upstream"}, indent=2))
    env = environment()
    vsroot = Path(env.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/2022/BuildTools"
    ninja = vsroot / "Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe"
    command(["cmake", "-S", NATIVE, "-B", build, "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja}", "-DCMAKE_C_COMPILER=clang-cl", "-DCMAKE_CXX_COMPILER=clang-cl", "-DCMAKE_BUILD_TYPE=Release", f"-DBASELINE_ROOT={CACHE / 'sources'}"], env=env)
    command(["cmake", "--build", build, "--parallel", "8"], env=env)
    return build / "hit_index_benchmark.exe", pins


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--bridge", action="store_true")
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--meter", action="store_true")
    args = parser.parse_args()
    if args.bridge:
        print(bridge(source_root=args.source_root, destination=args.output_root, meter=args.meter))
    else:
        print(json.dumps(sources(fetch=args.fetch), indent=2))


if __name__ == "__main__":
    main()
