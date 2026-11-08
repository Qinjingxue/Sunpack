# sunpack_native

Rust/PyO3 extension module for narrow native helpers used by SunPack.

This crate should stay focused on cross-platform filesystem and byte-structure
hot paths. Python remains responsible for configuration, rule decisions,
task orchestration, and error reporting. Embedded 7-Zip extraction lives in the
separate C++ `native/sevenzip_bridge` worker component.

## Build

```powershell
uv sync --locked --extra build
.\.venv\Scripts\maturin.exe build --manifest-path native\sunpack_native\Cargo.toml --release --target-dir .cache\rust-target\x64
```

Install the generated wheel:

```powershell
$wheel = Get-ChildItem .cache\rust-target\x64\wheels\sunpack_native-*.whl | Select-Object -First 1 -ExpandProperty FullName
uv pip uninstall --python .\.venv\Scripts\python.exe sunpack-native
uv pip install --python .\.venv\Scripts\python.exe --reinstall $wheel
```

Smoke test:

```powershell
.\.venv\Scripts\python.exe -c "import sunpack_native; print(sunpack_native.native_available())"
```

## API

`native_available()` returns `True` from the native module and is used by smoke
tests to confirm the extension was imported.


`NativeDirectoryScanOptions.scan(...)` walks a directory tree, applies the configured
filesystem filters, and returns filtered and raw `NativeDirectorySnapshot` views. Entry data stays
in four native columns (`path`, `is_dir`, `size`, and `mtime_ns`); the normal
scan path does not create per-entry Python dictionaries, `Path` objects, or
`FileEntry` objects. Custom filters must be expressible through native scan
parameters or the caller fails explicitly.

`NativePathRule(paths, files, extensions, full_names)` compiles one immutable rule
shared by directory scans, watch catalogs, output inventories and Python entry
filters. All fields contain `{ "value": "...", "regex": false }` records. Ordinary
rules support only `*` and `?`, anchored to the whole selected string and never
crossing `/`; remaining characters are literal. Matching is case-sensitive.
Names without wildcards use one exact set for ASCII and Unicode, with no case
conversion or literal regex fallback. Regex records
use the existing regex-automata engine, with one combined matcher per group.
No separate Glob or extension engine is used. The three file selectors use the
same fixed array of text matchers and one evaluation loop. `files` selects the
stem before the last dot, `extensions` selects the suffix without its dot, and
`full_names` selects the entire basename. The candidate caches its UTF-8 filename
and last-dot offset lazily; all rules borrow slices without allocating names or
extension strings. No dot means no extension; a final dot means an empty extension.
Filename rules only match files;
path rules match normalized root-relative paths and inherit directory matches.
Bare literal names match any component; literals containing `/` are root-relative.
Blacklist fields use OR; whitelist nonempty fields use AND, with OR within each
field. Anchored regex prefixes are extracted through regex-syntax to preserve
safe directory pruning using direct string prefixes, including Unicode.
Unknown prefix relations stay open.

Compiled rules are shared through `Arc`. Each native scan, watch operation or
inventory batch owns its lazy search caches and releases them on completion.
The explicit-cache APIs bypass the engine's internal search pool. The lazy-DFA
acceleration budget is 256 KiB per matcher cache; a full cache can be cleared or
the engine falls back to an NFA. This budget does not bound total rule memory.
There is no global/thread-local history of patterns or filenames. Python entry
filters use one native batch call instead of creating a cache per file.

`profile_directory_scan(...)` is the diagnostic equivalent. It returns the
same native snapshot plus regex compiled/cache byte estimates and nanosecond counters for directory enumeration,
metadata reads, path matching, native record construction, traversal overhead,
and snapshot construction. The reproducible benchmark driver is
`python -m benchmarks scan directory`; its `fresh-process` mode resets
Python/PyO3 process state but does not flush the operating-system file cache.

`list_regular_files_in_directory(directory)` lists regular files directly under
one directory and returns path/size/mtime metadata. This is intentionally a thin
filesystem helper used by relation grouping; Python still owns split-volume
semantics and grouping decisions.

`scan_embedded_archives(path)` performs one extension-independent sequential
scan for all supported embedded archive signatures. Every identity candidate
must pass its format-specific structural checks; the complete hit map is also
returned so the analysis stage can reuse the scan without another full-stream
signature pass.

Return value:

```python
{"complete": True, "candidates": [{"format": "7z", "offset": 123}], "hits": [...]}
```

An empty `candidates` list means no reliable embedded identity was found.

`analyze_zip_filename_encoding(archive_input)` consumes the canonical serialized
archive-input descriptor. It reads the logical ZIP central directory across file
ranges or multipart inputs and scores filename codepages in Rust without the
Python GIL. It returns a codepage string such as `"932"` or `None` when extraction
can use the ZIP handler's default filename decoding.

The module also exposes lightweight structure inspectors used by the detection
pipeline:

- `inspect_compression_stream_structure`
- `inspect_pe_overlay_structure`

These functions preserve the Python result shapes. During the current test
phase the application treats this native extension as required; missing native
functions or native errors should fail fast instead of falling back to Python
parsers.
