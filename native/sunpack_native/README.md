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


`scan_directory_snapshot(...)` walks a directory tree, applies every built-in
filesystem filter, and returns one `NativeDirectorySnapshot`. Entry data stays
in four native columns (`path`, `is_dir`, `size`, and `mtime_ns`); the normal
scan path does not create per-entry Python dictionaries, `Path` objects, or
`FileEntry` objects. Custom filters must be expressible through native scan
parameters or the caller fails explicitly.

Exact `prune_dir_globs` are matched through a case-insensitive name set;
wildcards are compiled into a regex set. Path patterns match paths relative to
the selected scan root, and rejected directories are never descended into.

`profile_directory_scan(...)` is the diagnostic equivalent. It returns the
same native snapshot plus nanosecond counters for directory enumeration,
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

`scan_after_markers(path, markers, archive_magics, tail_start, file_size, allow_full_scan)`
searches for archive magic bytes after carrier markers.

- `markers`: list of carrier marker bytes, such as JPEG EOF bytes.
- `archive_magics`: list of `(magic_bytes, detected_ext)` pairs.
- `tail_start` and `file_size`: define the tail scan range.
- `allow_full_scan`: when true, scan before the tail range if the tail scan misses.

Return value:

```python
{"detected_ext": ".7z", "offset": 123, "scan_scope": "tail"}
```

or `None` when no marker/magic pair is found.

`scan_magics_anywhere(path, archive_magics, min_offset, max_hits, end_offset=None)`
streams through a file and collects archive magic hits.

- `archive_magics`: list of `(magic_bytes, detected_ext)` pairs.
- `min_offset`: first byte offset to scan.
- `max_hits`: maximum number of hits to return.
- `end_offset`: optional exclusive end offset.

Return value:

```python
[{"detected_ext": ".zip", "offset": 123, "scan_scope": ""}]
```

`scan_zip_central_directory_names(path, max_samples, max_filename_bytes)`
reads ZIP central-directory metadata and returns raw filename samples for
encoding detection. ZIP64 central directory parsing is intentionally not handled
here; Python reports the unsupported status instead of reparsing it.

Return value:

```python
{
    "status": "ok",
    "raw_names": [b"name.txt"],
    "utf8_flags": [true],
    "unicode_path_names": [None],
    "truncated": False,
}
```

`unicode_path_names` 与 `raw_names` 一一对应；元素仅在中央目录中的
Info-ZIP Unicode Path Extra Field (`0x7075`) 版本、原始文件名 CRC32 和
UTF-8 载荷均校验成功时返回 `bytes`，否则为 `None`。

The module also exposes lightweight structure inspectors used by the detection
pipeline:

- `inspect_zip_local_header`
- `inspect_zip_eocd_structure`
- `inspect_seven_zip_structure`
- `inspect_rar_structure`
- `inspect_tar_header_structure`
- `inspect_compression_stream_structure`
- `inspect_pe_overlay_structure`

These functions preserve the Python result shapes. During the current test
phase the application treats this native extension as required; missing native
functions or native errors should fail fast instead of falling back to Python
parsers.
