# Real archive regression coverage

Use `.venv/Scripts/python.exe -m pytest tests/real`. Watch tests additionally
require the isolated Broker environment established by `run_acceptance_tests.ps1`.

The new regression cases cover:

* Plan 5 constructs carriers once with a declared seed. Rust streams source
  files into the carrier and records byte offsets/lengths independently of the
  scanner. Scanner failures cannot cause fixture regeneration. Fixed fake
  signatures, adjacent equal-format archives and signatures crossing 64 KiB /
  1 MiB boundaries have separate tests.
* `test_combined_nested_lifecycle.py` sends encrypted, disguised split 7z/ZIP/RAR
  through the real CLI. Inside are a carrier, a differently encrypted 7z and
  healthy / separately encrypted ZIP branches. A mixed-group Pipeline case
  covers concurrent failures, output hashes, deletion and flattening.
* Plan 7 adds late-tail delivery, a restart with incomplete volumes, a second
  restart with a retained inner password failure, and a directory-password
  update. Generated inner tasks inherit the original input password scope;
  the test asserts that scope before triggering the update.
* `test_external_structure_corpus.py` generates self-authored samples using
  Windows bsdtar/libarchive and WinRAR, independently of SunPack/7-Zip's usual
  fixture writer. It checks USTAR, PAX long Unicode paths, GNU longname,
  duplicate TAR/ZIP members, empty ZIP, legacy CP437 ZIP and solid RAR5 under
  plain names, disguised names and junk-prefixed/suffixed carriers. Expected
  output paths, sizes and SHA-256 come from source files, not extraction output.

Samples are generated once per structure per test module and reused for all
three container variants. The ignored `tests/real/corpus/` directory is optional;
a clean checkout can collect and run these tests without it. To generate an
inspectable corpus with tool/command/artifact provenance:

```powershell
.venv/Scripts/python.exe -m scripts.generate_real_structure_corpus
```

Binary assembly and hashing use the test-only Cargo example `real_fixture`,
with bounded 64 KiB buffers. It is built with the workspace's existing locked
dependencies and does not add production APIs or dependencies. Python reads
only text manifests and orchestrates existing fixture/tool paths.

## Known regression

The unlabelled libarchive CP437 ZIP with `café/über.txt` currently extracts that
name with private-use characters on this Windows environment. The native
encoding analysis elects not to override the codepage and the worker's default
decoding does not preserve CP437. Its three container cases have **strict
xfail** markers: the exact original path/content assertions remain enabled,
and a future fix will produce XPASS failures until the marker is removed.
Only the reproduced filename substitution with otherwise exact member hashes
raises the expected exception; fixture failures or additional output defects
remain ordinary failures.
The marker is active only in the reproduced Windows CP936 environment. Other
system codepages still run the same exact-path assertion as a normal test.
