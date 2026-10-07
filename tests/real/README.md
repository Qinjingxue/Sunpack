# Real archive regression coverage

Use `.venv/Scripts/python.exe -m pytest tests/real`. Watch tests additionally
require the isolated Broker environment established by `run_acceptance_tests.ps1`.

The new regression cases cover:

* LZ4 and TAR/LZ4 participate in Plan 1's ordinary/disguised/mixed directory
  matrices and concatenated streams. The nested CLI and Plan 7 restart/password
  fixtures contain a valid TAR/LZ4 carrier segment alongside encrypted 7z;
  expected sizes/CRC32 verify that this healthy segment survives sibling
  failures and is extracted exactly once. Plan 7 also covers LZ4 ordinary,
  disguised, embedded, chunked downloads and writes to the final path.
  `plan7_watch_downloads/test_plan7_lz4_wrapped_rar_volumes.py` delivers four
  independently LZ4-wrapped, header-encrypted RAR volumes with the password
  supplied before arrival. Both interleaved rename-commit and final-path writes
  start the real directory monitor, promote the volume group to the input root,
  and automatically extract each member
  exactly once; Rust inventories verify volume/member sizes and CRC32.

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
  update. Blocked inner inputs are promoted to the original input directory;
  the test asserts their ordinary password scope before triggering the update.
* `test_external_structure_corpus.py` generates self-authored samples using
  Windows bsdtar/libarchive and WinRAR, independently of SunPack/7-Zip's usual
  fixture writer. It checks USTAR, PAX long Unicode paths, GNU longname,
  duplicate TAR/ZIP members, empty ZIP, legacy CP437 ZIP and solid RAR5 under
  plain names, disguised names and junk-prefixed/suffixed carriers. Expected
  output paths, sizes and CRC32 come from source files, not extraction output.
* Plan 2, Plan 3 and Plan 7 exercise the official ENC v4 compatibility vector
  through foreground decryption, wrong-password reporting and watch downloads.
  Plan 2 gives the ENC vector a `.mov` name to verify signature-based discovery;
  the fixture is copied by the Rust test helper from
  `native/sunpack_enc/tests/data/algorithm_0.mov`.

Samples are generated once per structure per test module and reused for all
three container variants. The ignored `tests/real/corpus/` directory is optional;
a clean checkout can collect and run these tests without it. To generate an
inspectable corpus with tool/command/artifact provenance:

```powershell
.venv/Scripts/python.exe -m scripts.generate_real_structure_corpus
```

Binary assembly and hashing use the test-only Cargo example `real_fixture`,
with bounded buffers (64 KiB for assembly/hashing, 256 KiB input for LZ4).
LZ4 frames use the pinned upstream encoder with block/content checksums,
declared content size and linked 64 KiB blocks; multiple sources produce
concatenated frames without querying the product parser. It is built with the workspace's existing locked
dependencies and does not add production APIs or dependencies. Python reads
only text manifests and orchestrates existing fixture/tool paths.

The legacy CP437 case asserts exact names and contents in all three containers.
Rust passes CP437 explicitly when it wins the filename analysis, so the native
handler cannot substitute its Unix UTF-8 heuristic or the machine's codepage.
UTF-8 flags and valid Unicode path fields retain precedence in the handler.
