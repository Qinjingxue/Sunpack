# ENC v4

The shared Rust crate owns the only ENC parser, KDF, cipher and authentication
implementation. The Python extension probes password candidates; the C++
`IInArchive` adapter decrypts through existing streams and extraction callbacks.
Discovery confirms the 40-byte header without a KDF. Existing password scheduling
and generation-aware prepared contexts retain only 72 bytes of immutable header
material, with no derived keys or workspaces. Candidates cross the Python boundary
once; Rust reuses UTF-16 buffers. The first matching candidate keeps its priority.
The 32-byte quick block selects a password; keyed BLAKE3 authenticates extraction.

KDF and CTR reuse one process-wide Rayon executor and existing CPU credits.
Password batches retain at most 64 MiB of aggregate Argon2 scratch, except when a
single encoded workspace is larger; the default KDF uses up to six 10 MiB
workspaces. Active batches and granted lane credits bound concurrent workspaces.
Scratch and active-batch reservations are released at batch exit. The worker
borrows up to three extra credits for the selected-password KDF, returning them
before recovery framing or extraction I/O. One-credit KDF runs lanes serially.

`Decoder::decrypt_with_budget` is the sole authenticated decrypt entry point.
It streams through a 256 KiB buffer, sharing expanded keys and zeroizing key,
plaintext and counter scratch on drop. CTR acquires available extra credits each
batch, with at least 4 KiB per slice, then releases them before writes and on every
error/cancellation path. BLAKE3 stays on the base credit. COM I/O and callbacks stay
on the job thread; no per-job executor, double buffer or parallel MAC is retained.
C4 uses each cipher stage's own counter width and byte offset.

Custom ISA policy lives in `src/backend.rs`; optional features are detected once
and bound at key expansion. ARM64 RC6 uses baseline NEON directly, with no runtime
NEON detection or backend pointer. ARM64 Serpent and Threefish reuse scalar for
all sizes, without custom NEON code or backend pointers.

| Cipher | Windows x64 | Windows ARM64 |
| --- | --- | --- |
| RC6 | AVX2 bulk, scalar short/tail | NEON bulk, scalar short/tail |
| Serpent | AVX2 bulk, scalar short/tail | Scalar |
| Threefish | AVX2 bulk, scalar short/tail | Scalar |
| SHACAL | SHA-NI when available, portable otherwise | SHA2 when available, portable otherwise |
| Twofish | Eight-block interleave and fixed tails | Same |
| AES | Upstream runtime backend | Upstream runtime backend |

RC6/Serpent SIMD groups are eight blocks on x64; Threefish groups are four.
ARM64 RC6 groups are four blocks. Short proofs never pad to full SIMD groups.
SHA hardware supports incomplete groups; SHA2 remains optional independently of
NEON. Argon2 and portable SHA compression retain their upstream runtime backends.
Correctness tests cover official vectors, direct ISA paths, short/tail groups,
CTR offsets, CPU credits, corruption and cancellation:
`cargo test --manifest-path native/Cargo.toml --locked -p sunpack-enc --release --lib`.

ENC produces one unnamed authenticated item. Existing recursive discovery,
verification, cleanup and CLI/Watch scheduling own the resulting payload; the
reader does not interpret ZIP contents. Recovery framing is stripped and remains
authenticated; repair and output SHA-256 passes are not performed. ENC is a
complete logical stream with no declared ciphertext length, so arbitrary
prefix/suffix boundaries are not inferred. Existing bounded ranges and raw
concatenated streams reuse the same parser/probe. Older ENC versions are unsupported.
Java is used only to generate independent test fixtures.

References: [ENC specification](https://paranoiaworks.mobi/sse/file_encryption_specifications.html),
[recovery specification](https://paranoiaworks.mobi/sse/fe_recovery_specifications.html).
