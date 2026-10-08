# ENC v4

The shared Rust crate owns the only ENC parser, KDF, cipher and authentication
implementation. The native Python extension probes passwords; the C++
`IInArchive` adapter executes authenticated decryption through existing streams
and extraction callbacks. Java is used only to create independent test vectors.

Discovery confirms the 40-byte header without a KDF. The ordinary file task
then uses the existing password scheduler and generation-aware prepared-context
cache. Its immutable password material is only 72 bytes. Candidates are converted
once at the Python boundary; Rust converts and reuses each chunk's UTF-16 buffer.
The first matching candidate retains its original priority, and only that password
reaches extraction. The 32-byte alphanumeric quick block selects a password;
the full keyed BLAKE3 MAC still determines extraction success.

Batch calculations reuse the existing Rayon pool. Each chunk reuses one Argon2
workspace, with 64 MiB of aggregate scratch space per batch (six 10 MiB workspaces
for the default KDF). Higher encoded memory costs use fewer workspaces, with at
least one workspace of the encoded size. Scratch space is dropped at batch exit;
neither derived keys nor Argon2 buffers live in the prepared-context cache.
Rayon and the parallel-capable KDF/CTR implementations are unconditional crate
dependencies; the Python extension and worker use the same implementation, with
no compile-time serial/parallel feature split. Argon2 SIMD fills its four lanes
on the existing shared executor, bounded by each workspace's granted CPU budget.
The worker borrows at most three extra credits for the selected-password KDF and
returns them before reading recovery framing. A one-credit KDF fills lanes
serially with the same SIMD primitives, without dispatching to Rayon.
Candidate workspace counts account for both the four lanes and the number of
active ENC batches, to limit scratch retained by nested joins under concurrent
probes. The active-batch counter is released on every return/error; it retains
no passwords, keys or workspaces.

`Decoder::decrypt_with_budget` is the sole authenticated decrypt entry point.
The caller owns one base credit and supplies acquire/release callbacks; granting
zero extras is the normal serial case. A standalone fixed budget grants
`wanted.min(credits.saturating_sub(1))` and uses a no-op release. Extraction
retains only small keys and a 256 KiB streaming buffer. It returns
one unnamed item, so the existing callback chooses the input filename stem.
It knows nothing about ZIP contents or output extensions. Ordinary recursive
discovery, output verification, cleanup, cancellation and CLI/Watch scheduling
remain responsible for those behaviours. Recovery container framing is stripped;
its bytes participate in ENC authentication. Recovery repair and output SHA-256
passes are not performed.

For each 256 KiB batch the worker acquires the currently available CPU credits
from the existing broker and divides CTR into that many slices, plus its base
credit. The count can increase or decrease every batch, including non-power-of-two
counts. Its only limits are the shared Rayon executor's capacity and at least
4 KiB of useful work per slice, rather than an algorithm switch or fixed thread
count. Extra credits are returned immediately after computation, before writes,
also on cancellation and errors. BLAKE3 remains on the base credit; its measured
cost does not justify a second parallel scheduling mechanism. COM reads, writes
and callbacks remain on the job thread. C4 uses each stage's own counter width
and byte offset. Expanded keys are shared; counter/pad scratch is zeroized on
drop. The process shares one Rayon executor across jobs, so jobs never create or
retain separate pools.

Custom cipher ISA policy lives in `src/backend.rs`. One process-wide, immutable
capability record detects x64 AVX2 and SHA-NI (including SSSE3/SSE4.1), or ARM64
SHA2. RC6, Serpent and Threefish bind their x64 vector backend at key expansion;
SHACAL binds its SHA backend. The decrypt hot loop does not check ISA
availability. The record contains only CPU flags, with no keys or scratch space.
AES, Argon2 and the portable SHACAL compression helper retain their upstream
runtime-selected backends.

x64 RC6/Serpent/Threefish keep scalar processing for short proofs and incomplete
SIMD groups. Windows ARM64 RC6 directly uses baseline NEON for four-block bulk,
with scalar short/tail processing; it retains no backend pointer or NEON flag.
ARM64 Serpent and Threefish use the existing scalar implementation for all sizes.
On the native ARM runner, custom Serpent NEON did not improve on scalar, while
two-block Threefish NEON took 550ns versus scalar's 291ns; those backends were
removed. No cipher pads a 32B proof to a SIMD group. SHACAL uses its x64
two-block SHA-NI kernel or ARM four-block SHA2 kernel, including hardware tails.
Twofish keeps its eight-block interleave and const-generic tails. Unsupported ISA
falls back to the existing scalar/portable implementation selected at construction;
AVX2 does not imply SHA-NI, and NEON does not imply SHA2. Release CPU requirements
are unchanged.
Direct ISA tests compare NEON against scalar/upstream and SHA2 against portable
compression; SHA2-unavailable dispatch is tested with instruction-free callbacks.
ARM64 path selection was measured with short-block crossover and 32B proof/
1- and 4-credit CTR on a native Windows ARM64 runner. The temporary workflow and
crossover harness are removed after verification; correctness tests remain.

Bounded parallel MAC and writer probes remain benchmark-only. Production has
no MAC experiment mode, double buffer, special AES thread policy or ENC-to-ZIP
streaming route. CPU credits continue to vary by batch; input/output callbacks
stay on the caller, and plaintext/key buffers are cleared when dropped.

This initial implementation treats ENC as a complete logical stream. The format
does not declare the ciphertext length, so it does not infer ENC boundaries inside
arbitrary prefix/suffix junk. Existing bounded ranges and raw concatenated input
streams can feed the same parser and password probe without another analyser.
Older ENC versions are outside this implementation.

References: [ENC specification](https://paranoiaworks.mobi/sse/file_encryption_specifications.html),
[recovery specification](https://paranoiaworks.mobi/sse/fe_recovery_specifications.html).
