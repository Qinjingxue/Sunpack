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
The Python extension enables `parallel-kdf`: Argon2 0.6 computes its four lanes
in that same Rayon pool, including batches with only one to four candidates.
The worker build enables only `parallel-decrypt`, so its selected-password KDF
stays serial. Build these packages separately to preserve Cargo feature isolation.
Candidate workspace counts account for both the four lanes and the number of
active ENC batches, to limit scratch retained by nested joins under concurrent
probes. The active-batch counter is released on every return/error; it retains
no passwords, keys or workspaces.

Extraction retains only small keys and a 256 KiB streaming buffer. It returns
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
retain separate pools. Serpent uses RustCrypto 0.6's bitsliced implementation.

This initial implementation treats ENC as a complete logical stream. The format
does not declare the ciphertext length, so it does not infer ENC boundaries inside
arbitrary prefix/suffix junk. Existing bounded ranges and raw concatenated input
streams can feed the same parser and password probe without another analyser.
Older ENC versions are outside this implementation.

References: [ENC specification](https://paranoiaworks.mobi/sse/file_encryption_specifications.html),
[recovery specification](https://paranoiaworks.mobi/sse/fe_recovery_specifications.html).
