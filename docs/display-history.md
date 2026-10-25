# Display history

`watch.event_log_retention_days` defaults to 7. The writer expires records using
persisted UTC timestamps and rolling 24-hour days. Configuration uses the usual
reload path. No GUI timer, runtime connection, database, WAL, fsync, or replay is
required. Task recovery continues to use the existing business-state store.

`events.json` is an atomically published manifest; `events.json.store/` contains
compressed MessagePack records and fixed-width little-endian indexes. Runs have
nondecreasing timestamps. A different UTC day or backwards timestamp starts a
new run, so clock changes never invalidate binary search. Each 64-byte index row:

| Offset | Value |
|---|---|
| 0 | UTC microseconds, i64 |
| 8 | Data offset, u64 |
| 16 | LZ4 block bytes, u32 |
| 20 | Decoded bytes, u32 |
| 24 | Kind: diagnostic=0, processing=1, password=2, volumes=3, success=4, failure=5 |
| 28 | Live slot ordinal (unused for history), u32 |
| 32 | 256-bit single/bigram search filter |

The filter only rejects impossible matches. Consumers verify complete paths,
logical names and member paths after decompression. It handles one-character
and two-character searches, including Chinese; collisions cannot hide matches.
Unselective queries may still scan the disk index and decode candidates. They
are cancellable and never materialize all matching IDs or sort the full history.

The manifest commits the readable count and first surviving index ordinal.
Unpublished files and tails are disposable. Expiry uses binary search and
Windows sparse zero ranges to erase expired data and release whole allocation
units; entirely expired runs are deleted. Surviving record offsets stay stable.
There is one absolute UTC waitable timer per writer, armed only for the earliest
pending expiry. System time is checked on work/wakeup, never by idle polling.

History does not remain in the producer's task map. Only live task relations,
a 4 MiB asynchronous queue, bounded dirty-ID tracking, scratch buffers and run
metadata stay resident. Completed families keep only ownership-routing metadata
until their in-flight request owners release; history payloads are not retained.
Expired waiting records without an in-flight owner also leave the display map;
the authoritative business store remains responsible for retry/recovery.
The live store updates fixed disk slots per changed task, zeros replaced records
and recycles slots. Sparse data/slot holes trigger amortized compaction; unchanged
live payloads are copied compressed. Live queries scan compact slot metadata and
retain at most one page of candidates, independently of the history size.
Display logging is best effort: queue overload drops records and publishes its
cumulative dropped count rather than blocking extraction. One large record may
occupy an otherwise empty queue. This is a transient-memory bound, not a history
size limit. The existing per-event diagnostic payload bound remains in force.

Consumers open files read-only, share deletion, use timestamp/run/ordinal cursors
and release all handles at the end of each query. The GUI loads at most 100 rows
and approximately 8 MiB of decoded records per page (one larger record may stand
alone). Its back-navigation stack is bounded. It keeps working while the writer
is absent and does not expire or modify files itself. A consumer racing an atomic
publication retries through its existing event-driven I/O-error path.
