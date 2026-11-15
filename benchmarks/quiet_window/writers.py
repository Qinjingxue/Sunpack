"""Writer-side programs; no archive parsing, payload IO or completion oracle.

Byte-range validity is symbolic. Timings are declared synthetic stress ranges,
not measurements of the applications cited in WRITERS.md.
"""
from __future__ import annotations

import heapq
import math
from dataclasses import replace

from .corpus import FileTruth, MULTIPART, Mutation, WriterAction


def _remove(ranges, start, end):
    return [(a, b) for left, right in ranges
            for a, b in ((left, min(right, start)), (max(left, end), right)) if a < b]


def _add(ranges, start, end):
    result = []
    for left, right in sorted([*ranges, (start, end)]):
        if result and left <= result[-1][1]:
            result[-1] = (result[-1][0], max(right, result[-1][1]))
        else:
            result.append((left, right))
    return result


def _realize(index, family, expected, actions, *, preserve_mtime=False):
    actions = tuple(sorted(actions, key=lambda item: item.at))
    size, content_usn = 0, 0
    mtime = 100.0
    covered, mutations, handles, blocked = [], [], {}, []
    journal_reasons = 0
    directory_pending = False
    complete, visible = None, actions[0].at
    for action in actions:
        at, kind, offset, length = action.at, action.kind, action.offset, action.length
        reason, directory_event = 0, True
        if kind == "open":
            if not action.access or action.writer in handles:
                raise ValueError("invalid or repeated handle open")
            handles[action.writer] = (at, action.access, action.share)
        if kind == "rename":
            visible = at
        elif kind == "seed":
            covered = _add(covered, offset, offset + length)
        if kind == "close":
            if action.writer not in handles:
                raise ValueError("writer closed an unopened handle")
            start, access, share = handles.pop(action.writer)
            # The production reader asks for READ and shares READ only. Share
            # compatibility is bidirectional, even for a writer sharing READ.
            if ((access & ~1) or not (share & 1)) and start < at:
                blocked.append((start, at))
            directory_event = bool(access & 2 and directory_pending)
            if access & 2:
                directory_pending = False
            if not handles and journal_reasons:
                reason = journal_reasons | 0x80000000
                journal_reasons = 0
        if kind == "flush":
            directory_event = directory_pending
            directory_pending = False
        if kind not in {"allocate", "existing", "truncate", "replace", "write", "bad_write", "restore_mtime", "close", "flush"}:
            continue
        usn = len(mutations) + 1
        if kind in {"allocate", "existing", "truncate", "replace"}:
            if kind == "replace":
                covered = []
            covered = _remove(covered, length, max(size, expected))
            size = length
            reason = 0x4 if kind in {"truncate", "replace"} else 0x2
        elif kind in {"write", "bad_write"}:
            if length <= 0 or offset < 0 or offset + length > expected:
                raise ValueError("writer range exceeds its target")
            size = max(size, offset + length)
            covered = (_add if kind == "write" else _remove)(covered, offset, offset + length)
            reason = 0x2 if offset + length > (mutations[-1].size if mutations else 0) else 0x1
        if kind not in {"restore_mtime", "close", "flush"}:
            content_usn = usn
            directory_pending = True
            journal_reasons |= reason
            if not preserve_mtime:
                mtime = 100.0 + at
        elif kind == "restore_mtime":
            mtime = 10.0
            reason = 0x8000
            journal_reasons |= reason
        mutations.append(Mutation(at, size, mtime, usn, kind, offset, length, action.writer, content_usn,
                                  reason, directory_event))
        full = size == expected and covered == [(0, expected)]
        if not full:
            complete = None
        elif complete is None:
            complete = at
    if handles:
        raise ValueError("writer lifecycle leaves open handles")
    # Adjacent/overlapping locks from different writers block a reader until
    # ALL incompatible handles close, rather than until the first close.
    merged = []
    for start, end in sorted(blocked):
        merged = _add(merged, start, end)
    shape = "split_complete" if family in MULTIPART else "opaque"
    group = f"archive-{index // 4}" if family in MULTIPART else f"file-{index}"
    return FileTruth(f"file-{index}.opaque", group, shape, expected, actions,
                     tuple(mutations), complete, visible, tuple(merged))


def build_file(family, index, rng, group_rng):
    count = 48
    chunk = 1 << rng.randrange(14, 19)
    expected = count * chunk
    step = 10 ** rng.uniform(-3, -0.1)
    pause = rng.choice((0.5, 3.0, 30.0, 300.0, 3600.0)) * rng.uniform(0.7, 1.3)
    workers = rng.choice((2, 4, 8))
    start = index * 0.0001
    actions = []

    def emit(at, kind, offset=0, length=0, writer=0, phase="", *, access=0, share=7):
        actions.append(WriterAction(at, kind, offset, length, writer, phase, access, share))

    def write(at, block, writer=0, *, kind="write", phase="transfer", length=None):
        emit(at, kind, block * chunk, chunk if length is None else length, writer, phase)

    def sequential(blocks, at, *, writer=0, cadence=1.0, phase="transfer"):
        for block in blocks:
            at += step * cadence * rng.uniform(0.7, 1.3)
            write(at, block, writer, phase=phase)
        return at

    def parallel(blocks, at, *, shuffled=False, straggler=False, steal=False):
        blocks = list(blocks)
        if shuffled:
            rng.shuffle(blocks)
        clocks = [(at, worker) for worker in range(workers)]
        rates = [rng.uniform(0.5, 2) for _ in clocks]
        if straggler:
            rates[-1] *= rng.uniform(15, 60)
        if steal:
            # Faster workers take the next unassigned block when free.
            for block in blocks:
                moment, worker = heapq.heappop(clocks)
                moment += step * rates[worker]
                write(moment, block, worker, phase="work_stealing")
                heapq.heappush(clocks, (moment, worker))
        else:
            # Each stream advances inside its own contiguous byte range.
            for worker in range(workers):
                moment = at
                assigned = blocks[worker * len(blocks) // workers:(worker + 1) * len(blocks) // workers]
                for block in assigned:
                    moment += step * rates[worker] * rng.uniform(0.7, 1.3)
                    write(moment, block, worker)
                clocks[worker] = (moment, worker)
        return max(moment for moment, _ in clocks)

    if family not in {"close_reopen_batches", "exclusive_commit_tail"}:
        emit(start, "open", access=2)
    # Preallocation changes EOF but contributes no correct target bytes.
    if family not in {"segmented_sparse", "fragment_assembly", "copy_restartable", "copy_restart_from_zero",
                       "close_reopen_batches", "shared_handle_tail", "exclusive_commit_tail",
                       "archive_directory_last", "archive_header_backpatch", *MULTIPART}:
        emit(start, "existing" if family == "sync_inplace_delta" else "allocate", length=expected)
    else:
        emit(start, "truncate")
    at = start

    if family.startswith("segmented_"):
        if family in {"segmented_resume", "segmented_restart"}:
            blocks = list(range(count))
            rng.shuffle(blocks)
            at = parallel(blocks[:count // 2], at)
            emit(at, "checkpoint", phase="sidecar_only")
            emit(at, "close")
            emit(at, "pause")
            at += pause
            emit(at, "open", access=2)
            emit(at, "resume")
            if family == "segmented_restart":
                emit(at, "truncate", phase="range_request_rejected")
                at = sequential(range(count), at)
            else:
                at = parallel(blocks[count // 2:], at)
        else:
            at = parallel(range(count), at, straggler=family == "segmented_straggler",
                          steal=family == "segmented_work_stealing")
            if family == "segmented_retry_overlap":
                # One stream reconnects after a stall; other streams continue.
                stream_times = sorted(item.at for item in actions if item.kind == "write" and item.writer == workers - 1)
                reconnect = stream_times[len(stream_times) // 2]
                actions = [replace(item, at=item.at + pause if item.writer == workers - 1
                                        and item.kind == "write" and item.at >= reconnect else item.at)
                           for item in actions]
                # Resume validation/retries rewrite already correct overlapping
                # ranges; they do not advance completion or the coverage count.
                received = {item.offset // chunk: item.at for item in actions if item.kind == "write"}
                for block in rng.sample(range(count - 1), 6):
                    moment = max(received[block], received[block + 1]) + step / 10
                    write(moment, block, rng.randrange(workers), phase="overlap_retry", length=chunk + chunk // 2)
            if family == "segmented_finalize_rename":
                emit(at, "verify")
                at += pause
                emit(at, "close")
                emit(at, "rename", phase="publish_final_name")
    elif family in {"torrent_rarest_first", "torrent_recheck_repair"}:
        bad = set(rng.sample(range(count), 3)) if family == "torrent_recheck_repair" else set()
        # Twelve pieces, four blocks per piece. Prefer pieces with fewer
        # available peers; finish a selected piece before selecting another.
        availability = {piece: rng.sample(range(workers), rng.randint(1, workers)) for piece in range(count // 4)}
        pieces = sorted(availability, key=lambda piece: (len(availability[piece]), rng.random()))
        for piece in pieces:
            for block in range(piece * 4, piece * 4 + 4):
                at += step * rng.uniform(0.2, 3)
                peer = rng.choice(availability[piece])
                write(at, block, peer, kind="bad_write" if block in bad else "write", phase="peer_piece")
        if bad:
            emit(at, "verify", phase="failed_piece_check")
            at += pause
            for block in sorted(bad):
                at += step
                write(at, block, rng.randrange(workers), phase="repair")
    elif family in {"cached_piece_writeback", "mapped_page_batches"}:
        blocks = list(range(count))
        rng.shuffle(blocks)
        for begin in range(0, count, 8):
            at += step * rng.uniform(8, 32)
            emit(at, "receive", phase="user_cache" if family == "cached_piece_writeback" else "mapped_pages")
            for block in sorted(blocks[begin:begin + 8]):
                at += step / 100
                write(at, block, begin % workers, phase="cache_drain" if family == "cached_piece_writeback" else "mapped_store")
            emit(at + step / 100, "flush")
    elif family == "fragment_assembly":
        # Concurrent staging completion, then ordered target appends. A slow
        # early fragment holds later ready fragments back (head-of-line stall).
        arrivals = [step * (block + 1) / workers * rng.uniform(0.5, 2) for block in range(count)]
        arrivals[8] += pause
        for block, arrival in enumerate(arrivals):
            emit(start + arrival, "receive", block * chunk, chunk, block % workers, "staging_fragment")
            at = max(at, start + arrival) + step / 20
            write(at, block, phase="ordered_assembly")
            emit(at, "checkpoint", phase="sidecar_only")
    elif family in {"sync_reused_blocks", "sync_inplace_delta"}:
        missing = set(rng.sample(range(count), count // 4))
        for block in range(count):
            if block not in missing:
                if family == "sync_inplace_delta":
                    emit(start, "seed", block * chunk, chunk, phase="unchanged_existing_block")
                else:
                    at += step / 100
                    write(at, block, phase="local_block_copy")
        at += pause
        at = parallel(sorted(missing), at, shuffled=True)
        emit(at, "verify")
        if family == "sync_reused_blocks":
            at += step
            emit(at, "rename", phase="atomic_publish")
        emit(at + step, "restore_mtime")
    elif family in {"copy_restartable", "copy_restart_from_zero"}:
        at = sequential(range(count // 2), at)
        emit(at, "close")
        emit(at, "checkpoint")
        at += pause
        emit(at, "open", writer=1, access=2)
        if family == "copy_restart_from_zero":
            emit(at, "replace", writer=1, phase="new_file_identity")
            at = sequential(range(count), at, writer=1)
        else:
            # Retransmit the boundary block before continuing from checkpoint.
            at = sequential(range(count // 2 - 1, count), at, writer=1)
        emit(at + step, "restore_mtime")
    elif family == "close_reopen_batches":
        for begin in range(0, count, 8):
            emit(at, "open", access=2, share=0)
            at = sequential(range(begin, begin + 8), at)
            emit(at + step / 100, "close")
            if begin + 8 < count:
                at += step + pause / 5
                emit(at, "pause")
    elif family in {"shared_handle_tail", "exclusive_commit_tail"}:
        if family == "exclusive_commit_tail":
            emit(at, "open", access=2, share=0)
        at = sequential(range(count), at)
        emit(at, "flush")
        if family == "shared_handle_tail":
            # The writer releases while a distinct read-only handle remains.
            # READ sharing is not the same as a still-open writable handle.
            emit(at, "open", writer=1, access=1)
            emit(math.nextafter(at, math.inf), "close")
            emit(at + pause, "close", writer=1)
        else:
            emit(at + pause, "close")
    elif family == "archive_directory_last":
        at = sequential(range(count - 2), at, phase="compressed_payload")
        emit(at, "verify", phase="build_central_directory")
        at += pause
        at = sequential(range(count - 2, count), at, phase="central_directory_and_eocd")
    elif family == "archive_header_backpatch":
        write(at, 0, kind="bad_write", phase="placeholder_header", length=32)
        at += step
        emit(at, "write", 32, chunk - 32, phase="payload_after_header")
        at = sequential(range(1, count), at, phase="compressed_payload_and_next_header")
        emit(at, "verify", phase="finish_header")
        at += pause
        write(at, 0, phase="backpatch_start_header", length=32)
    elif family in MULTIPART:
        # Shared group time scale, real per-member order and a coherent group
        # completion barrier, rather than random split labels on lone files.
        volume_step = 10 ** group_rng.uniform(-3, -0.1)
        group_start = (index // 4) * volume_step
        at = group_start + (index % 4) * count * volume_step * 1.5 if family == "multipart_serial" else group_start
        # Move the initial create/open to this member's actual arrival.
        actions = [replace(action, at=at)
                   for action in actions]
        for block in range(count):
            if family == "multipart_late_volume" and index % 4 == 3 and block == count // 2:
                emit(at, "checkpoint")
                at += group_rng.uniform(30, 300)
            at += volume_step * rng.uniform(0.7, 1.3)
            write(at, block, index % 4, phase="volume_transfer")
    elif family == "cloud_hydration":
        # Placeholder EOF already exists. Range availability, not EOF, defines
        # local arrival. Automatic hydration caused by a reader is out of scope.
        at += pause
        at = parallel(range(count), at, shuffled=True, straggler=True)
    elif family in {"cancelled_holes", "paused_holes"}:
        missing = set(rng.sample(range(count), 3))
        at = parallel((block for block in range(count) if block not in missing), at, shuffled=True)
        emit(at, "checkpoint", phase="sidecar_only")
        emit(at + step, "cancel" if family == "cancelled_holes" else "pause")
    else:
        raise ValueError(f"unknown writer family: {family}")
    # Close every remaining coordinator handle after its last action, including
    # cancel/pause. Do not infer completion from this: holes/repairs stay truth.
    actions.sort(key=lambda action: action.at)
    opened = {}
    for action in actions:
        if action.kind == "open":
            if action.writer in opened:
                raise ValueError("unbalanced writer handle epoch")
            opened[action.writer] = action
        elif action.kind == "close":
            del opened[action.writer]
    last = math.nextafter(actions[-1].at, math.inf)
    for writer in opened:
        emit(last, "close", writer=writer)
    # Two notification lifecycles occur in ordinary downloads. A flush may
    # publish the last modification before the writer actually closes.
    if rng.getrandbits(1):
        actions = [item for action in sorted(actions, key=lambda item: item.at)
                   for item in ([action, WriterAction(action.at, "flush")]
                                if action.kind in {"write", "bad_write"} else [action])]
    return _realize(index, family, expected, actions, preserve_mtime=family == "mapped_page_batches")
