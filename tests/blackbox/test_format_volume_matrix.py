"""Real typed-input/worker boundaries missing from the ZIP/7z smoke cases.

These use the existing acceptance generators (including their external-tool
checks), not hand-built descriptor mocks. Missing generators are setup failures,
not a reason to silently skip format coverage in a configured Windows run.
"""
import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from tests.helpers.real_archives import (
    ArchiveFixtureFactory,
    create_encrypted_rar_archive,
    create_rar4_archive,
    create_zip_multidisk_archive,
)


PASSWORD = "format-volume-key"
SIBLING = b"independent embedded archive"


def _carrier(root, kind, password=None):
    options = dict(payload_size=160 * 1024, split_volume_size=48 * 1024)
    if kind.startswith("zip"):
        if kind == "zip-two-disks":
            options["split_volume_size"] = None
        case = create_zip_multidisk_archive(root, "carrier", password=password, **options)
    elif password:
        case = create_encrypted_rar_archive(
            root, "carrier", password=password, rar4=kind == "rar4",
            header_encrypt=True, split=True, **options,
        )
    elif kind == "rar4":
        case = create_rar4_archive(root, "carrier", split=True, compression_level=0, **options)
    else:
        case = ArchiveFixtureFactory().create(
            root, "carrier", "rar", split=True, compression_level=0, **options,
        )
    originals = sorted(case.archive_dir.iterdir(), key=lambda path: (path != case.entry_path, path.name))
    assert len(originals) >= 2
    parts = []
    for index, source in enumerate(originals, 1):
        target = source.with_name("shared.jpg" if index == 1 else f"shared.chunk{index}.opaque")
        source.rename(target)
        parts.append(target)
    sibling = io.BytesIO()
    with zipfile.ZipFile(sibling, "w") as archive:
        archive.writestr("sibling.txt", SIBLING)
    # Both the head offset and the boundary before an independent sibling must
    # survive discovery -> password planning -> native-volume callbacks.
    parts[0].write_bytes(b"unrecognized-carrier-prefix\0" * 211 + parts[0].read_bytes()
                        + b"gap" * 37 + sibling.getvalue() + b"suffix" * 11)
    return case, parts


def _one_marker(output, case):
    paths = list(output.rglob(case.marker_name))
    assert len(paths) == 1, paths
    assert paths[0].read_text(encoding="utf-8") == case.marker_text
    siblings = list(output.rglob("sibling.txt"))
    assert len(siblings) == 1, siblings
    assert siblings[0].read_bytes() == SIBLING
    return siblings[0]


@pytest.mark.parametrize("kind", ["rar4", "rar5", "zip-spanned", "zip-two-disks"])
@pytest.mark.parametrize("password", [None, PASSWORD], ids=["plain", "encrypted"])
def test_carrier_native_volume_and_password_matrix(package, tmp_path, kind, password):
    # Generic split ZIP and 7z tests do not exercise RAR encrypted headers or
    # ZIP disk-relative offsets crossing callback reads in the real worker.
    case, parts = _carrier(tmp_path, kind, password)
    output = tmp_path / "out"
    args = [] if password is None else ["-p", "wrong-key", "-p", password]
    result = package.json("extract", "-d", "-r", "1", "-c", "k", "-o", output,
                          "--no-builtin-pw", *args, parts[0])
    assert result["summary"]["failed_count"] == 0, result
    _one_marker(output, case)
    assert all(path.is_file() for path in parts)


@pytest.mark.parametrize("flags", [0, 1, 2, 3], ids=["normal", "extra-zero", "data-zero", "both-zero"])
def test_rar5_optional_common_fields_use_directory_password_plan(package, tmp_path, flags):
    # Change only the public header layout of a real nonempty archive. This
    # reaches directory Relations, then verifies the real worker output.
    import zlib

    case = create_encrypted_rar_archive(
        tmp_path, "common-header", password=PASSWORD, header_encrypt=True,
        split=False, payload_size=4096,
    )
    data = case.entry_path.read_bytes()
    assert data[:8] == b"Rar!\x1a\x07\x01\x00"
    assert data[12] < 128 and data[13:15] == b"\x04\x00"
    end = 13 + data[12]
    body = bytes([4, flags]) + b"\0" * flags.bit_count() + data[15:end]
    block = bytes([len(body)]) + body
    changed = data[:8] + zlib.crc32(block).to_bytes(4, "little") + block + data[end:]
    disguised = case.entry_path.with_suffix(".opaque")
    case.entry_path.unlink()
    disguised.write_bytes(changed)
    wrong = package.json("scan", "--no-builtin-pw", "-p", "wrong", case.archive_dir, code=1)
    assert wrong["items"][0]["error_kind"] == "wrong_password", wrong
    report = package.json("scan", "--no-builtin-pw", "-p", PASSWORD, case.archive_dir)
    assert len(report["items"]) == 1 and not report["items"][0].get("error_kind"), report
    output = tmp_path / "out"
    result = package.json("extract", "--no-builtin-pw", "-p", PASSWORD,
                          "-c", "k", "-o", output, case.archive_dir)
    assert result["summary"]["failed_count"] == 0, result
    marker, = output.rglob(case.marker_name)
    assert marker.read_text(encoding="utf-8") == case.marker_text


@pytest.mark.parametrize("carrier", [False, True], ids=["plain-file", "embedded"])
def test_renamed_rar5_volumes_resolve_encrypted_headers_before_numbering(package, tmp_path, carrier):
    case = create_encrypted_rar_archive(
        tmp_path, "numbered", password=PASSWORD, header_encrypt=True, split=True,
        payload_size=160 * 1024, split_volume_size=48 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) > 2 and parts[0] == case.entry_path

    # The public encryption header groups candidates, but only decryption
    # reveals the first volume. The misleading .001 file is really volume 2.
    disguised = []
    for index, part in enumerate(parts):
        target = part.with_name("renamed.xyz" if index == 0 else f"renamed.{index:03d}.jpg")
        part.rename(target)
        disguised.append(target)
    if carrier:
        sibling = io.BytesIO()
        with zipfile.ZipFile(sibling, "w") as archive:
            archive.writestr("sibling.txt", SIBLING)
        disguised[0].write_bytes(b"prefix" * 211 + disguised[0].read_bytes()
                                 + b"gap" * 37 + sibling.getvalue() + b"suffix" * 11)
    report = package.json("scan", "-d", "--no-builtin-pw", case.archive_dir, code=1)
    blocked, = [item for item in report["items"] if item.get("error_kind") == "password_required"]
    assert len(report["items"]) == 1 + carrier, report
    assert {Path(path) for path in blocked["all_parts"]} == set(disguised)

    # Password-blocked candidates must survive destructive cleanup requests.
    package.json("extract", "-d", "-r", "1", "-c", "d", "-o", tmp_path / "blocked",
                 "--no-builtin-pw", case.archive_dir, code=1)
    assert all(path.is_file() for path in disguised)

    # Retry uses the same relation solver with real roles, including changing
    # the representative from the alphabetically first continuation to the head.
    report = package.json("scan", "-d", "--no-builtin-pw", "-p", PASSWORD, case.archive_dir)
    item, = [item for item in report["items"] if item.get("all_parts")]
    assert {Path(path) for path in item["all_parts"]} == set(disguised)
    assert Path(item["main_path"]) == disguised[0]

    renamed = []
    for index, part in enumerate(disguised, 1):
        target = part.with_name(f"renamed.opaque.{index:03d}")
        part.rename(target)
        renamed.append(target)

    output = tmp_path / "out"
    report = package.json("extract", "-d", "-r", "1", "-c", "k", "-o", output,
                          "--no-builtin-pw", "-p", PASSWORD, renamed[0])

    assert report["summary"]["success_count"] == 1
    if carrier:
        _one_marker(output, case)
    else:
        assert (output / "renamed" / case.marker_name).read_text(encoding="utf-8") == case.marker_text


def test_encrypted_rar5_same_stem_keeps_independent_sets_and_singleton(package, tmp_path):
    # Same password and stem cannot distinguish independent sets. The single
    # set test cannot catch cross-set merging during cached password retry.
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    cases, groups = [], []
    for number in range(3):
        case = create_encrypted_rar_archive(
            tmp_path / f"fixture{number}", f"set{number}", password=PASSWORD,
            header_encrypt=True, split=number < 2, payload_size=100 * 1024,
            split_volume_size=48 * 1024,
        )
        cases.append(case)
        paths = []
        for index, part in enumerate(sorted(case.archive_dir.iterdir())):
            target = inputs / f"same.{index * 3 + number:03d}.jpg"
            shutil.copyfile(part, target)
            paths.append(target)
        groups.append(set(paths))
    report = package.json("scan", "-d", "--no-builtin-pw", inputs, code=1)
    assert len(report["items"]) == 3, [(Path(i["main_path"]).name, [Path(p).name for p in i.get("all_parts", [])]) for i in report["items"]]
    actual = [{Path(path) for path in item.get("all_parts", [item["main_path"]])}
              for item in report["items"]]
    assert all(group in actual for group in groups), report
    assert all(item["error_kind"] == "password_required" for item in report["items"])
    report = package.json("scan", "-d", "--no-builtin-pw", "-p", PASSWORD, inputs)
    assert len(report["items"]) == 3, [(Path(i["main_path"]).name, [Path(p).name for p in i.get("all_parts", [])]) for i in report["items"]]
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w") as archive:
        for part in inputs.iterdir():
            archive.write(part, part.name)
    output = tmp_path / "out"
    report = package.json("extract", "-d", "-r", "*", "-c", "k", "-o", output,
                          "--no-builtin-pw", "-p", PASSWORD, outer)
    assert report["summary"]["failed_count"] == 0, report
    for case in cases:
        markers = list(output.rglob(case.marker_name))
        assert len(markers) == 1, markers
        assert markers[0].read_text(encoding="utf-8") == case.marker_text


@pytest.mark.requires_watch_broker
def test_watch_encrypted_rar5_group_recovers_password_and_missing_volume(package, tmp_path):
    _watch_encrypted_rar5_recovery(package, tmp_path)


def _watch_encrypted_rar5_recovery(package, tmp_path, project=None):
    # One lifecycle covers a password-blocked candidate, decrypted missing slot,
    # persisted sibling ownership, and eventual cleanup after volume arrival.
    from tests.helpers.native_fixture import native_fixture

    case, parts = _carrier(tmp_path, "rar5", PASSWORD)
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    package.configure(post_extract={"archive_cleanup_mode": "d", "flatten_single_directory": False})
    package.json("watch", "add", "-d", "-o", output, case.archive_dir)
    package.json("watch", "start", "--once", "--no-tray")
    events = native_fixture("display_events", path=str(package.data / ".sunpack_watch" / "events.json"))
    blocked = [row for row in (*events["history"], *events["live"])
               if row.get("event") == "failed_password"]
    assert len(blocked) == 1, blocked
    if project:
        project("password", [path for path in parts if path != parts[1]], None)
    sibling, = output.rglob("sibling.txt")
    before = (sibling, sibling.stat().st_ino, sibling.stat().st_mtime_ns)
    assert all(path.is_file() for path in parts if path != parts[1])
    assert package.run("--persistent-shutdown").returncode == 0
    package.configure(user_passwords=[PASSWORD])
    result = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert result.returncode in (0, 1), (result.stdout, result.stderr)
    assert all(path.is_file() for path in parts if path != parts[1])
    assert not list(output.rglob(case.marker_name))
    events = native_fixture("display_events", path=str(package.data / ".sunpack_watch" / "events.json"))
    assert any(row.get("event") == "suspended_missing_volume" for row in events["live"]), json.dumps(events, ensure_ascii=False)
    assert len(list(output.rglob("sibling.txt"))) == 1, "password retry repeated an intact sibling"
    if project:
        project("volumes", [path for path in parts if path != parts[1]], parts[0])
    parts[1].write_bytes(missing)
    package.json("watch", "start", "--once", "--no-tray")
    sibling = _one_marker(output, case)
    assert (sibling, sibling.stat().st_ino, sibling.stat().st_mtime_ns) == before
    assert all(not path.exists() for path in parts)
    if project:
        project("done", parts, parts[0])


@pytest.mark.requires_watch_broker
@pytest.mark.parametrize("kind", ["rar4", "rar5", "zip-spanned"])
def test_watch_format_volume_arrival_survives_runtime_restart(package, tmp_path, kind):
    # One restart case per format covers persisted missing-volume ownership,
    # preserved independent output, and the subsequent worker callback geometry.
    case, parts = _carrier(tmp_path, kind)
    missing = parts[1].read_bytes()
    parts[1].unlink()
    output = tmp_path / "out"
    package.configure(post_extract={"archive_cleanup_mode": "d", "flatten_single_directory": False})
    package.json("watch", "add", "-d", "-o", output, case.archive_dir)
    blocked = package.run("watch", "start", "--once", "--no-tray", "--json")
    assert blocked.returncode in (0, 1), (blocked.stdout, blocked.stderr)
    siblings = list(output.rglob("sibling.txt"))
    assert len(siblings) == 1, siblings
    sibling = siblings[0]
    before = (sibling, sibling.stat().st_ino, sibling.stat().st_mtime_ns)
    assert sibling.read_bytes() == SIBLING
    assert all(path.is_file() for path in parts if path != parts[1])
    shutdown = package.run("--persistent-shutdown")
    assert shutdown.returncode == 0, (shutdown.stdout, shutdown.stderr)
    parts[1].write_bytes(missing)
    package.json("watch", "start", "--once", "--no-tray")
    sibling = _one_marker(output, case)
    assert (sibling, sibling.stat().st_ino, sibling.stat().st_mtime_ns) == before
    assert all(not path.exists() for path in parts)


@pytest.mark.parametrize("cleanup", ["k", "d", "r"])
def test_independent_heads_keep_shared_tail_until_both_consumers_finish(package, tmp_path, cleanup):
    # Relations keeps these two head identities separate. A single-head or
    # embedded-merged fixture cannot detect the second consumer losing its tail.
    case = ArchiveFixtureFactory().create(
        tmp_path, "shared", "7z", split=True, compression_level=0,
        payload_size=100 * 1024, split_volume_size=48 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert parts[0] == case.entry_path and len(parts) >= 3
    root = tmp_path / "inputs"
    for name in ("A", "B", "C"):
        (root / name).mkdir(parents=True)
    for directory in ("A", "B"):
        shutil.copyfile(parts[0], root / directory / parts[0].name)
    for part in parts[1:]:
        shutil.copyfile(part, root / "C" / part.name)
    sources = [path for path in root.rglob("*") if path.is_file()]
    package.configure(embedded_scan={"enabled": False})
    output = tmp_path / "out"
    result = package.json("extract", "-R", "-r", "1", "-c", cleanup, "-o", output, root)
    assert result["summary"]["failed_count"] == 0, result
    markers = list(output.rglob(case.marker_name))
    assert len(markers) == 2, markers
    assert all(path.read_text(encoding="utf-8") == case.marker_text for path in markers)
    assert all(path.exists() == (cleanup == "k") for path in sources)
