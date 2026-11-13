"""Real typed-input/worker boundaries missing from the ZIP/7z smoke cases.

These use the existing acceptance generators (including their external-tool
checks), not hand-built descriptor mocks. Missing generators are setup failures,
not a reason to silently skip format coverage in a configured Windows run.
"""
import io
import shutil
import zipfile

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


def test_renamed_rar5_volumes_resolve_encrypted_headers_before_numbering(package, tmp_path):
    case = create_encrypted_rar_archive(
        tmp_path, "numbered", password=PASSWORD, header_encrypt=True, split=True,
        payload_size=160 * 1024, split_volume_size=48 * 1024,
    )
    parts = sorted(case.archive_dir.iterdir())
    assert len(parts) > 2 and parts[0] == case.entry_path
    renamed = []
    for index, part in enumerate(parts, 1):
        target = part.with_name(f"renamed.opaque.{index:03d}")
        part.rename(target)
        renamed.append(target)

    output = tmp_path / "out"
    report = package.json("extract", "-r", "1", "-c", "k", "-o", output,
                          "--no-builtin-pw", "-p", PASSWORD, renamed[0])

    assert report["summary"]["success_count"] == 1
    assert (output / "renamed" / case.marker_name).read_text(encoding="utf-8") == case.marker_text


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
