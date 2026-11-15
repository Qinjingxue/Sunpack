"""Verify solid RAR5 members that represent file identities without payloads."""

from tests.helpers.native_fixture import assert_exact_tree, file_inventory
from tests.helpers.real_archives import run_cmd
from tests.helpers.tool_config import get_optional_rar
from tests.real.archive_boundary import extract_report, require_generator


def _assert_links(root, groups):
    for first, *links in groups:
        assert all((root / first).samefile(root / link) for link in links), (root, first, links)
    assert not (root / groups[0][0]).samefile(root / "independent.bin")


def test_solid_rar5_preserves_payload_and_empty_hardlink_groups(package, tmp_path):
    require_generator("rar")
    rar = str(get_optional_rar())
    source = tmp_path / "source"
    source.mkdir()
    groups = [
        ("原件.bin", "links/副本.bin", "links/nested/third.bin"),
        ("empty.bin", "links/empty-link.bin"),
    ]
    payload = bytes(range(256)) * 128
    for group, data in zip(groups, (payload, b""), strict=True):
        first, *links = group
        original = source / first
        original.write_bytes(data)
        for path in links:
            link = source / path
            link.parent.mkdir(parents=True, exist_ok=True)
            link.hardlink_to(original)
    (source / "independent.bin").write_bytes(payload)
    expected = file_inventory(source)

    archive = tmp_path / "identities.rar"
    run_cmd([rar, "a", "-ma5", "-s", "-oh", "-r", "-idq", str(archive), "*"], source)
    # The external extractor must reproduce both link groups. CRC checks alone
    # would also accept a fixture in which the writer stored ordinary copies.
    control = tmp_path / "control"
    control.mkdir()
    run_cmd([rar, "x", "-idq", "-y", str(archive), str(control) + "\\"], tmp_path)
    assert_exact_tree(control, expected)
    _assert_links(control, groups)

    output = tmp_path / "out"
    report = extract_report(package, archive, output, recur="1", cleanup="d")
    assert report["summary"]["success_count"] == 1, report
    extracted = output / archive.stem
    assert_exact_tree(extracted, expected)
    _assert_links(extracted, groups)
    assert not archive.exists()


def test_rar5_partial_recovery_does_not_publish_links_to_crc_failed_member(package, tmp_path):
    require_generator("rar")
    rar = str(get_optional_rar())
    source = tmp_path / "source"
    source.mkdir()
    target = "a-target.bin"
    alias = "z-alias.bin"
    payload = bytes(range(255, -1, -1)) * 32
    healthy = b"verified unrelated member"
    (source / target).write_bytes(payload)
    (source / alias).hardlink_to(source / target)
    (source / "healthy.txt").write_bytes(healthy)

    archive = tmp_path / "damaged.rar"
    run_cmd([rar, "a", "-ma5", "-m0", "-s-", "-oh", "-idq", str(archive), target, "healthy.txt", alias], source)
    seven_zip = str(package.tools / "7z.exe")
    run_cmd([seven_zip, "t", str(archive)], tmp_path)
    listing = run_cmd([seven_zip, "l", "-slt", str(archive)], tmp_path).stdout
    alias_record = next((record for record in listing.split("\n\n") if f"Path = {alias}\n" in record), "")
    assert f"Hard Link = {target}" in alias_record, listing

    damaged = bytearray(archive.read_bytes())
    assert damaged.count(payload) == 1
    damaged[damaged.index(payload)] ^= 1
    archive.write_bytes(damaged)

    package.configure(extraction={"content_requirement": "allow_partial"})
    output = tmp_path / "out"
    report = extract_report(package, archive, output, recur="1", cleanup="d", code=(0, 4))
    assert report["summary"]["partial_success_count"] == 1, report
    recovered, = report["summary"]["recovered_outputs"]
    assert recovered["complete_files"] == 1, report
    extracted = output / archive.stem
    assert (extracted / "healthy.txt").read_bytes() == healthy
    assert not (extracted / alias).exists()
    assert archive.is_file()
