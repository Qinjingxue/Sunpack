"""Create frozen RAR5 and ZipCrypto inputs plus a separate evaluator truth directory."""

from pathlib import Path
import itertools
import json
import random
import shutil
import subprocess
import sys
import zipfile

from benchmarks.harness.password_corpus import LEGACY_ZIP, ENC_PASSWORD


def add_layout_pair(root, manifest):
    """Both middle slices consist entirely of encrypted stored-member data."""
    payload = random.Random(107).randbytes(47000)
    truth = root / "truth"
    (truth / "body.dat").write_bytes(payload)
    archive = root / "master" / "stored.zip"
    seven = Path(__file__).resolve().parents[3] / "tools/7z.exe"
    subprocess.run(
        [
            seven,
            "a",
            "-tzip",
            "-mx=0",
            "-mem=ZipCrypto",
            "-p" + ENC_PASSWORD,
            archive,
            "body.dat",
        ],
        cwd=truth,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    data = archive.read_bytes()
    with zipfile.ZipFile(archive) as z:
        member = z.infolist()[0]
        assert (
            member.compress_type == 0
            and z.read(member, pwd=ENC_PASSWORD.encode()) == payload
        )
        start = (
            30
            + int.from_bytes(data[26:28], "little")
            + int.from_bytes(data[28:30], "little")
        )
        header = data[start : start + 12]
        check_byte = data[11] if member.flag_bits & 8 else member.CRC >> 24
        assert zipfile._ZipDecrypter(ENC_PASSWORD.encode())(header)[-1] == check_byte
        wrong = []
        for i in itertools.count():
            candidate = f"fixture-{i}"
            if zipfile._ZipDecrypter(candidate.encode())(header)[-1] == check_byte:
                wrong.append(candidate)
            if len(wrong) == 2:
                break
        assert len(wrong) == 2
        assert start + 12 < 12000 < 36000 < start + member.compress_size
    for mirrored in (False, True):
        case = "body-order-" + ("left" if mirrored else "right")
        folder = root / "visible" / case
        folder.mkdir()
        names = []
        for i in range(1, 5):
            other = {2: 3, 3: 2}.get(i, i)
            a, b = (i, other) if mirrored else (other, i)
            name = f"shared.build{a}.chunk{b}.bin"
            (folder / name).write_bytes(data[12000 * (i - 1) : 12000 * i])
            names.append(name)
        manifest[case] = dict(
            groups={"zip": names},
            passwords=[*wrong, ENC_PASSWORD],
            expected=["body.dat"],
            ambiguous=False,
        )


def add_rar_controls(root, manifest):
    repo = Path(__file__).resolve().parents[3]
    case = "rar4-collision"
    folder = root / "visible" / case
    folder.mkdir()
    shutil.copyfile(
        repo / "tests/data/rar4_tiny_crc_collision.rar", folder / "bundle.rar"
    )
    for name, data in {"a.bin": b"K", "z.bin": b"Z" * 2048}.items():
        (root / "truth" / name).write_bytes(data)
    manifest[case] = dict(
        groups={"rar": ["bundle.rar"]},
        passwords=["rar-collision-287", "secret"],
        expected=["a.bin", "z.bin"],
        ambiguous=False,
    )
    # Conflicting numeric columns, but an encrypted RAR header carries the real volume number.
    case = "rar5-header-layout"
    folder = root / "visible" / case
    folder.mkdir()
    name = "sealed.dat"
    (root / "truth" / name).write_bytes(random.Random(108).randbytes(165000))
    dest = root / "master" / "sealed"
    dest.mkdir()
    subprocess.run(
        [
            shutil.which("rar"),
            "a",
            "-idq",
            "-ma5",
            "-hpsecret",
            "-m0",
            "-v48k",
            str(dest / "sealed.rar"),
            name,
        ],
        cwd=root / "truth",
        check=True,
    )
    parts = sorted(dest.glob("*.rar"))
    assert len(parts) == 4
    names = []
    for i, part in enumerate(parts, 1):
        n = f"shared.build{ {2: 3, 3: 2}.get(i, i) }.chunk{i}.bin"
        names.append(n)
        shutil.copyfile(part, folder / n)
    manifest[case] = dict(
        groups={"rar": names},
        passwords=["incorrect", "secret"],
        expected=[name],
        ambiguous=False,
    )


def generate(root):
    visible = root / "visible"
    truth = root / "truth"
    truth.mkdir(parents=True)
    archives = {}
    for group in ("alpha", "beta"):
        name = group + ".dat"
        payload = random.Random(group).randbytes(112000)
        (truth / name).write_bytes(payload)
        archive = root / "master" / group / "job.rar"
        archive.parent.mkdir(parents=True)
        subprocess.run(
            [
                shutil.which("rar"),
                "a",
                "-idq",
                "-ma5",
                "-m0",
                "-v48k",
                "-p" + ENC_PASSWORD,
                str(archive),
                name,
            ],
            cwd=truth,
            check=True,
        )
        archives[group] = sorted(archive.parent.glob("*.rar"))
        assert len(archives[group]) == 3
    manifest = {}

    def stage(case, entries, passwords, expected, ambiguous=False):
        folder = visible / case
        folder.mkdir(parents=True)
        manifest[case] = dict(
            groups={}, passwords=passwords, expected=expected, ambiguous=ambiguous
        )
        for group, slots in entries.items():
            ordered = []
            for file, new in slots:
                shutil.copyfile(file, folder / new)
                ordered.append(new)
            manifest[case]["groups"][group] = ordered

    pw = ["incorrect", ENC_PASSWORD]
    groups = {
        g: [(f, f"{g}.chunk{i}.bin") for i, f in enumerate(files, 1)]
        for g, files in archives.items()
    }
    stage("solvable", groups, pw, ["alpha.dat", "beta.dat"])
    stage(
        "late-before",
        {"alpha": groups["alpha"], "beta": [groups["beta"][0], groups["beta"][2]]},
        pw,
        ["alpha.dat"],
    )
    stage("late-after", groups, pw, ["alpha.dat", "beta.dat"])
    # Both copies of each slot are byte-identical, and origin names carry no family identifier.
    names = ["cedar", "rose", "lilac", "mint", "oak", "elm"]
    stage(
        "ambiguous",
        {
            g: [(f, names[2 * i + j] + ".bin") for i, f in enumerate(archives["alpha"])]
            for j, g in enumerate(("copy1", "copy2"))
        },
        pw,
        [],
    )
    raw, collisions = LEGACY_ZIP["zip-crypto-shrink"]
    archive = root / "master" / "collision.zip"
    archive.write_bytes(bytes.fromhex(raw))
    check = archive.read_bytes()[31:43]
    check_byte = int.from_bytes(archive.read_bytes()[14:18], "little") >> 24
    assert all(
        zipfile._ZipDecrypter(p.encode())(check)[-1] == check_byte
        for p in [*collisions, ENC_PASSWORD]
    )
    # Original member is a literal-coded Shrink fixture. Recover the expected literals independently.
    body = zipfile._ZipDecrypter(ENC_PASSWORD.encode())(archive.read_bytes()[31:74])[
        12:
    ]
    packed = int.from_bytes(body, "little")
    import zlib

    payload = bytes((packed >> (9 * i)) & 511 for i in range(27))
    assert zlib.crc32(payload) == int.from_bytes(archive.read_bytes()[14:18], "little")
    (truth / "a").write_bytes(payload)
    stage(
        "collision",
        {"zip": [(archive, "bundle.zip")]},
        [*collisions, ENC_PASSWORD],
        ["a"],
    )
    # A second observable layout competes with the actual raw-slice order.
    parts = []
    data = archive.read_bytes()
    for i, start in enumerate(range(0, len(data), 40), 1):
        f = root / "master" / f"slice{i}"
        f.write_bytes(data[start : start + 40])
        parts.append((f, f"shared.build{ {2: 3, 3: 2}.get(i, i) }.chunk{i}.bin"))
    stage("collision-layout", {"zip": parts}, [*collisions, ENC_PASSWORD], ["a"])
    add_layout_pair(root, manifest)
    add_rar_controls(root, manifest)
    freeze(root, manifest)


def freeze(root, manifest):
    visible = root / "visible"
    truth = root / "truth"
    (root / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    with zipfile.ZipFile(root / "corpus.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for f in [root / "manifest.json", *visible.rglob("*"), *truth.glob("*")]:
            if f.is_file() and f.suffix != ".nzb":
                z.write(f, f.relative_to(root))


if __name__ == "__main__":
    generate(Path(sys.argv[1]).resolve())
