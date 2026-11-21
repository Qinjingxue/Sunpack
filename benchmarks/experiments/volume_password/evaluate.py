"""Audit bytes, source selections and observed operations; preserve method-specific units."""

import argparse
import json
from pathlib import Path
import re
import shutil
import zipfile

from benchmarks.scenarios.worker_300m import read_frame


def load(p):
    return json.loads(p.read_text(encoding="utf-8"))


def written(folder, truth, sources):
    rows = []
    for p in sorted(folder.rglob("*")):
        if not p.is_file():
            continue
        data = p.read_bytes()
        rows.append(
            dict(
                path=p.relative_to(folder).as_posix(),
                size=len(data),
                matches_payload=[k for k, v in truth.items() if v == data],
                matches_source=[k for k, v in sources.items() if v == data],
            )
        )
    return rows


def frames(folder):
    rows = []
    for cmd in sorted(folder.glob("*/call.json")):
        for i in cmd.parent.glob("*-in.bin"):

            def read(f):
                with f.open("rb") as h:
                    while h.tell() < f.stat().st_size:
                        yield read_frame(h)

            results = {
                x["job_id"]: x
                for x in read(i.with_name(i.name.replace("-in.", "-out.")))
                if x.get("type") == "result"
            }
            for request in read(i):
                if "archive_input" not in request:
                    continue
                answer = results[request["job_id"]]
                desc = request["archive_input"]
                parts = [Path(x["path"]).name for x in desc.get("parts", [])]
                selected = answer.get("volume_selection")
                if selected:
                    sources = desc["volume_attempts"]["sources"]
                    parts = [
                        Path(sources[idx]["path"]).name for idx in selected["sources"]
                    ]
                rows.append(
                    dict(
                        cli=load(cmd)[0],
                        op=request["operation"],
                        status=answer["status"],
                        entry=Path(desc["entry_path"]).name,
                        parts=parts,
                        selection=selected,
                        matched_index=answer.get("matched_index"),
                        candidates=request.get("password_candidates", []),
                    )
                )
    return rows


def evaluate(corpus, locations, diagnostic, dest):
    dest.mkdir(parents=True, exist_ok=True)
    manifest = load(corpus / "manifest.json")
    truth = {p.name: p.read_bytes() for p in (corpus / "truth").iterdir()}
    runs = []
    with zipfile.ZipFile(dest / "evidence.zip", "w", zipfile.ZIP_DEFLATED) as raw:
        for method, base in locations.items():
            for name, c in manifest.items():
                d = base / method / name
                row = dict(
                    case=name,
                    method=method,
                    expected=c["expected"],
                    truth_groups=c["groups"],
                )
                sources = {
                    p.name: p.read_bytes()
                    for p in (corpus / "visible" / name).iterdir()
                }
                output = written(d / "output", truth, sources)
                row["output"] = output
                row["exact_named"] = [
                    path
                    for path in c["expected"]
                    if any(
                        Path(f["path"]).name == path and path in f["matches_payload"]
                        for f in output
                    )
                ]
                if method in ("joint", "serial"):
                    sc = load(d / "scan.json")
                    ex = load(d / "extract.json")
                    row["scan"] = [
                        dict(
                            main=Path(it["main_path"]).name,
                            parts=[Path(p).name for p in it.get("all_parts", [])],
                            completeness=it.get("volume_completeness"),
                            plan=bool(it.get("volume_attempts")),
                            error=it.get("error_kind"),
                        )
                        for it in sc["stdout"]["items"]
                    ]
                    row["status"] = [j["stdout"]["summary"] for j in ex]
                    row["wall_ms"] = round(1000 * sum(j["seconds"] for j in ex), 2)
                    if method == "serial":
                        row["frozen_groups"] = load(d / "selected.json")
                        quals = load(d / "qualification.json")
                        row["qualifications"] = [q["status"] for q in quals]
                        row["wall_ms"] += round(
                            1000
                            * (
                                sc["seconds"]
                                + load(d / "preparation.json")
                                + sum(
                                    q["scan"]["seconds"] for q in quals if "scan" in q
                                )
                            ),
                            2,
                        )
                    calls = frames(diagnostic / method / name / "frames")
                    assert (
                        written(diagnostic / method / name / "output", truth, sources)
                        == output
                    ), (method, name)
                    row["worker_calls"] = calls
                    row["attempts"] = sum(
                        1 for f in calls if f["cli"] == "extract" or method == "serial"
                    )
                    row["attempt_unit"] = (
                        "worker IPC jobs (exclude independent joint scan)"
                    )
                    evidence = list(d.glob("*.json")) + list(
                        (diagnostic / method / name / "frames").rglob("*")
                    )
                    for f in evidence:
                        if f.is_file():
                            anchor = (
                                d if f.is_relative_to(d) else diagnostic / method / name
                            )
                            raw.write(
                                f, f"{method}/{name}/{f.relative_to(anchor).as_posix()}"
                            )
                else:
                    result = load(d / "result.json")
                    lines = (
                        (d / "console.log")
                        .read_text(encoding="utf-8", errors="replace")
                        .splitlines()
                    )
                    row["wall_ms"] = round(1000 * result["seconds"], 2)
                    if method == "nzbget":
                        row["status"] = [
                            s
                            for s in lines
                            if re.search(
                                r"Unpack for|Nothing to unpack|Could not unpack", s
                            )
                        ]
                        row["renames"] = [
                            s
                            for s in lines
                            if re.search(r"\] Renaming |Could not rename", s)
                        ]
                        row["attempts"] = sum(
                            bool(re.search(r"\] (Unrar: UNRAR |7-Zip: 7-Zip)", s, re.I))
                            for s in lines
                        )
                        row["attempt_unit"] = "decoder startup banners"
                    else:
                        h = result["history"][0]
                        row["status"] = [h["status"], h["fail_message"]]
                        row["renames"] = [
                            s.split("Deobfuscate: ")[-1]
                            for s in lines
                            if "Deobfuscate: Renaming " in s
                        ]
                        row["attempts"] = sum(
                            "Running external command:" in s
                            and bool(
                                re.search(
                                    r"(rar_extract_core|seven_extract_core|create_unrar_instance)",
                                    s,
                                )
                            )
                            and bool(re.search(r"""["']x["']""", s))
                            for s in lines
                        )
                        row["attempt_unit"] = "logged decoder extract launches"
                    raw.write(d / "result.json", f"{method}/{name}/result.json")
                    # Retain job evidence, omitting unrelated host startup/configuration messages.
                    pattern = r"Renaming |Could not rename|Unrar:|7-Zip:|Trying password|[Uu]npack|[Cc]hecksum|[Pp]assworded|staircase|Deobfuscate:|fully encrypted|\.\.\.Moving|RAR renamer|Successfully downloaded"
                    raw.writestr(
                        f"{method}/{name}/job.log",
                        "\n".join(s for s in lines if re.search(pattern, s)),
                    )
                runs.append(row)
    (dest / "runs.json").write_text(
        json.dumps(runs, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    shutil.copyfile(corpus / "corpus.zip", dest / "corpus.zip")
    print("observations", len(runs))
    for row in runs:
        print(
            row["method"],
            row["case"],
            ",".join(row["exact_named"]),
            row["attempts"],
            round(row["wall_ms"]),
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    for key in ("corpus", "joint", "serial", "nzbget", "sabnzbd", "diagnostic", "dest"):
        p.add_argument("--" + key, type=Path, required=True)
    a = p.parse_args()
    evaluate(
        a.corpus,
        {k: getattr(a, k) for k in ("joint", "serial", "nzbget", "sabnzbd")},
        a.diagnostic,
        a.dest,
    )
