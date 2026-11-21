"""Feed frozen snapshots to both stock Windows clients using NZBGet's loopback NServ."""

from contextlib import contextmanager
from pathlib import Path
import json
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def child(cmd, log, cwd):
    with log.open("wb") as output:
        p = subprocess.Popen(
            cmd,
            stdout=output,
            stderr=subprocess.STDOUT,
            cwd=cwd,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
            p.wait()


def save(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def nzb(client, root, case, work, port):
    opts = {
        "MainDir": work,
        "DestDir": work / "output",
        "InterDir": work / "inter",
        "WriteLog": "append",
        "LogFile": work / "client.log",
        "Server1.Host": "127.0.0.1",
        "Server1.Port": port,
        "Server1.Encryption": "no",
        "Server1.Username": "",
        "Server1.Password": "",
        "Server1.Connections": 1,
        "ControlIP": "127.0.0.1",
        "ControlPort": free_port(),
        "UnpackPassFile": work / "passwords.txt",
        "OutputMode": "log",
        "DetailTarget": "both",
        "InfoTarget": "both",
        "DebugTarget": "log",
        "UnpackCleanupDisk": "no",
        "AppendCategoryDir": "no",
        "DiskSpace": 0,
    }
    template = (client.parent / "nzbget.conf.template").read_text(encoding="utf-8-sig")
    for k, v in opts.items():
        template, count = re.subn(
            "^" + re.escape(k) + "=.*$",
            lambda _: k + "=" + str(v),
            template,
            flags=re.M,
        )
        if count != 1:
            raise ValueError(k)
    cfg = work / "nzbget.conf"
    cfg.write_text(template, encoding="utf-8")
    start = time.perf_counter()
    with (work / "console.log").open("wb") as log:
        p = subprocess.run(
            [client, "-c", cfg, root / "visible" / (case + ".nzb")],
            cwd=work,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    return dict(seconds=time.perf_counter() - start, code=p.returncode)


def sab(client, root, case, work, port):
    ctl = free_port()
    conf = work / "sabnzbd.ini"
    conf.write_text(
        f"""[misc]
api_key = localtest
host = 127.0.0.1
port = {ctl}
download_dir = {work / "inter"}
complete_dir = {work / "output"}
admin_dir = {work / "admin"}
log_dir = {work / "logs"}
password_file = {work / "passwords.txt"}
direct_unpack_tested = 1
direct_unpack = 0
pause_on_pwrar = 0
deobfuscate_final_filenames = 0
check_new_rel = 0
auto_browser = 0
[servers]
[[local]]
name = local
host = 127.0.0.1
port = {port}
ssl = 0
enable = 1
connections = 1
""",
        encoding="utf-8",
    )

    def api(mode, content=None):
        url = "http://127.0.0.1:%d/api?" % ctl + urllib.parse.urlencode(
            dict(mode=mode, output="json", apikey="localtest")
        )
        req = urllib.request.Request(url)
        if content is not None:
            req.add_header("Content-Type", "multipart/form-data; boundary=RQ2form")
            req.data = (
                (
                    f'--RQ2form\r\nContent-Disposition: form-data; name="name"; filename="{case}.nzb"\r\n'
                    "Content-Type: application/x-nzb\r\n\r\n"
                ).encode()
                + content
                + b"\r\n--RQ2form--\r\n"
            )
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.load(response)

    with child(
        [client, "--new", "--browser", "0", "--logging", "2", "-f", conf],
        work / "console.log",
        work,
    ) as p:
        while True:
            if p.poll() is not None:
                raise RuntimeError(("SAB startup", p.returncode, work))
            try:
                api("version")
                break
            except OSError:
                time.sleep(0.1)
        start = time.perf_counter()
        job = api("addfile", (root / "visible" / (case + ".nzb")).read_bytes())
        ids = job["nzo_ids"]
        while True:
            if p.poll() is not None:
                raise RuntimeError(("SAB processing", p.returncode, work))
            history = api("history")
            slots = [s for s in history["history"]["slots"] if s["nzo_id"] in ids]
            if slots and slots[0]["status"] in ("Completed", "Failed"):
                break
            time.sleep(0.1)
        result = dict(seconds=time.perf_counter() - start, history=slots)
        try:
            api("shutdown")
        except (OSError, ValueError):
            pass
        p.wait()
        return result


def main(base, root, out, mode):
    nzbexe = base / "nzb-bin/nzbget.exe"
    sabexe = base / "sab-bin/SABnzbd/SABnzbd-console.exe"
    out.mkdir(parents=True, exist_ok=True)
    port = free_port()
    subprocess.run(
        [nzbexe, "--nserv", "-d", root / "visible", "-z", "500000", "-q"],
        check=True,
        capture_output=True,
    )
    cases = json.loads((root / "manifest.json").read_text())
    with child(
        [nzbexe, "--nserv", "-b", "127.0.0.1", "-p", str(port), "-d", root / "visible"],
        out / (mode + "-nserv.log"),
        out,
    ) as server:
        while True:
            if server.poll() is not None:
                raise RuntimeError("NServ startup")
            try:
                with socket.create_connection(("127.0.0.1", port)):
                    break
            except OSError:
                time.sleep(0.1)
        for case, entry in cases.items():
            if sys.argv[5:] and case not in sys.argv[5:]:
                continue
            work = out / mode / case
            work.mkdir(parents=True)
            (work / "passwords.txt").write_text(
                "\n".join(entry["passwords"]) + "\n", encoding="utf-8"
            )
            result = (
                nzb(nzbexe, root, case, work, port)
                if mode == "nzbget"
                else sab(sabexe, root, case, work, port)
            )
            save(work / "result.json", result)
            print(mode, case, round(result["seconds"], 2), flush=True)


if __name__ == "__main__":
    main(*(Path(v).resolve() for v in sys.argv[1:4]), sys.argv[4])
