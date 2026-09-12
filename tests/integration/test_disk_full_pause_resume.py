"""真实满盘端到端（VHD）。

默认 `pytest.skip`；仅当进程具备管理员权限时执行（`diskpart` 需要提权）。

用 VHD 而不是写满开发机磁盘，是为了精确控制容量并可随时 attach / detach / 删除。

注入式失败的用例替代不了这里：真实的 `ERROR_DISK_FULL` 是否真的从 `WriteFile` /
`create_directories` 里出来、满盘时 SDK 是否真的被 producer 反压挡住、满盘期间
`shutdown` / `cancel` 是否真的能穿透 native 侧的 gate、释放空间后同 handle 续写是否
真的成功，都只有真实满盘才能证明。

每个用例都会自己创建并销毁 VHD：它们不依赖任何预置盘符或残留文件。
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="VHD / diskpart 是 Windows-only"
)

_MIB = 1 << 20
_VHD_ALIGNMENT_MB = 8
_VHD_MIN_SIZE_MB = 16
_VHD_FILESYSTEM_SAFETY_BYTES = 8 * _MIB
_VHD_HOST_FREE_RESERVE_BYTES = 32 * _MIB
_DISKPART_MAX_ATTEMPTS = 8
_DISKPART_RETRY_DELAY_SECONDS = 0.75
_DISKPART_LOCK_TIMEOUT_SECONDS = 120.0
_DISKPART_LOCK_PATH = Path(tempfile.gettempdir()) / "sunpack-diskpart-test.lock"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - 非 Windows
        return False


requires_vhd = pytest.mark.skipif(
    not _is_admin(),
    reason="需要管理员权限（diskpart 提权）",
)


def _available_drive_letter(preferred: str) -> str:
    drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
    all_letters = [chr(code) for code in range(ord("D"), ord("Z") + 1)]
    candidates: list[str] = []

    # xdist workers must not all race for the same preferred letter. Reserve a
    # deterministic pair of candidate letters per worker; the second slot is
    # needed by the one test that mounts two VHDs at once.
    worker_name = os.environ.get("PYTEST_XDIST_WORKER", "")
    if worker_name.startswith("gw") and worker_name[2:].isdigit():
        worker_index = int(worker_name[2:])
        slot = 1 if preferred.upper() in {"W", "Y"} else 0
        worker_candidate_index = worker_index * 2 + slot
        if worker_candidate_index < len(all_letters):
            candidates.append(all_letters[worker_candidate_index])

    candidates.append(preferred.upper())
    candidates.extend(all_letters)
    candidates = list(dict.fromkeys(candidates))
    for letter in candidates:
        if not drive_mask & (1 << (ord(letter) - ord("A"))):
            return letter
    raise RuntimeError("no unused Windows drive letter is available for the VHD test")


def _dynamic_vhd_size_mb(directory: Path, payload_bytes: int, blocked_free_bytes: int) -> int:
    required_bytes = (
        payload_bytes
        + blocked_free_bytes
        + _VHD_FILESYSTEM_SAFETY_BYTES
    )
    required_mb = (required_bytes + _MIB - 1) // _MIB
    size_mb = max(
        _VHD_MIN_SIZE_MB,
        ((required_mb + _VHD_ALIGNMENT_MB - 1) // _VHD_ALIGNMENT_MB) * _VHD_ALIGNMENT_MB,
    )

    host_free_bytes = shutil.disk_usage(str(directory)).free
    host_required_bytes = size_mb * _MIB + _VHD_HOST_FREE_RESERVE_BYTES
    if host_free_bytes < host_required_bytes:
        pytest.skip(
            "宿主磁盘剩余空间不足以安全创建 VHDX："
            f"需要约 {host_required_bytes // _MIB} MiB，"
            f"当前约 {host_free_bytes // _MIB} MiB"
        )
    return size_mb


@contextmanager
def _diskpart_critical_section():
    """Serialize only the OS-global DiskPart command, not the test workloads."""
    import msvcrt

    _DISKPART_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    stream = open(_DISKPART_LOCK_PATH, "a+b")
    stream.seek(0, os.SEEK_END)
    if stream.tell() == 0:
        stream.write(b"0")
        stream.flush()

    deadline = time.monotonic() + _DISKPART_LOCK_TIMEOUT_SECONDS
    try:
        while True:
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("timed out waiting for the global DiskPart test lock")
                time.sleep(0.1)
        yield
    finally:
        try:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            stream.close()


class SpaceVhd:
    """一个按用例需求动态计算容量的固定容量 NTFS 测试盘。

    用完必须 `close()`：卸载并删除 VHDX 文件。所有用例都用 try/finally 保证这一点，
    否则满盘残留会污染后续测试。盘符在挂载时从当前未使用盘符中选择。
    """

    def __init__(
        self,
        directory: Path,
        letter: str,
        *,
        payload_bytes: int,
        blocked_free_bytes: int,
    ):
        self.directory = directory
        self.path = directory / f"space-{letter.lower()}-{uuid.uuid4().hex[:8]}.vhdx"
        self._preferred_letter = letter
        self.letter = letter
        self.payload_bytes = payload_bytes
        self.blocked_free_bytes = blocked_free_bytes
        self.size_mb: int | None = None
        self._attached = False
        self._needs_diskpart_cleanup = False
        self._filler: Path | None = None

    # diskpart 原语
    @staticmethod
    def _diskpart(script: str) -> None:
        last_error = ""
        for attempt in range(_DISKPART_MAX_ATTEMPTS):
            with _diskpart_critical_section():
                completed = subprocess.run(
                    ["diskpart"],
                    input=script,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
            # diskpart 在部分失败时仍返回 0，因此必须检查输出。
            combined = f"{completed.stdout}\n{completed.stderr}"
            last_error = combined
            transient = "disk management services" in combined.lower()
            if not transient:
                if "Virtual Disk Service error" in combined or "错误" in combined and "DiskPart" not in combined:
                    raise RuntimeError(f"diskpart failed:\n{combined}")
                if completed.returncode != 0:
                    raise RuntimeError(f"diskpart exit {completed.returncode}:\n{combined}")
                return
            if attempt + 1 < _DISKPART_MAX_ATTEMPTS:
                time.sleep(_DISKPART_RETRY_DELAY_SECONDS * (attempt + 1))

        raise RuntimeError(f"diskpart remained unavailable after retries:\n{last_error}")

    def attach(self) -> None:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            self.size_mb = _dynamic_vhd_size_mb(
                self.directory,
                self.payload_bytes,
                self.blocked_free_bytes,
            )
            self.letter = _available_drive_letter(self._preferred_letter)
            if self.path.exists():
                self.path.unlink()
            self._needs_diskpart_cleanup = True
            self._diskpart(
                "\n".join(
                    [
                        f"create vdisk file={self.path} maximum={self.size_mb} type=fixed",
                        f"select vdisk file={self.path}",
                        "attach vdisk",
                        "create partition primary",
                        "format fs=ntfs quick label=SUNPACKSPACE",
                        f"assign letter={self.letter}",
                        "exit",
                    ]
                )
            )
            self._attached = True
            deadline = time.monotonic() + 60.0
            while time.monotonic() < deadline:
                if Path(f"{self.letter}:\\").exists():
                    return
                time.sleep(0.25)
            raise RuntimeError(f"volume {self.letter}: did not appear")
        except BaseException:
            self._detach_best_effort()
            self._remove_image()
            raise

    def _detach_best_effort(self) -> None:
        if not self._needs_diskpart_cleanup:
            return
        try:
            self._diskpart(
                "\n".join([f"select vdisk file={self.path}", "detach vdisk", "exit"])
            )
        except Exception:
            pass
        self._attached = False
        self._needs_diskpart_cleanup = False

    def _remove_image(self) -> None:
        for _ in range(20):
            try:
                if self.path.exists():
                    self.path.unlink()
                return
            except OSError:
                time.sleep(0.25)

    def detach(self) -> None:
        if not self._attached:
            return
        self._diskpart(
            "\n".join([f"select vdisk file={self.path}", "detach vdisk", "exit"])
        )
        self._attached = False
        self._needs_diskpart_cleanup = False

    def close(self) -> None:
        try:
            self.release()
        finally:
            self._detach_best_effort()
            self._remove_image()

    # 空间控制
    @property
    def root(self) -> Path:
        return Path(f"{self.letter}:\\")

    def free_bytes(self) -> int:
        return shutil.disk_usage(str(self.root)).free

    def fill_until_free_below(self, remaining_bytes: int) -> None:
        """写一个填充文件，直到可用空间小于给定值（然后把它留给用例释放）。"""

        chunk = bytes(range(256)) * 256  # 64 KiB，避免被 NTFS 压缩（NTFS 默认不压缩）
        self._filler = self.root / "sunpack-space-filler.bin"
        with open(self._filler, "wb") as handle:
            while True:
                free = self.free_bytes()
                if free <= remaining_bytes + len(chunk):
                    break
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())

    def release(self) -> None:
        """释放填充文件占用的空间（模拟"用户清理了磁盘"）。"""

        if self._filler is not None and self._filler.exists():
            self._filler.unlink()
        self._filler = None

    def __enter__(self) -> "SpaceVhd":
        self.attach()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class WorkerSession:
    """按行 JSON 协议驱动 sunpack_sevenzip_worker.exe。

    SevenZipRunner 会在自己的看门狗里取消 job，而这里要测的是 native 侧的行为，
    因此本文件直接说协议：写请求、读事件、按需 cancel / shutdown。
    """

    def __init__(self, worker_path: Path, extra_environment: dict[str, str] | None = None):
        self.worker_path = str(worker_path)
        self.extra_environment = dict(extra_environment or {})
        self.process: subprocess.Popen | None = None
        # 累积列表，不是消费式队列：drain 会丢掉同时到达的 result 事件。
        self._all: list[dict] = []
        self._lock = threading.Lock()
        self._raw: list[str] = []
        self._reader: threading.Thread | None = None

    def __enter__(self) -> "WorkerSession":
        environment = dict(os.environ)
        environment.update(self.extra_environment)
        self.process = subprocess.Popen(
            [self.worker_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=environment,
        )
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self.wait_for(lambda event: event.get("type") == "worker_ready", timeout=60.0)
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _pump(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        for line in self.process.stdout:
            self._raw.append(line)
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                with self._lock:
                    self._all.append(payload)

    def send(self, payload: dict) -> None:
        assert self.process is not None and self.process.stdin is not None
        self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def close_stdin(self) -> None:
        """关掉 stdin 制造 EOF（一次性 `echo request | worker.exe` 的形态）。

        EOF 之后 worker 进入排空：停止接收新请求，但 controller、space monitor
        与 worker 线程必须继续活着。
        """

        assert self.process is not None and self.process.stdin is not None
        try:
            self.process.stdin.close()
        except Exception:
            pass
        self.process.stdin = None

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._all)

    def wait_for(self, predicate, timeout: float = 300.0) -> dict | None:
        """等待第一个满足条件的事件（非破坏性：可以反复调用）。"""

        deadline = time.monotonic() + timeout
        while True:
            for event in self.snapshot():
                if predicate(event):
                    return event
            if self.process is not None and self.process.poll() is not None:
                return None
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)

    def events(self) -> list[dict]:
        return self.snapshot()

    def space_events(self) -> list[dict]:
        return [
            event
            for event in self.snapshot()
            if str(event.get("event", "")).startswith("space_")
        ]

    def wait_exit(self, timeout: float = 15.0) -> int:
        assert self.process is not None
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
            raise

    def close(self) -> None:
        if self.process is None:
            return
        try:
            self.send({"worker_command": "shutdown"})
        except Exception:
            pass
        try:
            self.process.wait(timeout=10)
        except Exception:
            self.process.kill()
        self.process = None


def _worker_path() -> Path:
    from sunpack.support.resources import get_sevenzip_bridge_worker_path

    path = Path(get_sevenzip_bridge_worker_path())
    if not path.exists():
        pytest.skip(f"native worker not built: {path}")
    return path


def _seven_zip_dll() -> Path:
    from sunpack.support.resources import get_7z_dll_path

    path = Path(get_7z_dll_path())
    if not path.exists():
        pytest.skip(f"7z.dll not found: {path}")
    return path


def _make_archive(path: Path, payload_bytes: int, entries: int = 1) -> bytes:
    """写一个 stored（不压缩）的 zip，返回原始内容以便逐字节比对。"""

    payload = bytes((index * 131 + index // 509) & 0xFF for index in range(payload_bytes))
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        if entries == 1:
            archive.writestr("payload.bin", payload)
        else:
            per = payload_bytes // entries
            for index in range(entries):
                archive.writestr(f"part-{index:03d}.bin", payload[index * per : (index + 1) * per])
    return payload


def _physical_volume_key(path: Path) -> str:
    r"""解析输出目录所在的真实物理卷身份键（\\?\Volume{GUID} 小写无尾反斜杠）。

    解析失败时返回空串 —— 此时 native 侧退化成 synthetic `job:<id>` 键，仍然安全，
    只是跨 job 去重失效。
    """

    try:
        from sunpack.support.output_paths import resolve_output_volume_key

        return str(resolve_output_volume_key(str(path)) or "")
    except Exception:
        return ""


def _job_request(job_id: str, archive: Path, output_dir: Path, volume_key: str = "") -> dict:
    request = {
        "job_id": job_id,
        "seven_zip_dll_path": str(_seven_zip_dll()),
        "archive_path": str(archive),
        "output_dir": str(output_dir),
    }
    if volume_key:
        request["output_volume_key"] = volume_key
    return request


def _gate_environment() -> dict[str, str]:
    """打开卷空间 gate。

    默认显式注入 `SUNPACK_VOLUME_SPACE_GATE=1`：必须在"功能被明确开启"这一前提下
    验证行为，否则一旦默认值被改回 false，本文件会静默地测了个寂寞。

    设 `SUNPACK_SPACE_TEST_USE_NATIVE_DEFAULT=1` 时不注入任何开关，用来验证
    "默认开启"本身真的生效（端到端，而不是只读配置）。
    """

    if os.environ.get("SUNPACK_SPACE_TEST_USE_NATIVE_DEFAULT") == "1":
        return {}

    return {
        "SUNPACK_VOLUME_SPACE_GATE": "1",
        "SUNPACK_VOLUME_SPACE_POLL_MS": "200",
        "SUNPACK_VOLUME_SPACE_STATUS_REPORT_MS": "1000",
    }


def _vhd_directory(tmp_path_factory) -> Path:
    """VHD 落地目录。

    默认落在 pytest 的临时目录（通常在 C:），但可以用 `SUNPACK_SPACE_TEST_VHD_DIR`
    指向一个空间充裕的盘 —— 每个用例会写入整个 VHD 容量（固定盘）。
    """

    configured = os.environ.get("SUNPACK_SPACE_TEST_VHD_DIR")
    if configured:
        directory = Path(configured)
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    return Path(tmp_path_factory.mktemp("space-vhd"))


@requires_vhd
def test_win17_root_output_directory_on_full_volume(tmp_path_factory):
    """输出目录尚不存在且所在盘已满时，必须出现 space_blocked 而不是直接失败。

    根输出目录创建发生在 ExtractToDiskCallback 构造之前，直接失败会以
    output_prepare / output_filesystem 返回。
    """

    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "big.zip"
    payload = _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "V",
        payload_bytes=len(payload),
        blocked_free_bytes=256 * 1024,
    ) as vhd:
        # 留出不到 1 MiB：连目录项都可能创建不出来。
        vhd.fill_until_free_below(256 * 1024)
        assert vhd.free_bytes() < 1 * _MIB

        output_dir = vhd.root / "fresh-output-directory"
        assert not output_dir.exists()

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw17", archive, output_dir))
            blocked = session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            )
            assert blocked is not None, (
                "输出盘满时必须自动暂停；实际事件流："
                + json.dumps(session.events(), ensure_ascii=False)
            )
            assert blocked["episode_id"] >= 1
            assert blocked["win32_error"] in {112, 39, 314, 1295}
            assert blocked["volume_query_ok"] is True
            # 核心断言：绝不能是 output_prepare / output_filesystem 直接失败。
            premature = session.wait_for(
                lambda event: event.get("type") == "result", timeout=0.5
            )
            assert premature is None, f"满盘不得直接产生终态结果：{premature}"

            vhd.release()
            resumed = session.wait_for(
                lambda event: event.get("event") == "space_resumed", timeout=120.0
            )
            assert resumed is not None, "释放空间后必须自动恢复"
            assert resumed["episode_id"] == blocked["episode_id"]

            result = session.wait_for(
                lambda event: event.get("type") == "result", timeout=180.0
            )
            assert result is not None and result.get("status") == "ok", result

        extracted = output_dir / "payload.bin"
        assert extracted.exists(), "恢复后必须真的解压出文件"
        assert extracted.read_bytes() == payload, "输出必须逐字节等于原始内容"


@requires_vhd
def test_win2_single_writer_full_then_release(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "resume.zip"
    payload = _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "W",
        payload_bytes=len(payload),
        blocked_free_bytes=1 * _MIB,
    ) as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        # 留出 ~1 MiB：足够开始写，但绝不够写完 8 MiB。
        vhd.fill_until_free_below(1 * _MIB)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw2", archive, output_dir))
            blocked = session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            )
            assert blocked is not None

            # 暂停期间不得有终态结果。
            assert session.wait_for(lambda e: e.get("type") == "result", timeout=1.0) is None

            vhd.release()
            assert session.wait_for(
                lambda event: event.get("event") == "space_resumed", timeout=120.0
            ) is not None
            result = session.wait_for(lambda e: e.get("type") == "result", timeout=180.0)
            assert result is not None and result.get("status") == "ok", result

        extracted = output_dir / "payload.bin"
        assert extracted.read_bytes() == payload


@requires_vhd
def test_win13_cancelling_last_waiter_is_not_resume(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "cancel.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "X",
        payload_bytes=8 * _MIB,
        blocked_free_bytes=1 * _MIB,
    ) as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        vhd.fill_until_free_below(1 * _MIB)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw13", archive, output_dir))
            assert session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            ) is not None

            session.send({"worker_command": "cancel", "job_id": "tw13"})
            result = session.wait_for(lambda e: e.get("type") == "result", timeout=60.0)
            assert result is not None and result.get("status") == "failed"

            # 取消绝不等于"卷已恢复"。
            session.send({"worker_command": "shutdown"})
            assert session.wait_exit(timeout=30.0) is not None
            assert not [
                event
                for event in session.space_events()
                if event.get("event") == "space_resumed"
            ], "取消最后一个 waiter 绝不能产生 space_resumed"


@requires_vhd
def test_win20_shutdown_pierces_a_paused_gate(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "shutdown.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "Y",
        payload_bytes=8 * _MIB,
        blocked_free_bytes=1 * _MIB,
    ) as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        vhd.fill_until_free_below(1 * _MIB)

        session = WorkerSession(_worker_path(), _gate_environment())
        session.__enter__()
        try:
            session.send(_job_request("tw20", archive, output_dir))
            assert session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            ) is not None

            # 这里不事先显式取消任何 job：专测"只 wake 不改 terminal 条件"。
            started = time.monotonic()
            session.send({"worker_command": "shutdown"})
            session.wait_exit(timeout=15.0)
            elapsed = time.monotonic() - started
            assert elapsed < 10.0, f"暂停期间 shutdown 用了 {elapsed:.1f}s（预期 1s 量级）"
        finally:
            session.close()


@requires_vhd
def test_win21_two_volumes_recover_independently(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive_a = work / "a.zip"
    archive_b = work / "b.zip"
    payload_a = _make_archive(archive_a, 4 * _MIB)
    payload_b = _make_archive(archive_b, 4 * _MIB)

    with (
        SpaceVhd(
            vhd_directory,
            "V",
            payload_bytes=len(payload_a),
            blocked_free_bytes=512 * 1024,
        ) as vhd_a,
        SpaceVhd(
            vhd_directory,
            "W",
            payload_bytes=len(payload_b),
            blocked_free_bytes=512 * 1024,
        ) as vhd_b,
    ):
        out_a = vhd_a.root / "out"
        out_b = vhd_b.root / "out"
        out_a.mkdir()
        out_b.mkdir()
        vhd_a.fill_until_free_below(512 * 1024)
        vhd_b.fill_until_free_below(512 * 1024)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            # 用真实卷身份键：两个 job 各自命中一个物理卷的 gate。
            key_a = _physical_volume_key(out_a)
            key_b = _physical_volume_key(out_b)
            assert key_a and key_b and key_a != key_b, (key_a, key_b)
            session.send(_job_request("tw21-a", archive_a, out_a, key_a))
            session.send(_job_request("tw21-b", archive_b, out_b, key_b))
            blocked = session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            )
            assert blocked is not None
            # 两个卷都要进入 blocked（两个不同的 volume_key）。
            deadline = time.monotonic() + 90.0
            while time.monotonic() < deadline:
                keys = {
                    event.get("volume_key")
                    for event in session.space_events()
                    if event.get("event") == "space_blocked"
                }
                if {key_a, key_b} <= keys:
                    break
                time.sleep(0.25)
            keys = {
                event.get("volume_key")
                for event in session.space_events()
                if event.get("event") == "space_blocked"
            }
            assert {key_a, key_b} <= keys, f"两个卷都必须进入 blocked：{keys}"

            # 先释放 A：A 必须恢复；此时 B 仍 blocked。
            vhd_a.release()
            deadline = time.monotonic() + 120.0
            while time.monotonic() < deadline:
                if any(
                    event.get("event") == "space_resumed"
                    and event.get("volume_key") == key_a
                    for event in session.space_events()
                ):
                    break
                time.sleep(0.25)
            assert any(
                event.get("event") == "space_resumed" and event.get("volume_key") == key_a
                for event in session.space_events()
            ), "先释放的卷必须能恢复"
            assert not any(
                event.get("event") == "space_resumed" and event.get("volume_key") == key_b
                for event in session.space_events()
            ), "B 仍然满盘，绝不能被误判为已恢复"

            # A 恢复之后再释放 B，B 也必须能恢复。
            vhd_b.release()
            result_a = session.wait_for(
                lambda event: event.get("type") == "result"
                and event.get("job_id") == "tw21-a",
                timeout=240.0,
            )
            result_b = session.wait_for(
                lambda event: event.get("type") == "result"
                and event.get("job_id") == "tw21-b",
                timeout=300.0,
            )
            assert result_a is not None and result_a.get("status") == "ok", (
                "tw21-a 未在超时前完成；事件流："
                + json.dumps(session.events(), ensure_ascii=False)
            )
            assert result_b is not None and result_b.get("status") == "ok", (
                "tw21-b 未在超时前完成；事件流："
                + json.dumps(session.events(), ensure_ascii=False)
            )

        assert (out_a / "payload.bin").read_bytes() == payload_a
        assert (out_b / "payload.bin").read_bytes() == payload_b


@requires_vhd
def test_win12_two_jobs_on_one_volume_both_notified(tmp_path_factory):
    """`affected_jobs_` 扇出的端到端验收。

    两个 job 命中同一个物理卷 → 同一个 gate → 一个 episode，各自收到一条
    space_blocked；恢复时每个 job 各收到一条 space_resumed，probe owner 也必须在
    其中（它抢到许可后已经从 waiters_ 里移除，遍历 waiters_ 会漏掉它）。
    """

    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive_a = work / "tw12-a.zip"
    archive_b = work / "tw12-b.zip"
    payload_a = _make_archive(archive_a, 4 * _MIB)
    payload_b = _make_archive(archive_b, 4 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "V",
        payload_bytes=len(payload_a) + len(payload_b),
        blocked_free_bytes=1536 * 1024,
    ) as vhd:
        out_a = vhd.root / "out-a"
        out_b = vhd.root / "out-b"
        out_a.mkdir()
        out_b.mkdir()
        # 留 ~1.5 MiB：两个 4 MiB 的 job 都写不完。
        vhd.fill_until_free_below(1536 * 1024)
        volume_key = _physical_volume_key(out_a)
        assert volume_key
        assert volume_key == _physical_volume_key(out_b), "两个 job 必须落在同一个物理卷"

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw12-a", archive_a, out_a, volume_key))
            session.send(_job_request("tw12-b", archive_b, out_b, volume_key))

            assert session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=120.0
            ) is not None

            # 两个 job 都必须收到 blocked，且 episode_id 相同（同一卷同一 episode）。
            deadline = time.monotonic() + 120.0
            while time.monotonic() < deadline:
                blocked = [
                    event
                    for event in session.space_events()
                    if event.get("event") == "space_blocked"
                ]
                if {"tw12-a", "tw12-b"} <= {event.get("job_id") for event in blocked}:
                    break
                time.sleep(0.25)
            blocked = [
                event
                for event in session.space_events()
                if event.get("event") == "space_blocked"
            ]
            by_job = {event.get("job_id"): event for event in blocked}
            assert {"tw12-a", "tw12-b"} <= set(by_job), (
                "同一卷的两个 job 都必须收到 space_blocked（只有一个 probe owner 收到"
                "就是 §4.7.1.1 的 Bug A）；实际：" + json.dumps(blocked, ensure_ascii=False)
            )
            assert by_job["tw12-a"]["episode_id"] == by_job["tw12-b"]["episode_id"], (
                "同一物理卷必须只有一个 episode"
            )
            assert all(event.get("volume_key") == volume_key for event in blocked)

            vhd.release()
            result_a = session.wait_for(
                lambda event: event.get("type") == "result"
                and event.get("job_id") == "tw12-a",
                timeout=240.0,
            )
            result_b = session.wait_for(
                lambda event: event.get("type") == "result"
                and event.get("job_id") == "tw12-b",
                timeout=240.0,
            )
            assert result_a is not None and result_a.get("status") == "ok", result_a
            assert result_b is not None and result_b.get("status") == "ok", result_b

            resumed_jobs = {
                event.get("job_id")
                for event in session.space_events()
                if event.get("event") == "space_resumed"
            }
            assert {"tw12-a", "tw12-b"} <= resumed_jobs, (
                "probe owner 也必须在 space_resumed 的扇出对象里（遍历 waiters_ 会漏掉它，"
                "就是 §4.7.1.1 的 Bug B）；实际：" + json.dumps(sorted(resumed_jobs))
            )

        assert (out_a / "payload.bin").read_bytes() == payload_a
        assert (out_b / "payload.bin").read_bytes() == payload_b


@requires_vhd
def test_win24_eof_drain_survives_a_full_disk(tmp_path_factory):
    r"""EOF 排空不得提前终止 controller / space monitor。

    本用例不注入任何 cancel / shutdown：只关 stdin，然后要求
    "满盘 → 释放 → 恢复 → 正常退出"整条链路成立。
    """

    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "eof.zip"
    payload = _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "V",
        payload_bytes=len(payload),
        blocked_free_bytes=1 * _MIB,
    ) as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        vhd.fill_until_free_below(1 * _MIB)

        session = WorkerSession(_worker_path(), _gate_environment())
        session.__enter__()
        try:
            session.send(_job_request("tw24", archive, output_dir))
            # 制造 EOF：此后不再发送任何命令（不 cancel、不 shutdown）。
            session.close_stdin()

            blocked = session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=120.0
            )
            assert blocked is not None, (
                "EOF 排空期间满盘仍必须能进入 Blocked；实际事件流："
                + json.dumps(session.space_events(), ensure_ascii=False)
            )

            vhd.release()
            resumed = session.wait_for(
                lambda event: event.get("event") == "space_resumed", timeout=180.0
            )
            assert resumed is not None, (
                "EOF 之后 controller/monitor 必须仍然活着 —— 否则释放空间也永远不恢复"
                "（这正是『排空不能提前 stopping_』要防的闭环）"
            )

            result = session.wait_for(lambda e: e.get("type") == "result", timeout=240.0)
            assert result is not None and result.get("status") == "ok", result

            # 排空结束后进程必须自己退出（EOF 路径），不能永久挂在 join 上。
            exit_code = session.wait_exit(timeout=60.0)
            assert isinstance(exit_code, int)
        finally:
            session.close()

        extracted = output_dir / "payload.bin"
        assert extracted.exists()
        assert extracted.read_bytes() == payload, "EOF 排空路径的输出必须完整"


@requires_vhd
def test_win15_unqueryable_volume_stays_blocked(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "detach.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(
        vhd_directory,
        "V",
        payload_bytes=8 * _MIB,
        blocked_free_bytes=1 * _MIB,
    ) as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        vhd.fill_until_free_below(1 * _MIB)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw15", archive, output_dir))
            assert session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            ) is not None

            # 拔盘：卷不再可查询，必须保持 Blocked 并带出诊断。
            # 不能先 release()：probe 会成功 → gate 回 Ready → 再也不会有 space_status。
            vhd.detach()
            status = session.wait_for(
                lambda event: event.get("event") == "space_status"
                and event.get("volume_query_ok") is False,
                timeout=90.0,
            )
            assert status is not None, (
                "卷不可查询时必须用 space_status 带出诊断；实际事件流："
                + json.dumps(session.space_events(), ensure_ascii=False)
            )
            assert int(status.get("volume_query_error") or 0) != 0
            # 绝不能变成"已恢复"。
            assert not [
                event
                for event in session.space_events()
                if event.get("event") == "space_resumed"
            ], "不可查询的卷绝不能产生 space_resumed"
            # 也绝不能产生终态结果：空间压力本身不得产生 job 终态。
            assert session.wait_for(lambda e: e.get("type") == "result", timeout=2.0) is None
