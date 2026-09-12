"""L4：真实满盘端到端（VHD）。

对应《SunPack Worker 磁盘空间不足自动暂停与恢复实现文档.md》§10.4 的 T-WIN-*。

**门控**：默认 `pytest.skip`；仅当 `SUNPACK_SPACE_TEST_VHD=1` **且**进程具备管理员
权限时执行（`diskpart` 需要提权）。这与文档 §10.4 的门控一字不差。

**为什么用 VHD 而不是写满测试盘**：写满开发机磁盘会破坏环境；VHD 可精确控制容量
（本文件默认 2 GiB 固定盘），可随时 attach / detach / 删除。

**为什么这些用例不能被 L1/L2 取代**：L1/L2 用注入式失败替换"真实系统调用"这一步，
因此它们证明不了：

  * 真实的 `ERROR_DISK_FULL` 是否真的从 `WriteFile` / `create_directories` 里出来；
  * 真实满盘时 SDK 是否真的被 producer 反压挡住（R13 的未验证假设）；
  * 满盘期间 `shutdown` / `cancel` 是否真的能穿透 native 侧的 gate（T-WIN-11/20）；
  * 释放空间后同 handle 续写是否真的成功（T-WIN-2 / T-WIN-23）。

每个用例都会**自己创建并销毁** VHD：它们不依赖任何预置盘符或残留文件。
"""

from __future__ import annotations

import ctypes
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "win32", reason="VHD / diskpart 是 Windows-only"
)

_VHD_ENABLED = os.environ.get("SUNPACK_SPACE_TEST_VHD") == "1"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - 非 Windows
        return False


requires_vhd = pytest.mark.skipif(
    not (_VHD_ENABLED and _is_admin()),
    reason="需要 SUNPACK_SPACE_TEST_VHD=1 且管理员权限（diskpart 提权）",
)

_MIB = 1 << 20


# ---------------------------------------------------------------------------
# diskpart 驱动的 VHD 生命周期
# ---------------------------------------------------------------------------
class SpaceVhd:
    """一个固定容量的 NTFS 测试盘。

    用完必须 `close()`：卸载并删除 VHDX 文件。所有用例都用 try/finally 保证这一点，
    否则满盘残留会污染后续（以及别处的）测试。
    """

    def __init__(self, directory: Path, letter: str, size_mb: int = 1024):
        self.path = directory / f"space-{letter.lower()}-{uuid.uuid4().hex[:8]}.vhdx"
        self.letter = letter
        self.size_mb = size_mb
        self._attached = False
        self._filler: Path | None = None

    # ---- diskpart 原语 -------------------------------------------------
    @staticmethod
    def _diskpart(script: str) -> None:
        completed = subprocess.run(
            ["diskpart"],
            input=script,
            capture_output=True,
            text=True,
            timeout=300,
        )
        # diskpart 在部分失败时仍返回 0，因此必须检查输出。
        combined = f"{completed.stdout}\n{completed.stderr}"
        if "Virtual Disk Service error" in combined or "错误" in combined and "DiskPart" not in combined:
            raise RuntimeError(f"diskpart failed:\n{combined}")
        if completed.returncode != 0:
            raise RuntimeError(f"diskpart exit {completed.returncode}:\n{combined}")

    def attach(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.unlink()
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

    def detach(self) -> None:
        if not self._attached:
            return
        self._diskpart(
            "\n".join([f"select vdisk file={self.path}", "detach vdisk", "exit"])
        )
        self._attached = False

    def close(self) -> None:
        try:
            self.release()
            self.detach()
        finally:
            for _ in range(20):
                try:
                    if self.path.exists():
                        self.path.unlink()
                    break
                except OSError:
                    time.sleep(0.25)

    # ---- 空间控制 ------------------------------------------------------
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


# ---------------------------------------------------------------------------
# native worker 会话（直接驱动协议，不经 SevenZipRunner）
# ---------------------------------------------------------------------------
class WorkerSession:
    """按行 JSON 协议驱动 sunpack_sevenzip_worker.exe。

    SevenZipRunner 会在自己的看门狗里取消 job，而这里要测的恰恰是 native 侧的行为，
    因此本文件直接说协议：写请求、读事件、按需 cancel / shutdown。
    """

    def __init__(self, worker_path: Path, extra_environment: dict[str, str] | None = None):
        self.worker_path = str(worker_path)
        self.extra_environment = dict(extra_environment or {})
        self.process: subprocess.Popen | None = None
        # ⚠️ **累积**列表，不是消费式队列：早先的 `space_events()` 会 drain 掉队列，
        #    把同时到达的 result 事件永久丢掉，于是后面的 wait_for(result) 永远等不到。
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

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._all)

    def wait_for(self, predicate, timeout: float = 300.0) -> dict | None:
        """等待**第一个**满足条件的事件（非破坏性：可以反复调用）。"""

        deadline = time.monotonic() + timeout
        while True:
            for event in self.snapshot():
                if predicate(event):
                    return event
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


# ---------------------------------------------------------------------------
# 测试工件
# ---------------------------------------------------------------------------
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
    """写一个 **stored（不压缩）** 的 zip，返回原始内容以便逐字节比对。"""

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
    r"""解析输出目录所在的**真实**物理卷身份键（\\?\Volume{GUID} 小写无尾反斜杠）。

    解析失败时返回空串 —— 此时 native 侧退化成 synthetic `job:<id>` 键，仍然安全，
    只是跨 job 去重失效（§4.3.4）。多卷用例必须拿到真实键，否则测不到"同一物理卷 =
    同一 gate"这条性质。
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

    默认显式注入 `SUNPACK_VOLUME_SPACE_GATE=1`：L4 必须在"功能被明确开启"这一前提下
    验证行为，否则一旦默认值被改回 false，本文件会静默地测了个寂寞。

    设 `SUNPACK_SPACE_TEST_USE_NATIVE_DEFAULT=1` 时**不注入任何开关** —— 这条路专门
    用来验证 Phase 6c 之后的"默认开启"本身真的生效（端到端，而不是只读配置）。
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
    指向一个空间充裕的盘 —— 每个用例会写入整个 VHD 容量（固定盘），
    把几 GiB 写到系统盘并不合适。
    """

    configured = os.environ.get("SUNPACK_SPACE_TEST_VHD_DIR")
    if configured:
        directory = Path(configured)
        directory.mkdir(parents=True, exist_ok=True)
        return directory
    return Path(tmp_path_factory.mktemp("space-vhd"))


# ---------------------------------------------------------------------------
# T-WIN-17 根输出目录满盘（P0 验收）
# ---------------------------------------------------------------------------
@requires_vhd
def test_win17_root_output_directory_on_full_volume(tmp_path_factory):
    """输出目录**尚不存在**且所在盘已满时，必须出现 space_blocked 而不是直接失败。

    这是 §3.11 那个 P0 的验收：根输出目录创建发生在 ExtractToDiskCallback 构造之前，
    早期实现会在这里直接以 output_prepare / output_filesystem 返回。
    """

    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "big.zip"
    payload = _make_archive(archive, 8 * _MIB)

    with SpaceVhd(vhd_directory, "V") as vhd:
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
            # ★ P0 的核心断言：绝不能是 output_prepare / output_filesystem 直接失败。
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


# ---------------------------------------------------------------------------
# T-WIN-2 / T-WIN-23 单个 writer 写满 → 释放 → 恢复，数据完整
# ---------------------------------------------------------------------------
@requires_vhd
def test_win2_single_writer_full_then_release(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "resume.zip"
    payload = _make_archive(archive, 8 * _MIB)

    with SpaceVhd(vhd_directory, "W") as vhd:
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

            # 暂停期间不得有终态结果（B1 契约）。
            assert session.wait_for(lambda e: e.get("type") == "result", timeout=1.0) is None

            vhd.release()
            assert session.wait_for(
                lambda event: event.get("event") == "space_resumed", timeout=120.0
            ) is not None
            result = session.wait_for(lambda e: e.get("type") == "result", timeout=180.0)
            assert result is not None and result.get("status") == "ok", result

        extracted = output_dir / "payload.bin"
        assert extracted.read_bytes() == payload


# ---------------------------------------------------------------------------
# T-WIN-13 取消最后一个 waiter 不得变成"已恢复"
# ---------------------------------------------------------------------------
@requires_vhd
def test_win13_cancelling_last_waiter_is_not_resume(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "cancel.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(vhd_directory, "X") as vhd:
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

            # ★ 铁律一：取消绝不等于"卷已恢复"。
            session.send({"worker_command": "shutdown"})
            assert session.wait_exit(timeout=30.0) is not None
            assert not [
                event
                for event in session.space_events()
                if event.get("event") == "space_resumed"
            ], "取消最后一个 waiter 绝不能产生 space_resumed"


# ---------------------------------------------------------------------------
# T-WIN-20 满盘暂停期间 shutdown 必须真的能穿透 gate
# ---------------------------------------------------------------------------
@requires_vhd
def test_win20_shutdown_pierces_a_paused_gate(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "shutdown.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(vhd_directory, "Y") as vhd:
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

            # ⚠️ 这里**不**事先显式取消任何 job：专测"只 wake 不改 terminal 条件"
            #    那个回归（文档 §4.5.6.1）。
            started = time.monotonic()
            session.send({"worker_command": "shutdown"})
            session.wait_exit(timeout=15.0)
            elapsed = time.monotonic() - started
            assert elapsed < 10.0, f"暂停期间 shutdown 用了 {elapsed:.1f}s（预期 1s 量级）"
        finally:
            session.close()


# ---------------------------------------------------------------------------
# T-WIN-21 双卷独立（sticky hint 的端到端回归）
# ---------------------------------------------------------------------------
@requires_vhd
def test_win21_two_volumes_recover_independently(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive_a = work / "a.zip"
    archive_b = work / "b.zip"
    payload_a = _make_archive(archive_a, 4 * _MIB)
    payload_b = _make_archive(archive_b, 4 * _MIB)

    with SpaceVhd(vhd_directory, "V") as vhd_a, SpaceVhd(vhd_directory, "W") as vhd_b:
        out_a = vhd_a.root / "out"
        out_b = vhd_b.root / "out"
        out_a.mkdir()
        out_b.mkdir()
        vhd_a.fill_until_free_below(512 * 1024)
        vhd_b.fill_until_free_below(512 * 1024)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            # 用**真实**卷身份键：两个 job 各自命中一个物理卷的 gate，
            # 这样才真的在测"两个物理卷 + sticky hint"。
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

            # ★ 关键：A 恢复**之后**再释放 B，B 也必须能恢复
            #   （旧的精确 bool has_blocked_ 会在这里永久卡住 B）。
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
            assert result_a is not None and result_a.get("status") == "ok", result_a
            assert result_b is not None and result_b.get("status") == "ok", (
                result_b,
                json.dumps(session.space_events(), ensure_ascii=False),
            )

        assert (out_a / "payload.bin").read_bytes() == payload_a
        assert (out_b / "payload.bin").read_bytes() == payload_b


# ---------------------------------------------------------------------------
# T-WIN-12 两个 job 阻塞在同一卷：各自收到 space_blocked（同一 episode_id）与 resumed
# ---------------------------------------------------------------------------
@requires_vhd
def test_win12_two_jobs_on_one_volume_both_notified(tmp_path_factory):
    """`affected_jobs_` 扇出的端到端验收（§4.7.1.1 的两个 bug）。

    * 两个 job 命中**同一个物理卷** → 同一个 gate → **一个 episode**；
    * 每个 job 各收到一条 space_blocked（不是"只有 probe owner 收到"）；
    * 恢复时每个 job 各收到一条 space_resumed（probe owner 也必须在其中 ——
      它抢到许可后已经从 waiters_ 里移除，遍历 waiters_ 会漏掉它）。
    """

    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive_a = work / "tw12-a.zip"
    archive_b = work / "tw12-b.zip"
    payload_a = _make_archive(archive_a, 4 * _MIB)
    payload_b = _make_archive(archive_b, 4 * _MIB)

    with SpaceVhd(vhd_directory, "V") as vhd:
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


# ---------------------------------------------------------------------------
# T-WIN-15 卷不可查询：保持 Blocked，并把诊断带出去
# ---------------------------------------------------------------------------
@requires_vhd
def test_win15_unqueryable_volume_stays_blocked(tmp_path_factory):
    vhd_directory = _vhd_directory(tmp_path_factory)
    work = Path(tmp_path_factory.mktemp("space-work"))
    archive = work / "detach.zip"
    _make_archive(archive, 8 * _MIB)

    with SpaceVhd(vhd_directory, "V") as vhd:
        output_dir = vhd.root / "out"
        output_dir.mkdir()
        vhd.fill_until_free_below(1 * _MIB)

        with WorkerSession(_worker_path(), _gate_environment()) as session:
            session.send(_job_request("tw15", archive, output_dir))
            assert session.wait_for(
                lambda event: event.get("event") == "space_blocked", timeout=90.0
            ) is not None

            # 拔盘：卷不再可查询。B5：保持 Blocked，只带诊断出去。
            # ⚠️ **不要**先 release()：那会把空间还给卷，probe 会成功 → gate 回 Ready →
            #    该卷从 blocked_volumes() 消失 → 再也不会有 space_status。
            #    本用例要测的正是"卷仍然不可写且不可查询"。
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
            # ★ 绝不能变成"已恢复"。
            assert not [
                event
                for event in session.space_events()
                if event.get("event") == "space_resumed"
            ], "不可查询的卷绝不能产生 space_resumed"
            # 也绝不能产生终态结果（B1：空间压力本身不得产生 job 终态）。
            assert session.wait_for(lambda e: e.get("type") == "result", timeout=2.0) is None
