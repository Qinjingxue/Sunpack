"""Current worker wire data shared by parser-focused fixtures."""


def worker_result(*, manifest_rows=None, trace_items=None, **fields):
    """Build a fixture result through the binary parser and job accumulator."""
    from sunpack_native import NativeWorkerResultAccumulator, encode_worker_frame, parse_worker_event

    job_id = "fixture"
    accumulator = NativeWorkerResultAccumulator(job_id)

    def accept(kind, **payload):
        event = parse_worker_event(encode_worker_frame({"type": kind, "job_id": job_id, **payload}))
        accumulator.accept(event)
        return event

    if manifest_rows is not None:
        if manifest_rows:
            accept("manifest_chunk", seq=0, rows=manifest_rows)
        fields["verified_manifest"] = {
            **fields["verified_manifest"],
            "chunk_count": int(bool(manifest_rows)),
            "file_count": len(manifest_rows),
        }
    if trace_items is not None:
        if trace_items:
            accept("trace_chunk", seq=0, items=trace_items)
        diagnostics = fields.get("diagnostics", {})
        fields["diagnostics"] = {
            **diagnostics,
            "output_trace": {
                **diagnostics.get("output_trace", {}),
                "chunk_count": int(bool(trace_items)),
                "item_count": len(trace_items),
            },
        }
    return accept("result", **fields)


def worker_trace_item(**overrides):
    item = {
        "index": 0,
        "path": "",
        "output_path": "",
        "is_dir": False,
        "encrypted": False,
        "bytes_written": 0,
        "expected_size": 0,
        "has_expected_size": False,
        "source_crc32": 0,
        "has_source_crc32": False,
        "output_crc32": 0,
        "has_output_crc32": False,
        "crc_verified": False,
        "operation_result": 0,
        "operation_result_name": "",
        "hresult": 0,
        "win32_error": 0,
        "done": True,
        "failed": False,
    }
    item.update(overrides)
    if "expected_size" in overrides and "has_expected_size" not in overrides:
        item["has_expected_size"] = True
    return item


def worker_events(data):
    from sunpack_native import NativeWorkerFrameDecoder
    decoder = NativeWorkerFrameDecoder()
    events = decoder.feed(data)
    decoder.finish()
    return events


def read_worker_events(stream):
    from sunpack_native import NativeWorkerFrameDecoder
    decoder = NativeWorkerFrameDecoder()
    while block := stream.read1(65536):
        yield from decoder.feed(block)
        decoder.check()
    decoder.finish()


def launch_python_worker(monkeypatch, path):
    """Launch this test peer directly so terminate() also closes its pipes."""
    import asyncio
    import os
    import sys

    create_subprocess_exec = asyncio.create_subprocess_exec

    async def launch(program, *args, **kwargs):
        if str(program) == str(path):
            # A .cmd wrapper leaves Python alive with inherited stdio handles
            # when the runner terminates the wrapper on Windows.
            executable = sys.executable
            if sys.platform == "win32" and os.path.normcase(executable) != os.path.normcase(sys._base_executable):
                # Mirror multiprocessing.popen_spawn_win32: bypass the venv
                # redirector too, while retaining its site-packages.
                executable = sys._base_executable
                environment = kwargs.get("env")
                kwargs["env"] = dict(os.environ if environment is None else environment)
                kwargs["env"]["__PYVENV_LAUNCHER__"] = sys.executable
            return await create_subprocess_exec(executable, str(path), *args, **kwargs)
        return await create_subprocess_exec(program, *args, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", launch)
    return path


def write_worker_script(path, steps, monkeypatch):
    """A real pipe peer controlled by request frames, without timing sleeps."""
    from sunpack_native import encode_worker_frame
    actions = [encode_worker_frame(step) if isinstance(step, dict) else step for step in steps]
    path.write_text(
        "import sys, struct\n"
        "def exact(size):\n"
        "    data = bytearray()\n"
        "    while len(data) < size:\n"
        "        block = sys.stdin.buffer.read(size-len(data))\n"
        "        if not block: sys.exit(0)\n"
        "        data.extend(block)\n"
        "    return data\n"
        f"for step in {actions!r}:\n"
        "    if step is None:\n"
        "        header = exact(8)\n"
        "        assert header[:4] == b'SPBF'\n"
        "        exact(struct.unpack('<I', header[4:])[0])\n"
        "    elif isinstance(step, int): sys.exit(step)\n"
        "    else:\n"
        "        sys.stdout.buffer.write(step)\n"
        "        sys.stdout.buffer.flush()\n", encoding="utf-8")
    return launch_python_worker(monkeypatch, path)


def worker_frames(data):
    offset = 0
    while offset < len(data):
        assert data[offset:offset+4] == b"SPBF" and len(data)-offset >= 8
        size = int.from_bytes(data[offset+4:offset+8], "little") + 8
        assert size <= len(data)-offset
        yield data[offset:offset+size]
        offset += size
