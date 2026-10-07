"""Current worker wire data shared by parser-focused fixtures."""


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
        "hresult_hex": "",
        "win32_error": 0,
        "done": True,
        "failed": False,
    }
    item.update(overrides)
    if "expected_size" in overrides and "has_expected_size" not in overrides:
        item["has_expected_size"] = True
    return item
