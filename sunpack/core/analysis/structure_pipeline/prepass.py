from sunpack.core.analysis.view import SharedBinaryView


DEFAULT_HEAD_BYTES = 1024 * 1024
DEFAULT_TAIL_BYTES = 1024 * 1024


def run_signature_prepass(view: SharedBinaryView, config: dict | None = None) -> dict:
    config = config or {}
    head_size = int(config.get("head_bytes", DEFAULT_HEAD_BYTES) or DEFAULT_HEAD_BYTES)
    tail_size = int(config.get("tail_bytes", DEFAULT_TAIL_BYTES) or DEFAULT_TAIL_BYTES)
    return view.signature_prepass(head_bytes=head_size, tail_bytes=tail_size)
