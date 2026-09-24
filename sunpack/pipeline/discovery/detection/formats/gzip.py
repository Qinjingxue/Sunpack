from sunpack.pipeline.discovery.detection.formats._stream import confirm_stream


FORMAT = "gzip"


def confirm(path: str, analyzer) -> bool:
    return confirm_stream(path, analyzer, FORMAT)
