from sunpack.detection.formats._stream import confirmed_stream


FORMAT = "zstd"


def confirm(path: str, analyzer) -> bool:
    return confirmed_stream(analyzer.probe_compression_stream(path).to_raw_dict(), FORMAT)
