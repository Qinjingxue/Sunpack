"""Physical fixtures only; native state APIs verify decoded behavior."""
import struct
import zlib


def header(kind=1):
    return struct.pack('<4sHHQ', b'SPWL', 1, kind, 0)


def frame(seq, payload):
    fields = struct.pack('<IQ', len(payload), seq)
    return fields + struct.pack('<I', zlib.crc32(fields + payload)) + payload


def frames(path):
    raw = path.read_bytes()
    assert raw[:16] in (header(1), header(2))
    records = []
    offset = 16
    while offset < len(raw):
        size, seq, crc = struct.unpack_from('<IQI', raw, offset)
        end = offset + 16 + size
        payload = raw[offset + 16:end]
        assert len(payload) == size
        assert zlib.crc32(raw[offset:offset + 12] + payload) == crc
        records.append((seq, payload, raw[offset:end]))
        offset = end
    return records
