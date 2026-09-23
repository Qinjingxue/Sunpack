import hashlib
from typing import Any


def hash_unit(value: Any, *, buckets: int = 2048) -> float:
    text = str(value or "")
    if not text:
        return 0.0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return (int(digest[:8], 16) % buckets) / float(buckets - 1)
