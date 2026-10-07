from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from sunpack_native import promote_blocked_input_files


@dataclass(frozen=True)
class BlockedInputPromotionResult:
    path_map: dict[str, str]
    removed_dirs: tuple[str, ...] = ()
    touched_dirs: tuple[str, ...] = ()


class BlockedInputPromotionError(OSError):
    def __init__(self, message: str, path_map: dict[str, str]):
        super().__init__(message)
        self.path_map = path_map


def promote_blocked_input(paths: Iterable[str], destination_dir: str) -> BlockedInputPromotionResult:
    mapping, removed, touched, error = promote_blocked_input_files(list(paths), destination_dir)
    if error:
        raise BlockedInputPromotionError(error, mapping)
    return BlockedInputPromotionResult(mapping, tuple(removed), tuple(touched))
