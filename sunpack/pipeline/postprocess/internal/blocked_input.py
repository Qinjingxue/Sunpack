from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from sunpack_native import NativeBlockedInputPromotion


@dataclass(frozen=True)
class BlockedInputPromotionResult:
    path_map: dict[str, str]
    removed_dirs: tuple[str, ...] = ()
    touched_dirs: tuple[str, ...] = ()


class BlockedInputPromotionError(OSError):
    def __init__(self, message: str, path_map: dict[str, str], collision: bool):
        super().__init__(message)
        self.path_map = path_map
        self.collision = collision


def promote_blocked_input(
    paths: Iterable[str], destination_dir: str, *, before_move: Callable[[], None] | None = None,
    plan: NativeBlockedInputPromotion | None = None,
) -> BlockedInputPromotionResult:
    if plan is None:
        plan = NativeBlockedInputPromotion(list(paths), destination_dir)
    mapping, removed, touched, error, collision = plan.execute(before_move)
    if error:
        raise BlockedInputPromotionError(error, mapping, collision)
    return BlockedInputPromotionResult(mapping, tuple(removed), tuple(touched))
