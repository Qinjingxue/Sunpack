"""Small, destination-local tree palette shared by scan and extraction."""
import io
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class TreeStyle:
    branch: str
    last_branch: str
    vertical: str
    blank: str
    ellipsis: str

    def edge(self, last: bool) -> str:
        return self.last_branch if last else self.branch

    def continuation(self, last: bool) -> str:
        return self.blank if last else self.vertical


UNICODE_TREE = TreeStyle("├─ ", "└─ ", "│  ", "   ", "…")
ASCII_TREE = TreeStyle("+---", "\\---", "|   ", "    ", "...")


def supports_unicode_tree(stream) -> bool:
    # A persistent stream's UTF-8 wire encoding need not be its client's
    # destination encoding. Forward that capability independently of VT/TTY.
    forwarded = getattr(stream, "supports_unicode_tree", None)
    if forwarded is not None:
        return bool(forwarded)
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        # A plain text sink has no encoding restriction. Honor a subclass
        # advertising an encoding, and be conservative for unknown writers.
        return isinstance(stream, io.StringIO)
    try:
        "├─└│…".encode(encoding, "strict")
    except (LookupError, UnicodeError, TypeError):
        return False
    return True


def tree_style(stream) -> TreeStyle:
    return UNICODE_TREE if supports_unicode_tree(stream) else ASCII_TREE
