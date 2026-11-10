from sunpack_native import flatten_single_branch_directories as _native_flatten_single_branch_directories
from sunpack.core.contracts.results import DirectoryFlattenResult


def flatten_dirs(base: str, *, work_path: str | None = None, before_move=None) -> DirectoryFlattenResult:
    result = (_native_flatten_single_branch_directories(str(base), work_path=work_path, before_move=before_move)
              if work_path is not None else _native_flatten_single_branch_directories(str(base)))
    return DirectoryFlattenResult(
        path=str(base),
        output_dir=str(result["output_dir"]),
        source_dir=str(result["source_dir"]),
        moved=int(result["moved"]),
        removed_dirs=int(result["removed_dirs"]),
        errors=tuple(str(error) for error in result["errors"]),
    )
