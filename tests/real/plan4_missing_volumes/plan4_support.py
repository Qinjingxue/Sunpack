"""Remove the selected real volume while keeping a separate SFX launcher."""

SCENARIOS = ("missing_head", "missing_tail", "missing_middle", "only_middle", "only_head", "only_tail")
MAY_LACK_RECOGNIZABLE_HEAD = {"missing_head", "only_middle", "only_tail"}


def apply_missing_volume_scenario(case, scenario):
    parts = case.metadata.get("volume_paths") or sorted(
        path for path in case.archive_dir.iterdir() if path.is_file()
    )
    entry = case.entry_path.resolve()
    separate_launcher = entry.suffix.lower() == ".exe" and any(path.suffix == ".001" for path in parts)
    volumes = [path for path in parts if not separate_launcher or path.resolve() != entry]
    assert len(volumes) >= 3, volumes
    selected = {"head": volumes[0], "tail": volumes[-1], "middle": volumes[len(volumes) // 2]}
    mode, position = scenario.split("_", 1)
    target = selected[position]
    removed = [target] if mode == "missing" else [path for path in volumes if path != target]
    for path in removed:
        path.unlink()
