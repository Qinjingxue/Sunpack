COMMAND_ALIASES = {
    "extract": ("x",),
    "scan": ("s",),
    "inspect": ("i",),
    "passwords": ("pw",),
    "watch": ("w",),
    "config": ("cfg",),
    "version": ("ver",),
}

_CANONICAL_COMMANDS = {
    alias: command
    for command, aliases in COMMAND_ALIASES.items()
    for alias in aliases
}


def canonical_command(command: str | None) -> str | None:
    return _CANONICAL_COMMANDS.get(command, command)
