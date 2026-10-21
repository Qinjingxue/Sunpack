import json
from sunpack.core.passwords.internal.builtin import read_builtin_password_file


def write_password_json(path, values=(), *, scopes=(), history=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"passwords": [
        *({"value": value} for value in values),
        *({"value": value, "scopes": list(directories)} for value, directories in scopes),
    ], "clipboard_history": list(history)}, ensure_ascii=False), encoding="utf-8")
    return read_builtin_password_file(path)
