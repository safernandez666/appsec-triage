"""Minimal `.env` loader — no new runtime dependencies.

Loads `KEY=VALUE` pairs from a `.env` file at CLI start. Existing
environment variables ALWAYS win — the file is a default, not an
override. Same precedence model python-dotenv uses by default, and
the property that lets a user say `GITHUB_TOKEN=other appsec-triage …`
for a one-off run without editing the file.

Loud-on-load behavior:
- Missing file → silent (return 0). Many users export tokens from the
  shell and never write a `.env`; that workflow must stay frictionless.
- Malformed line → skipped silently. The file is operator-edited and
  often hand-copied; a stray blank or comment must not crash the bot.
"""
from __future__ import annotations

import os
from pathlib import Path


def _strip_inline_comment(value: str) -> str:
    """Drop ` # comment` tail from unquoted values."""
    # Only strip when there is whitespace before the `#`, so that
    # `KEY=https://host/#anchor` and tokens with literal `#` survive.
    idx = value.find(" #")
    if idx >= 0:
        return value[:idx]
    idx = value.find("\t#")
    if idx >= 0:
        return value[:idx]
    return value


def _parse_value(raw: str) -> str:
    v = raw.strip()
    # Strip matching surrounding quotes; keep contents verbatim.
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        return v[1:-1]
    return _strip_inline_comment(v).rstrip()


def load_dotenv(path: str | os.PathLike[str] = ".env") -> int:
    """Load `path` into os.environ. Returns the number of keys loaded.

    Returns 0 if the file does not exist. Never overwrites a variable
    already present in `os.environ` — explicit shell exports win over
    file defaults, which is the convention every tooling user expects.
    """
    p = Path(path)
    if not p.is_file():
        return 0
    loaded = 0
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Tolerate `export KEY=value` lines copied from shell snippets.
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        if key in os.environ:
            continue
        os.environ[key] = _parse_value(value)
        loaded += 1
    return loaded
