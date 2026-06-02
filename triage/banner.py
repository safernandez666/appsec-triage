"""Startup banner with a violet → orange truecolor gradient.

Printed to stderr at CLI start so it never pollutes stdout. Auto-disabled
when stderr is not a TTY (cron logs, pipes, CI runners) and via NO_COLOR
or APPSEC_NO_BANNER for users who want it silent.
"""
from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError, version as _pkg_version

# ANSI Shadow rendering of "APPSEC". Six rows × 48 columns.
# Trailing spaces are load-bearing — they keep the gradient aligned per column.
_BANNER_LINES: tuple[str, ...] = (
    " █████╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗",
    "██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝",
    "███████║██████╔╝██████╔╝███████╗█████╗  ██║     ",
    "██╔══██║██╔═══╝ ██╔═══╝ ╚════██║██╔══╝  ██║     ",
    "██║  ██║██║     ██║     ███████║███████╗╚██████╗",
    "╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚══════╝ ╚═════╝",
)

_SUBTITLE = "defensive triage · the LLM never acts alone"

# Tailwind violet-500 → orange-400. Chosen for visible contrast on both
# light and dark terminal themes.
_START_RGB: tuple[int, int, int] = (139, 92, 246)
_END_RGB: tuple[int, int, int] = (251, 146, 60)


def _is_enabled() -> bool:
    """Banner is interactive UX only — skip in non-TTY contexts.

    Order matters: APPSEC_NO_BANNER and NO_COLOR are explicit opt-outs and
    should win over isatty checks. Only fall back to TTY detection when
    nothing was opted out, to avoid surprising users who set NO_COLOR but
    still pipe interactively.
    """
    if os.environ.get("APPSEC_NO_BANNER"):
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stderr.isatty()


def _lerp_rgb(t: float) -> tuple[int, int, int]:
    r = int(round(_START_RGB[0] + (_END_RGB[0] - _START_RGB[0]) * t))
    g = int(round(_START_RGB[1] + (_END_RGB[1] - _START_RGB[1]) * t))
    b = int(round(_START_RGB[2] + (_END_RGB[2] - _START_RGB[2]) * t))
    return r, g, b


def _colorize_line(line: str, width: int) -> str:
    """Emit one SGR per column transition. Spaces stay uncolored."""
    parts: list[str] = []
    last_rgb: tuple[int, int, int] | None = None
    for col, ch in enumerate(line):
        if ch == " ":
            parts.append(ch)
            continue
        t = col / max(width - 1, 1)
        rgb = _lerp_rgb(t)
        if rgb != last_rgb:
            parts.append(f"\033[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m")
            last_rgb = rgb
        parts.append(ch)
    parts.append("\033[0m")
    return "".join(parts)


def _resolve_version() -> str:
    try:
        return _pkg_version("appsec-triage")
    except PackageNotFoundError:
        # Editable install before metadata is wired, or running from source
        # without pip install. The banner is cosmetic — don't crash here.
        return "dev"


def print_banner() -> None:
    """Print the AppSec banner to stderr. No-op when disabled."""
    if not _is_enabled():
        return
    width = max(len(ln) for ln in _BANNER_LINES)
    for line in _BANNER_LINES:
        print(_colorize_line(line, width), file=sys.stderr)
    mid_r, mid_g, mid_b = _lerp_rgb(0.5)
    tag = f"  {_SUBTITLE} · v{_resolve_version()}"
    print(f"\033[38;2;{mid_r};{mid_g};{mid_b}m{tag}\033[0m", file=sys.stderr)
    print(file=sys.stderr)
