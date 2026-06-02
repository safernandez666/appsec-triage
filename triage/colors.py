"""Minimal ANSI color helper for CLI pipeline output.

Complements `triage/banner.py` (truecolor gradient, one-shot) by emitting
short 256-color sequences inline on per-line zone prefixes, verdicts, and
action keywords. Stays stdlib-only.

Auto-disabled when stdout is not a TTY (cron, pipes, CI). Honors
`NO_COLOR` (standard) and `APPSEC_NO_COLOR` (project-specific) so users
who want the banner gradient but plain pipeline output can opt out of
just the inline colors.

Call sites read by role, not by hue — `z1(text)`, `verdict("reproducible", …)`,
`severity("high")` — so renaming the palette later does not touch cli.py.
"""
from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# 256-color palette. Names map to the role in the pipeline, not the hue,
# so the call sites stay readable when the palette is tuned.
_Z1 = "\033[38;5;81m"          # cyan
_Z2 = "\033[38;5;215m"         # warm amber
_Z3 = "\033[38;5;177m"         # violet
_Z4 = "\033[38;5;213m"         # pink-magenta
_FP = "\033[38;5;77m"          # green
_REPRO = "\033[38;5;203m"      # red
_NR = "\033[38;5;215m"         # orange
_ROTATE = "\033[38;5;199m"     # bright pink
_OK = "\033[38;5;77m"          # green
_BAD = "\033[38;5;203m"        # red
_GRAY = "\033[38;5;245m"       # gray
_HEADER = "\033[38;5;231m"     # bright white
_SEV_HIGH = "\033[38;5;203m"   # red
_SEV_MEDIUM = "\033[38;5;214m" # amber
_SEV_LOW = "\033[38;5;77m"     # green

_ENABLED: bool | None = None


def _detect() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("APPSEC_NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def enabled() -> bool:
    """Memoized: once detected, the decision stays for the process."""
    global _ENABLED
    if _ENABLED is None:
        _ENABLED = _detect()
    return _ENABLED


def reset_for_tests() -> None:
    """Force re-detection (used by unit tests, never by the CLI)."""
    global _ENABLED
    _ENABLED = None


def _wrap(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if enabled() else text


def z1(text: str) -> str:
    return _wrap(text, _Z1)


def z2(text: str) -> str:
    return _wrap(text, _Z2)


def z3(text: str) -> str:
    return _wrap(text, _Z3)


def z4(text: str) -> str:
    return _wrap(text, _Z4)


def ok(text: str) -> str:
    """Green — used for FORCED, OK, PASS-THROUGH outcomes."""
    return _wrap(text, _OK)


def bad(text: str) -> str:
    """Red — used for CONTRADICTION, DEGRADE, FAIL outcomes."""
    return _wrap(text, _BAD)


def dim(text: str) -> str:
    """Gray — noise to fade out (SKIP, repeated state, prior=X already)."""
    return _wrap(text, _GRAY)


def bold(text: str) -> str:
    return _wrap(text, BOLD)


def header(text: str) -> str:
    """Bold bright white — used to anchor each alert visually."""
    return _wrap(text, BOLD + _HEADER)


def verdict(kind_value: str, text: str | None = None, *, strong: bool = True) -> str:
    """Color `text` (or the kind name) by verdict.

    `strong=True` adds bold; the Final Judge line uses strong, action
    summary uses weak so the counts stay readable.
    """
    label = text if text is not None else kind_value
    code = {
        "false_positive": _FP,
        "reproducible": _REPRO,
        "needs_review": _NR,
        "rotate_now": _ROTATE,
    }.get(kind_value, _GRAY)
    if strong:
        code = BOLD + code
    return _wrap(label, code)


def severity(sev: str) -> str:
    """Color a `severity=<x>` token."""
    sev_norm = (sev or "").lower()
    code = {
        "critical": BOLD + _SEV_HIGH,
        "high": _SEV_HIGH,
        "medium": _SEV_MEDIUM,
        "low": _SEV_LOW,
    }.get(sev_norm, _GRAY)
    return _wrap(f"severity={sev}", code)


def action(kind: str) -> str:
    """Color an action keyword (CREATE / SKIP / CLOSE / DISMISS).

    Lowercase or uppercase input both accepted. Returns the colored
    UPPERCASE token so log lines stay uniform.
    """
    norm = (kind or "").lower()
    upper = kind.upper() if kind else ""
    if norm == "create":
        return _wrap(upper, BOLD + _Z4)
    if norm == "dismiss":
        return _wrap(upper, BOLD + _NR)
    if norm == "close":
        return _wrap(upper, _GRAY)
    if norm == "skip":
        return _wrap(upper, _GRAY)
    return upper
