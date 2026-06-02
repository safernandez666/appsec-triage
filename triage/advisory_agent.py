"""Zone 2 — Advisory Agent. LLM-light, extraction ONLY.

Pulls the dotted names of specific vulnerable APIs out of a Dependabot
advisory's free-text. Names only — no judgment about whether they are present
in the repo (that is the Evidence Agent's job), no opinion about severity, no
recommendation.

Contract:
- Returns an `AdvisoryResult(apis, available, note)`. `apis` is a tuple of
  dotted symbol names; `available` says whether the LLM was actually reached;
  `note` is a one-line log message.
- Without LLM_API_KEY in env: returns `apis=()` and `available=False`. The
  pipeline keeps working — without an Advisory the Truth Table loses Rule B
  for this alert, that is all. No silent failure: the CLI prints the note.
- `temperature=0` and strict JSON response format are enforced upstream in
  `triage.llm`. We still validate defensively — anything that does not look
  like a dotted symbol is dropped before returning.
"""
from __future__ import annotations

import json
import re
from typing import NamedTuple

from triage.llm import LLMNotConfigured, chat
from triage.types import Alert

SYSTEM_PROMPT = """You are an extraction tool. Given the text of a security advisory \
for a package, extract the names of specific functions, methods, classes, or top-level \
helpers in that package that the advisory says are vulnerable. Output strict JSON: \
{"apis": [<dotted name strings>]}.

Rules:
- Names must be dotted symbol paths as they appear in source code,
  e.g. "requests.Session", "requests.get", "yaml.load", "ssl.wrap_socket".
- The package name itself alone (e.g. just "requests") does NOT count.
- If the advisory describes a config setting or behavior but names no specific
  API, return {"apis": []}.
- Never invent. Only names that the advisory text actually mentions.
- No prose. JSON only."""

# Dotted symbol shape: identifier (.identifier)+. No whitespace, no parens, no args.
_SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$")


class AdvisoryResult(NamedTuple):
    apis: tuple[str, ...]
    available: bool   # True iff the LLM was actually called and returned
    note: str         # one-line summary for logs / Issue body


def extract_vulnerable_apis(alert: Alert) -> AdvisoryResult:
    try:
        raw_content = chat(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_payload(alert)},
            ],
            response_format={"type": "json_object"},
        )
    except LLMNotConfigured:
        return AdvisoryResult(
            apis=(),
            available=False,
            note="LLM not configured; advisory APIs unknown (Rule B disabled for this alert)",
        )
    except Exception as e:
        return AdvisoryResult(
            apis=(),
            available=False,
            note=f"LLM call failed ({type(e).__name__}); advisory APIs unknown",
        )

    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError:
        return AdvisoryResult(
            apis=(),
            available=True,
            note="LLM returned non-JSON; treating as no APIs",
        )

    raw = payload.get("apis") if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return AdvisoryResult(
            apis=(),
            available=True,
            note="LLM JSON missing or malformed 'apis' field",
        )

    apis = _validate_and_dedupe(raw)
    return AdvisoryResult(apis=apis, available=True, note=f"extracted {len(apis)} API(s)")


def _validate_and_dedupe(raw: list[object]) -> tuple[str, ...]:
    """Drop anything that is not a dotted symbol; preserve first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not _SYMBOL.match(s):
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def _user_payload(alert: Alert) -> str:
    return (
        f"Package: {alert.package_name} ({alert.package_ecosystem})\n"
        f"Advisory ID: {alert.ghsa_id} / {alert.cve_id or 'no CVE'}\n"
        f"Summary: {alert.summary}\n"
        f"Description:\n{alert.description}\n"
    )
