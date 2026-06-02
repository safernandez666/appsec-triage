"""Per-repo configuration loader (stdlib TOML).

Reads `.appsec-triage.toml` from the current working directory at CLI
start. The single surface today is **tier overrides per repo** — a
declaration of what risk class each repo belongs to. The Truth Table
otherwise infers tier from a heuristic (archived → ARCHIVED, deploy
artifacts → DEPLOYED, else INTERNAL); a config lets operators state
intent explicitly instead of relying on the heuristic, which matters
for repos like a Bootstrap-themed control surface where the static
file structure does not reflect the actual blast radius.

Format (intentionally tiny):

    [repos]
    "org/payments-api" = { tier = "critical" }
    "org/internal-tool" = { tier = "internal" }
    "org/legacy-backup"  = { tier = "archived" }

Missing file is silent — every operator path stays default. Malformed
file logs a warning and falls back to the heuristic, never crashes.
This is a defense-in-depth amenity, not a correctness boundary.

TOML over YAML because `tomllib` is stdlib (3.11+) — the project still
ships with `httpx` as the only runtime dependency.
"""
from __future__ import annotations

import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from triage.types import Tier


@dataclass(frozen=True)
class TierConfig:
    """Resolved tier configuration. Empty when the file is absent."""
    by_repo: dict[str, Tier]

    def lookup(self, repo_full_name: str) -> Tier | None:
        """Return the explicit tier override for `repo_full_name`, or None."""
        return self.by_repo.get(repo_full_name)


_EMPTY = TierConfig(by_repo={})

_TIER_NAMES: dict[str, Tier] = {
    "critical": Tier.CRITICAL,
    "deployed": Tier.DEPLOYED,
    "internal": Tier.INTERNAL,
    "archived": Tier.ARCHIVED,
}


def load_config(path: str | Path = ".appsec-triage.toml") -> TierConfig:
    """Load the tier override config. Returns EMPTY when the file is missing.

    Tolerates malformed entries (skipped with a stderr warning) so a typo
    in one repo override does not block the rest of the batch. The full
    list of accepted tier names is `critical | deployed | internal |
    archived` (case-insensitive); unknown names are dropped.
    """
    p = Path(path)
    if not p.is_file():
        return _EMPTY
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        print(
            f"[config] could not parse {p}: {e}; ignoring overrides",
            file=sys.stderr,
        )
        return _EMPTY
    raw_repos = data.get("repos")
    if not isinstance(raw_repos, dict):
        return _EMPTY
    out: dict[str, Tier] = {}
    for repo, entry in raw_repos.items():
        if not isinstance(repo, str) or not isinstance(entry, dict):
            continue
        tier_name = entry.get("tier")
        if not isinstance(tier_name, str):
            continue
        tier = _TIER_NAMES.get(tier_name.strip().lower())
        if tier is None:
            print(
                f"[config] unknown tier {tier_name!r} for {repo!r}; "
                f"valid: critical|deployed|internal|archived",
                file=sys.stderr,
            )
            continue
        out[repo] = tier
    return TierConfig(by_repo=out)
