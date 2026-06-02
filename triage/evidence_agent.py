"""Zone 2 — Evidence Agent. Pure Python, no LLM.

Collects raw facts about the alert and the repo:
- Direct package usage (does the code import / reference the vulnerable package?)
- Vulnerable API usage (does the code call the specific symbols the advisory
  flagged? Only meaningful once the Advisory Agent has extracted those symbols.)
- Manifest / lockfile / Dockerfile presence.

NO interpretation. Counts and booleans only. Everything that smells like a
verdict belongs to the Truth Table or the Judge.

Two backends, same shape:
- `collect_evidence_offline`: reads `_meta.code_search_hint` from the fixture.
  Honest about not hitting the network — the hint IS the synthetic evidence.
- `collect_evidence_online`: uses /search/code and /contents on the real API.

CAVEAT (documented in README): /search/code only indexes the default branch
and files <384 KB. `direct_package_hits == 0` therefore means "no evidence found
on the default branch in indexable files" — not "definitely not used". The
Truth Table treats this absence as positive evidence only under specific
conditions, never blindly.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from triage.types import Alert, EvidenceMatrix, RepoProfile

if TYPE_CHECKING:
    from triage.github_client import GitHubClient

# Ecosystem → candidate lockfile paths on the default branch root.
# Conservative: only entries we are confident about. Unknown ecosystems just get
# `has_lockfile=False` rather than a wrong guess.
LOCKFILES_BY_ECOSYSTEM: dict[str, tuple[str, ...]] = {
    "pip": ("poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock"),
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "rubygems": ("Gemfile.lock",),
    "cargo": ("Cargo.lock",),
    "go_modules": ("go.sum",),
    "gradle": ("gradle.lockfile",),
    "maven": (),  # Maven uses pom.xml as both manifest and dependency lock; no separate lockfile.
}


def empty_evidence_for_non_dependabot(alert: Alert) -> EvidenceMatrix:
    """v2: build a minimal EvidenceMatrix for sources that do not use the
    Dependabot-style reachability flow.

    CodeQL: the rule already names what is vulnerable and where. There is no
    package/version range to map onto code search, and there are no API
    symbols to look up. We still produce an EvidenceMatrix so the rest of
    the pipeline (Truth Table dispatch, Judge prompt, Prosecutor checks) has
    something to consume — but every count is 0 and every boolean reflects
    "we did not look".
    """
    from triage.types import AlertSource
    ecosystem = (
        "code-scanning" if alert.source is AlertSource.CODE_SCANNING
        else alert.source.value
    )
    return EvidenceMatrix(
        package_name=alert.rule_id or (alert.summary[:40] if alert.summary else "?"),
        ecosystem=ecosystem,
        direct_package_hits=0,
        vuln_api_hits=0,
    )


def collect_evidence_offline(
    alert: Alert,
    repo: RepoProfile,
    advisory_apis: tuple[str, ...] = (),
) -> EvidenceMatrix:
    """Build an EvidenceMatrix from the fixture's `_meta.code_search_hint`.

    `advisory_apis` is what the Advisory Agent extracted (empty `()` until Phase 6
    wires it in). When empty, we deliberately leave `vuln_api_hits=0` and
    `vuln_apis_seen=()` — we have nothing to look up. The fixture may carry
    those values in its hint, but consuming them without Advisory output would
    be cheating: the matrix would claim an API was seen when nothing told the
    Evidence Agent to look for it.
    """
    hint: dict[str, Any] = alert.meta.get("code_search_hint", {}) or {}
    direct_hits = int(hint.get("direct_package_hits", 0))

    vuln_hits = 0
    vuln_apis_seen: tuple[str, ...] = ()
    if advisory_apis:
        seen_from_hint = hint.get("vuln_apis_seen", []) or []
        # Restrict to APIs the Advisory Agent actually surfaced — never invent.
        vuln_apis_seen = tuple(a for a in seen_from_hint if a in advisory_apis)
        # Hit counter is honest only when the intersection is non-empty:
        # reporting "3 hits but no APIs listed" would be a count without a
        # subject. If Advisory and the hint do not overlap, we saw nothing.
        vuln_hits = int(hint.get("vuln_api_hits", 0)) if vuln_apis_seen else 0

    return EvidenceMatrix(
        package_name=alert.package_name,
        ecosystem=alert.package_ecosystem,
        direct_package_hits=direct_hits,
        vuln_api_hits=vuln_hits,
        vuln_apis_seen=vuln_apis_seen,
        has_manifest=bool(hint.get("has_manifest", bool(alert.manifest_path))),
        has_lockfile=bool(hint.get("has_lockfile", False)),
        has_dockerfile=bool(hint.get("has_dockerfile", False)),
        advisory_apis=advisory_apis,
    )


def collect_evidence_online(
    alert: Alert,
    repo: RepoProfile,
    client: "GitHubClient",
    advisory_apis: tuple[str, ...] = (),
) -> EvidenceMatrix:
    """Use /search/code and /contents to collect facts.

    Rate-limit caveat: /search/code is throttled to ~30 req/min authenticated.
    Errors from individual searches degrade to a 0 count rather than killing the
    cycle — the Truth Table needs an honest "we couldn't see" signal, which
    here is `direct_package_hits == 0` plus the operator's awareness via the
    error log.
    """
    direct_hits = _count_search_hits(client, _package_query(alert.package_name, repo))

    vuln_hits = 0
    vuln_apis_seen_list: list[str] = []
    for api in advisory_apis:
        n = _count_search_hits(client, _api_query(api, repo))
        if n > 0:
            vuln_apis_seen_list.append(api)
            vuln_hits += n

    has_manifest = bool(alert.manifest_path) and _safe_path_exists(
        client, repo.owner, repo.name, alert.manifest_path
    )
    has_lockfile = _detect_lockfile(client, repo, alert.package_ecosystem)
    has_dockerfile = _safe_path_exists(client, repo.owner, repo.name, "Dockerfile")

    return EvidenceMatrix(
        package_name=alert.package_name,
        ecosystem=alert.package_ecosystem,
        direct_package_hits=direct_hits,
        vuln_api_hits=vuln_hits,
        vuln_apis_seen=tuple(vuln_apis_seen_list),
        has_manifest=has_manifest,
        has_lockfile=has_lockfile,
        has_dockerfile=has_dockerfile,
        advisory_apis=advisory_apis,
    )


# ---- online helpers --------------------------------------------------------


def _package_query(package: str, repo: RepoProfile) -> str:
    # Conservative literal match scoped to the repo. We deliberately do NOT
    # over-filter by path/language here — that would hide imports in test files
    # or polyglot subdirs that the Judge later needs to reason about.
    return f'"{package}" repo:{repo.full_name}'


def _api_query(api: str, repo: RepoProfile) -> str:
    return f'"{api}" repo:{repo.full_name}'


def _count_search_hits(client: "GitHubClient", query: str) -> int:
    try:
        payload = client.search_code(query)
    except Exception:
        # Degraded mode: 0 hits rather than aborting. The cycle still produces
        # an EvidenceMatrix; the Truth Table will see absence and choose its
        # path conservatively.
        return 0
    return int(payload.get("total_count", 0))


def _safe_path_exists(client: "GitHubClient", owner: str, name: str, path: str) -> bool:
    try:
        return client.path_exists(owner, name, path)
    except Exception:
        return False


def _detect_lockfile(client: "GitHubClient", repo: RepoProfile, ecosystem: str) -> bool:
    for path in LOCKFILES_BY_ECOSYSTEM.get(ecosystem, ()):
        if _safe_path_exists(client, repo.owner, repo.name, path):
            return True
    return False
