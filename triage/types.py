"""Core data shapes shared across the triage pipeline.

Every value object here is a plain dataclass — no behavior beyond construction
helpers. Behavior lives in the agents that consume them. Frozen so a downstream
agent can't quietly mutate an upstream agent's findings; replace via
`dataclasses.replace` when intentional.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Tier(Enum):
    """Repo criticality — fixed by the Pre-flight Truth Table (Phase 5).

    Determines confidence floors for the Critic and whether auto-dismiss is
    even permitted. Tier 1 is never auto-dismissed; that guardrail is checked
    in the issue manager (Phase 10), not here.
    """
    CRITICAL = 1   # customer-facing
    DEPLOYED = 2   # deployed, not directly customer-facing
    INTERNAL = 3   # internal tooling / services
    ARCHIVED = 4   # archived / EOL


class VerdictKind(Enum):
    FALSE_POSITIVE = "false_positive"
    REPRODUCIBLE = "reproducible"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True)
class Alert:
    """Flattened Dependabot alert.

    The original payload is kept under `raw` so downstream agents that need
    fields we did not promote (commit_sha, auto_dismissed_at, etc.) can still
    reach them without re-fetching.
    """
    number: int
    state: str
    package_name: str
    package_ecosystem: str
    manifest_path: str
    scope: str
    ghsa_id: str
    cve_id: str | None
    summary: str
    description: str
    severity: str
    vulnerable_version_range: str
    first_patched_version: str | None
    created_at: str
    html_url: str
    raw: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)  # fixture-only, not present online

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Alert":
        dep = payload.get("dependency", {})
        pkg = dep.get("package", {})
        adv = payload.get("security_advisory", {})
        vuln = payload.get("security_vulnerability", {})
        patched = vuln.get("first_patched_version") or {}
        return cls(
            number=int(payload["number"]),
            state=payload.get("state", "open"),
            package_name=pkg.get("name", "?"),
            package_ecosystem=pkg.get("ecosystem", "?"),
            manifest_path=dep.get("manifest_path", ""),
            scope=dep.get("scope", "runtime"),
            ghsa_id=adv.get("ghsa_id", ""),
            cve_id=adv.get("cve_id"),
            summary=adv.get("summary", ""),
            description=adv.get("description", ""),
            severity=adv.get("severity", "unknown"),
            vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
            first_patched_version=patched.get("identifier"),
            created_at=payload.get("created_at", ""),
            html_url=payload.get("html_url", ""),
            raw=payload,
            meta=payload.get("_meta", {}) or {},
        )

    @property
    def identity(self) -> str:
        """Stable key for memory and consensus lookups (CVE+package)."""
        cve = self.cve_id or self.ghsa_id or "?"
        return f"{cve}::{self.package_ecosystem}::{self.package_name}"


@dataclass(frozen=True)
class RepoProfile:
    """Repo metadata used by Truth Table + Evidence Agent.

    `tier` is intentionally NOT here — it is derived by the Truth Table and
    travels alongside the profile, not on it. Keeps this dataclass faithful to
    what the GitHub API actually returns.
    """
    owner: str
    name: str
    archived: bool
    language: str | None
    age_days: int
    default_branch: str = "main"

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "RepoProfile":
        created = payload.get("created_at")
        age_days = 0
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - dt).days
            except ValueError:
                age_days = 0
        owner_login = (payload.get("owner") or {}).get("login", "?")
        return cls(
            owner=owner_login,
            name=payload.get("name", "?"),
            archived=bool(payload.get("archived", False)),
            language=payload.get("language"),
            age_days=age_days,
            default_branch=payload.get("default_branch", "main"),
        )

    @classmethod
    def from_hint(cls, hint: dict[str, Any]) -> "RepoProfile":
        """Build a RepoProfile from a fixture's _meta.repo_profile_hint block.

        Only used in --offline mode; the live API never sees this path.
        """
        return cls(
            owner=hint.get("owner", "fixture-org"),
            name=hint.get("name", "fixture-repo"),
            archived=bool(hint.get("archived", False)),
            language=hint.get("language"),
            age_days=int(hint.get("age_days", 0)),
            default_branch=hint.get("default_branch", "main"),
        )


@dataclass(frozen=True)
class EvidenceMatrix:
    """Pure facts from the Evidence Agent. No interpretation.

    Counts and booleans only — anything that could be called a 'verdict' lives
    later in the pipeline (Truth Table, Judge). The Advisory Agent populates
    `advisory_apis`; everything else comes from code search + repo inspection.
    """
    package_name: str
    ecosystem: str
    direct_package_hits: int
    vuln_api_hits: int
    vuln_apis_seen: tuple[str, ...] = ()
    has_manifest: bool = False
    has_lockfile: bool = False
    has_dockerfile: bool = False
    advisory_apis: tuple[str, ...] = ()

    @property
    def advisory_has_specific_apis(self) -> bool:
        return len(self.advisory_apis) > 0


@dataclass(frozen=True)
class Verdict:
    kind: VerdictKind
    confidence: float
    human_conclusion: str
    source: str = "judge"  # which component produced this: judge|truth_table|consensus|prosecutor|critic

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.kind.value,
            "confidence": self.confidence,
            "human_conclusion": self.human_conclusion,
            "source": self.source,
        }
