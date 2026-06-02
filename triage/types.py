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
    # v2: secret scanning never goes through Judge — it ends here.
    ROTATE_NOW = "rotate_now"


class AlertSource(Enum):
    """Where an alert came from. Drives ingestion + routing + dismiss semantics.

    DEPENDABOT  — vulnerable dependency; goes through the full Z1→Z2→Z3→Z4 pipeline.
    CODE_SCANNING — CodeQL / external SAST finding; same pipeline but different
                    Judge prompt and dismiss reasons.
    SECRET_SCANNING — leaked credential; Z1 SHORT-CIRCUITS to Z4 with a
                      "rotate now" Issue. No Z2/Z3, no LLM judgment. Auto-dismiss
                      is structurally impossible for this source.
    """
    DEPENDABOT = "dependabot"
    CODE_SCANNING = "code_scanning"
    SECRET_SCANNING = "secret_scanning"


@dataclass(frozen=True)
class Alert:
    """Flattened alert from any GitHub security source.

    The original payload is kept under `raw` so downstream agents that need
    fields we did not promote (commit_sha, auto_dismissed_at, location.start_line,
    secret_type_display_name, etc.) can still reach them without re-fetching.

    Fields are nullable because they only make sense for some sources:
      - Dependabot only: package_*, manifest_path, scope, ghsa_id, cve_id,
        vulnerable_version_range, first_patched_version.
      - CodeQL only: rule_id, location_path, location_line, dataflow_class.
      - Secret scanning only: secret_type, secret_locations (in raw).
    Source-specific accessors live in the respective agents — this struct
    just carries the data.
    """
    source: AlertSource
    number: int
    state: str
    summary: str
    description: str
    severity: str
    created_at: str
    html_url: str

    # Dependabot-specific (None for other sources)
    package_name: str | None = None
    package_ecosystem: str | None = None
    manifest_path: str | None = None
    scope: str | None = None
    ghsa_id: str | None = None
    cve_id: str | None = None
    vulnerable_version_range: str | None = None
    first_patched_version: str | None = None

    # CodeQL-specific (None for other sources)
    rule_id: str | None = None
    location_path: str | None = None
    location_line: int | None = None

    # Secret scanning-specific (None for other sources)
    secret_type: str | None = None

    raw: dict[str, Any] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)  # fixture-only, not present online

    @classmethod
    def from_dependabot_payload(cls, payload: dict[str, Any]) -> "Alert":
        dep = payload.get("dependency", {})
        pkg = dep.get("package", {})
        adv = payload.get("security_advisory", {})
        vuln = payload.get("security_vulnerability", {})
        patched = vuln.get("first_patched_version") or {}
        return cls(
            source=AlertSource.DEPENDABOT,
            number=int(payload["number"]),
            state=payload.get("state", "open"),
            summary=adv.get("summary", ""),
            description=adv.get("description", ""),
            severity=adv.get("severity", "unknown"),
            created_at=payload.get("created_at", ""),
            html_url=payload.get("html_url", ""),
            package_name=pkg.get("name", "?"),
            package_ecosystem=pkg.get("ecosystem", "?"),
            manifest_path=dep.get("manifest_path", ""),
            scope=dep.get("scope", "runtime"),
            ghsa_id=adv.get("ghsa_id", ""),
            cve_id=adv.get("cve_id"),
            vulnerable_version_range=vuln.get("vulnerable_version_range", ""),
            first_patched_version=patched.get("identifier"),
            raw=payload,
            meta=payload.get("_meta", {}) or {},
        )

    @classmethod
    def from_code_scanning_payload(cls, payload: dict[str, Any]) -> "Alert":
        """v2: GitHub Code Scanning (CodeQL + external SAST) alert payload.

        Endpoint shape: /repos/{o}/{r}/code-scanning/alerts
        Reference: https://docs.github.com/en/rest/code-scanning/code-scanning
        """
        rule = payload.get("rule", {})
        tool = payload.get("tool", {})
        most_recent = payload.get("most_recent_instance", {}) or {}
        location = most_recent.get("location", {}) or {}
        message = most_recent.get("message", {}) or {}
        return cls(
            source=AlertSource.CODE_SCANNING,
            number=int(payload["number"]),
            state=payload.get("state", "open"),
            summary=rule.get("description") or rule.get("name", ""),
            description=(message.get("text") or rule.get("full_description") or ""),
            severity=rule.get("security_severity_level") or rule.get("severity") or "unknown",
            created_at=payload.get("created_at", ""),
            html_url=payload.get("html_url", ""),
            rule_id=rule.get("id"),
            location_path=location.get("path"),
            location_line=(location.get("start_line") if isinstance(location.get("start_line"), int) else None),
            raw=payload,
            meta=payload.get("_meta", {}) or {},
        )

    @classmethod
    def from_secret_scanning_payload(cls, payload: dict[str, Any]) -> "Alert":
        """v2: GitHub Secret Scanning alert payload.

        Endpoint shape: /repos/{o}/{r}/secret-scanning/alerts
        Reference: https://docs.github.com/en/rest/secret-scanning
        """
        secret_type = payload.get("secret_type", "unknown")
        return cls(
            source=AlertSource.SECRET_SCANNING,
            number=int(payload["number"]),
            state=payload.get("state", "open"),
            summary=f"Secret leaked: {payload.get('secret_type_display_name') or secret_type}",
            description=(
                f"A {payload.get('secret_type_display_name') or secret_type} was detected "
                "in this repository. Rotate the secret immediately; do not rely on "
                "removing it from history."
            ),
            severity="critical",  # every leaked secret is critical until rotated
            created_at=payload.get("created_at", ""),
            html_url=payload.get("html_url", ""),
            secret_type=secret_type,
            raw=payload,
            meta=payload.get("_meta", {}) or {},
        )

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "Alert":
        """Backwards-compat shim for v1 callers. Dispatches by payload shape.

        New code should call the source-specific classmethod directly.
        """
        if "secret_type" in payload:
            return cls.from_secret_scanning_payload(payload)
        if "rule" in payload and "most_recent_instance" in payload:
            return cls.from_code_scanning_payload(payload)
        return cls.from_dependabot_payload(payload)

    @property
    def identity(self) -> str:
        """Stable key for memory and consensus lookups. Source-dependent.

        Dependabot:     CVE::ecosystem::package      (cross-repo consensus works)
        CodeQL:         rule_id::path                (per-file rule identity)
        Secret:         secret_type::commit_or_path  (one secret, many leaks)
        """
        if self.source is AlertSource.DEPENDABOT:
            cve = self.cve_id or self.ghsa_id or "?"
            return f"{cve}::{self.package_ecosystem}::{self.package_name}"
        if self.source is AlertSource.CODE_SCANNING:
            return f"{self.rule_id or '?'}::{self.location_path or '?'}"
        if self.source is AlertSource.SECRET_SCANNING:
            # Locations may rotate; secret_type + first commit is the stable key.
            first_commit = ""
            try:
                first_commit = (self.raw.get("locations") or [{}])[0].get("details", {}).get("commit_sha", "")
            except (AttributeError, IndexError, TypeError):
                first_commit = ""
            return f"{self.secret_type or '?'}::{first_commit or self.number}"
        return f"{self.source.value}::{self.number}"


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
