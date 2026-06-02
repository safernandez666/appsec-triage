"""Zone 4 — Issue management + auto-transition + tier-1 guardrail.

GitHub-first output. One Issue per alert (label `autotriage` + hidden HTML
marker for state tracking). The triage conclusion goes as a comment on that
Issue. Optional auto-dismiss of the Dependabot alert when the verdict is
false_positive and confidence clears the tier transition floor — except in
tier-1 repos, where auto-dismiss is structurally and explicitly impossible.

The non-negotiable tier-1 guardrail is enforced two ways:
  1. `TIER_FLOORS[Tier.CRITICAL].transition_floor = float("inf")` — the
     confidence comparison cannot pass.
  2. An explicit early return below — belt + suspenders. If anyone ever edits
     the floors to a finite value, this catches it.

Honors the spec's `--dry-run` (compute everything, mutate nothing) and the
absence of `--auto-transition` (Issues still get created/commented, but no
Dependabot dismiss).

NEVER clones repos, NEVER writes code in target repos, NEVER dismisses outside
the conditions above.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from triage.consistency import ConsistencyAction, ConsistencyDecision
from triage.truth_table import TierClassification
from triage.types import Alert, RepoProfile, Tier, Verdict, VerdictKind

ISSUE_LABEL = "autotriage"


@dataclass(frozen=True)
class CycleFlags:
    dry_run: bool = False
    auto_transition: bool = False


@dataclass(frozen=True)
class IssueAction:
    kind: str               # "skip" | "create" | "comment" | "close" | (+"+dismissed") | "blocked"
    issue_number: int | None
    detail: str             # log line


class _IssuesAndAlertsClient(Protocol):
    """Minimal slice of GitHubClient/OfflineGitHubClient used here."""
    def list_issues(self, owner: str, name: str, *, label: str, state: str = "open") -> list[dict]: ...
    def create_issue(self, owner: str, name: str, title: str, body: str, labels: list[str] | tuple[str, ...] = ()) -> int: ...
    def add_comment(self, owner: str, name: str, issue_number: int, body: str) -> int: ...
    def close_issue(self, owner: str, name: str, issue_number: int) -> bool: ...
    def dismiss_alert(self, owner: str, name: str, number: int, reason: str, comment: str = "") -> bool: ...


def marker_for(alert: Alert) -> str:
    return f"<!-- triage:{alert.identity} -->"


def issue_title(alert: Alert) -> str:
    cve = alert.cve_id or alert.ghsa_id
    return f"[triage] {alert.package_name} — {cve}"


def handle_fast_path_close(
    client: _IssuesAndAlertsClient,
    repo: RepoProfile,
    alert: Alert,
    note: str,
    flags: CycleFlags,
) -> IssueAction:
    """Z1 fast-path (state already fixed/dismissed upstream).

    If an Issue exists for this alert, comment + close it. If none exists,
    do nothing — never create an Issue just to close it.
    """
    marker = marker_for(alert)
    existing = _find_existing(client, repo, marker, state="open")
    if existing is None:
        return IssueAction("skip", None, "no existing Issue; fast-path close has nothing to update")
    if flags.dry_run:
        return IssueAction(
            "close",
            existing,
            f"DRY-RUN would close Issue #{existing} with note: {note}",
        )
    client.add_comment(repo.owner, repo.name, existing, note)
    client.close_issue(repo.owner, repo.name, existing)
    return IssueAction("close", existing, f"closed Issue #{existing} after upstream resolution")


def handle(
    client: _IssuesAndAlertsClient,
    repo: RepoProfile,
    alert: Alert,
    verdict: Verdict,
    tier: TierClassification,
    decision: ConsistencyDecision,
    flags: CycleFlags,
) -> IssueAction:
    """Apply Issue + Dependabot side-effects implied by `decision` and `verdict`."""
    if decision.action is ConsistencyAction.SKIP:
        return IssueAction("skip", None, "consistency=SKIP: no Issue change, no dismiss")

    marker = marker_for(alert)
    existing = _find_existing(client, repo, marker, state="open")

    if existing is None:
        body = _build_issue_body(alert, verdict, marker)
        if flags.dry_run:
            issue_number: int | None = None
            issue_log = f"DRY-RUN would create Issue: title='{issue_title(alert)}', label={ISSUE_LABEL}"
        else:
            issue_number = client.create_issue(
                repo.owner, repo.name, issue_title(alert), body, labels=[ISSUE_LABEL],
            )
            issue_log = f"created Issue #{issue_number}"
        primary_kind = "create"
    else:
        comment_body = _build_comment(verdict, decision)
        if flags.dry_run:
            issue_number = existing
            issue_log = f"DRY-RUN would comment on existing Issue #{existing}"
        else:
            client.add_comment(repo.owner, repo.name, existing, comment_body)
            issue_number = existing
            issue_log = f"commented on existing Issue #{existing}"
        primary_kind = "comment"

    dismissed, transition_log = _maybe_dismiss(client, repo, alert, verdict, tier, flags)
    if transition_log is None:
        return IssueAction(primary_kind, issue_number, issue_log)
    suffix = "+dismissed" if dismissed else "+nodismiss"
    return IssueAction(f"{primary_kind}{suffix}", issue_number, f"{issue_log}; {transition_log}")


def _maybe_dismiss(
    client: _IssuesAndAlertsClient,
    repo: RepoProfile,
    alert: Alert,
    verdict: Verdict,
    tier: TierClassification,
    flags: CycleFlags,
) -> tuple[bool, str | None]:
    """Returns (actually_dismissed, log_line).

    log_line is None only when the verdict is not FP (the question doesn't apply).
    In every other case there's something worth saying — auto-transition off,
    guardrail block, confidence below floor, dry-run, or the actual DISMISS.
    Whether the dismiss actually happened is in the bool, not the kind string.
    """
    if verdict.kind is not VerdictKind.FALSE_POSITIVE:
        return False, None
    if not flags.auto_transition:
        return False, "--auto-transition off, no dismiss attempted"

    # GUARDRAIL — non-negotiable. Tier 1 repos are never auto-dismissed,
    # full stop. Belt + suspenders with the float("inf") transition floor.
    if tier.tier is Tier.CRITICAL:
        return False, (
            f"GUARDRAIL: tier-1 (critical) repo — auto-dismiss blocked "
            f"regardless of confidence ({verdict.confidence:.2f})"
        )

    if verdict.confidence < tier.transition_floor:
        return False, (
            f"confidence {verdict.confidence:.2f} below tier transition_floor "
            f"{tier.transition_floor:.2f}; no dismiss"
        )

    reason = _dismiss_reason(verdict)
    if flags.dry_run:
        return False, f"DRY-RUN would dismiss Dependabot alert #{alert.number} reason={reason}"
    client.dismiss_alert(
        repo.owner, repo.name, alert.number,
        reason, comment=verdict.human_conclusion[:140],
    )
    return True, f"DISMISSED Dependabot alert #{alert.number} reason={reason}"


def _dismiss_reason(verdict: Verdict) -> str:
    src = verdict.source or ""
    # Truth Table rules that fire on "no usage detected" map cleanly to `not_used`.
    # Everything else (Judge or forced rules with different sources) → `inaccurate`,
    # which is the safest non-`tolerable_risk` reason. We never use
    # `tolerable_risk` automatically — that is a human policy decision.
    if src.startswith("truth_table:") and "no_hits" in src:
        return "not_used"
    return "inaccurate"


def _find_existing(
    client: _IssuesAndAlertsClient,
    repo: RepoProfile,
    marker: str,
    *,
    state: str = "open",
) -> int | None:
    try:
        issues = client.list_issues(repo.owner, repo.name, label=ISSUE_LABEL, state=state)
    except Exception:
        return None
    for i in issues:
        body = i.get("body") or ""
        if marker in body:
            try:
                return int(i["number"])
            except (TypeError, ValueError, KeyError):
                return None
    return None


def _build_issue_body(alert: Alert, verdict: Verdict, marker: str) -> str:
    cve = alert.cve_id or alert.ghsa_id
    patched = alert.first_patched_version or "unknown"
    return (
        f"{marker}\n\n"
        f"**Package:** `{alert.package_name}` ({alert.package_ecosystem}/{alert.scope})\n"
        f"**Advisory:** {alert.ghsa_id} / {cve} (severity={alert.severity})\n"
        f"**Vulnerable range:** {alert.vulnerable_version_range}  "
        f"**First patched:** {patched}\n"
        f"**Manifest:** `{alert.manifest_path or 'unspecified'}`\n"
        f"\n---\n\n### Triage conclusion\n\n{verdict.human_conclusion}\n"
    )


def _build_comment(verdict: Verdict, decision: ConsistencyDecision) -> str:
    parts: list[str] = []
    if decision.action is ConsistencyAction.GUARD:
        parts.append(
            "> ⚠️ **Please review before closing.** The verdict changed since "
            "the last cycle, but the new conclusion is not strong enough to "
            "act on automatically.\n"
        )
    parts.append(verdict.human_conclusion)
    return "\n".join(parts)
