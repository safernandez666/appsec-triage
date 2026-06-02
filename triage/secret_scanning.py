"""v2 — Secret scanning: Z1 short-circuit straight to Z4.

Different risk model: a leaked secret is leaked. There is no "is it
reproducible?" question to answer, no advisory APIs to extract, no code
reachability to check. The bot's job is to make sure the secret gets
rotated by a human — fast.

Therefore the pipeline collapses to:
  Z1 routing  →  Z4 output  (no Z2 investigation, no Z3 judgment)

The Verdict produced here is `ROTATE_NOW` (v2 addition to VerdictKind),
emitted by `build_rotate_now_verdict()`. It NEVER reaches the Judge, the
Prosecutor, the Critic, the Consensus check, or any LLM call.

The Consistency Gate is still consulted (a re-detected secret should not
generate a duplicate Issue), but the verdict cannot flip — the only
possible state for an open secret alert is `ROTATE_NOW`.

Auto-dismiss for this source is structurally impossible:
  1. `triage/github_client.py` does NOT expose a dismiss method for
     secret scanning.
  2. `issue_manager._maybe_dismiss()` early-returns on `AlertSource.SECRET_SCANNING`
     before reaching any dismiss logic, as a second line of defense.

Humans must confirm the rotation by manually closing the Issue.
"""
from __future__ import annotations

from triage.types import Alert, Verdict, VerdictKind


def build_rotate_now_verdict(alert: Alert) -> Verdict:
    """Build the one and only verdict a secret scanning alert can have.

    `confidence=1.0` is honest: this isn't a probabilistic call, it's
    structural — every leaked secret needs rotation. The Critic will pass
    this through unchanged on any tier (1.0 clears every post_floor).
    """
    location = _format_location(alert)
    secret_name = (
        alert.raw.get("secret_type_display_name")
        or alert.secret_type
        or "secret"
    )
    return Verdict(
        kind=VerdictKind.ROTATE_NOW,
        confidence=1.0,
        human_conclusion=(
            f"A {secret_name} was detected in this repository at {location}. "
            "Rotate the credential immediately upstream; removing it from git "
            "history is not sufficient because the value may already have been "
            "scraped. After rotation, close this Issue manually."
        ),
        source="secret_scanning:rotate_now",
    )


def _format_location(alert: Alert) -> str:
    """Best-effort 'file:line @ commit_sha[:8]' from the raw payload."""
    try:
        loc = (alert.raw.get("locations") or [{}])[0]
        details = loc.get("details") or {}
        path = details.get("path")
        line = details.get("start_line")
        sha = details.get("commit_sha", "")
        if path and line:
            sha_short = (sha[:8] + "…") if sha else ""
            base = f"`{path}:{line}`"
            return f"{base} (commit {sha_short})" if sha_short else base
        if path:
            return f"`{path}`"
    except (AttributeError, IndexError, TypeError, KeyError):
        pass
    return "an unknown location in this repo"


def build_issue_body(alert: Alert, marker: str) -> str:
    """Override the Dependabot/CodeQL Issue body for secret scanning.

    The body is shaped for urgency: location first, rotation steps right after,
    rationale at the bottom. Reviewer should be able to start rotating in one
    read. Used by issue_manager when alert.source is SECRET_SCANNING.
    """
    secret_name = (
        alert.raw.get("secret_type_display_name")
        or alert.secret_type
        or "secret"
    )
    location = _format_location(alert)
    return (
        f"{marker}\n\n"
        f"# 🔥 ROTATE NOW\n\n"
        f"A **{secret_name}** was detected in this repository.\n\n"
        f"**Location:** {location}\n"
        f"**Alert:** {alert.html_url}\n\n"
        f"---\n\n"
        f"## Steps\n\n"
        f"1. **Rotate the credential at the issuing provider** (cloud console, "
        f"IdP, service dashboard). Do NOT skip this step — removing it from "
        f"git history is insufficient because the value may already have been "
        f"scraped by automated crawlers.\n"
        f"2. Deploy any service or job that depends on the rotated credential.\n"
        f"3. Audit access logs for use of the leaked credential between the "
        f"commit time and the rotation time.\n"
        f"4. Close this Issue manually once rotation is confirmed.\n\n"
        f"---\n\n"
        f"## Why this is not auto-closed\n\n"
        f"Secret scanning alerts are never auto-dismissed by this bot. "
        f"A leaked credential is not a question of reproducibility — it is leaked. "
        f"The only valid resolution is rotation upstream, and only a human can "
        f"confirm that happened. See "
        f"[the project README](https://github.com/safernandez666/appsec-triage#zone-4--output-github-first-no-jira) "
        f"for the source policy.\n"
    )
