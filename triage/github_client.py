"""GitHub API wrapper.

Two backends behind one shape: real HTTP via httpx (online) and disk fixtures
(offline). The CLI and downstream agents work with `RepoAlertSet` and don't
care which backend produced it.

Endpoints in v1 scope:
    GET   /repos/{o}/{r}/dependabot/alerts         list alerts
    GET   /repos/{o}/{r}                           repo metadata (Truth Table input)
    GET   /search/code                             reachability (Evidence Agent — Phase 4)
    PATCH /repos/{o}/{r}/dependabot/alerts/{n}     auto-dismiss (Phase 10)

httpx is imported lazily so --offline never needs the dependency installed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from triage.types import Alert, AlertSource, RepoProfile

GITHUB_API = "https://api.github.com"
USER_AGENT = "appsec-triage-bot/0.2"

# Dismiss vocabulary differs per source.
DEPENDABOT_DISMISS_REASONS = {"not_used", "inaccurate", "tolerable_risk"}
CODE_SCANNING_DISMISS_REASONS = {"false positive", "won't fix", "used in tests"}
# Secret scanning has NO automated dismiss — humans must rotate then close.

# Back-compat alias for the v1 name. Existing code that imports DISMISS_REASONS
# is talking about Dependabot.
DISMISS_REASONS = DEPENDABOT_DISMISS_REASONS


@dataclass(frozen=True)
class RepoAlertSet:
    """One repo + its open Dependabot alerts. The unit of work for the pipeline."""
    repo: RepoProfile
    alerts: list[Alert]


class GitHubClient:
    """Online client. Real HTTP via httpx."""

    def __init__(self, token: str):
        import httpx  # lazy: --offline must not require httpx to be installed
        self._client = httpx.Client(
            base_url=GITHUB_API,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": USER_AGENT,
            },
            timeout=30.0,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def get_repo(self, owner: str, name: str) -> RepoProfile:
        r = self._client.get(f"/repos/{owner}/{name}")
        r.raise_for_status()
        return RepoProfile.from_payload(r.json())

    def list_dependabot_alerts(self, owner: str, name: str, state: str = "open") -> list[Alert]:
        r = self._client.get(
            f"/repos/{owner}/{name}/dependabot/alerts",
            params={"state": state, "per_page": 100},
        )
        r.raise_for_status()
        return [Alert.from_dependabot_payload(p) for p in r.json()]

    def list_code_scanning_alerts(self, owner: str, name: str, state: str = "open") -> list[Alert]:
        """v2: GitHub Code Scanning (CodeQL + 3rd-party SAST).

        Requires `security_events: read` scope. State filter aligns with the
        Dependabot listing; CodeQL also supports `dismissed`, `fixed`.
        """
        r = self._client.get(
            f"/repos/{owner}/{name}/code-scanning/alerts",
            params={"state": state, "per_page": 100},
        )
        r.raise_for_status()
        return [Alert.from_code_scanning_payload(p) for p in r.json()]

    def list_secret_scanning_alerts(self, owner: str, name: str, state: str = "open") -> list[Alert]:
        """v2: GitHub Secret Scanning.

        Requires `secret_scanning_alerts: read` scope (separate from
        `security_events`). The dismiss method is INTENTIONALLY not provided
        — humans must confirm rotation; see issue_manager._maybe_dismiss.
        """
        r = self._client.get(
            f"/repos/{owner}/{name}/secret-scanning/alerts",
            params={"state": state, "per_page": 100},
        )
        r.raise_for_status()
        return [Alert.from_secret_scanning_payload(p) for p in r.json()]

    def path_exists(self, owner: str, name: str, path: str) -> bool:
        """True if `path` exists on the default branch.

        Used by the Evidence Agent (Phase 4) to confirm manifest / lockfile /
        Dockerfile presence. Returns False on 404 instead of raising — that is
        the expected "not present" signal, not an error.
        """
        if not path:
            return False
        r = self._client.get(f"/repos/{owner}/{name}/contents/{path}")
        if r.status_code == 404:
            return False
        r.raise_for_status()
        return True

    def search_code(self, query: str) -> dict[str, Any]:
        """Code search. CAVEAT: default branch only, files <384 KB only.

        Documented limitation of the PoC — see README.
        """
        r = self._client.get("/search/code", params={"q": query, "per_page": 100})
        r.raise_for_status()
        return r.json()

    def dismiss_alert(
        self,
        owner: str,
        name: str,
        number: int,
        reason: str,
        comment: str = "",
    ) -> bool:
        """Dismiss a Dependabot alert. (Back-compat name; new code may also
        call dismiss_dependabot_alert.)
        """
        if reason not in DEPENDABOT_DISMISS_REASONS:
            raise ValueError(
                f"Dependabot dismissed_reason must be one of "
                f"{DEPENDABOT_DISMISS_REASONS}, got {reason!r}"
            )
        r = self._client.patch(
            f"/repos/{owner}/{name}/dependabot/alerts/{number}",
            json={
                "state": "dismissed",
                "dismissed_reason": reason,
                "dismissed_comment": comment,
            },
        )
        r.raise_for_status()
        return True

    # v2: explicit alias for clarity.
    dismiss_dependabot_alert = dismiss_alert

    def dismiss_code_scanning_alert(
        self,
        owner: str,
        name: str,
        number: int,
        reason: str,
        comment: str = "",
    ) -> bool:
        """v2: dismiss a CodeQL / code-scanning alert.

        Distinct from Dependabot in vocabulary: CodeQL uses {"false positive",
        "won't fix", "used in tests"} (with the spaces). The Issue manager
        decides which reason fits and passes it here.
        """
        if reason not in CODE_SCANNING_DISMISS_REASONS:
            raise ValueError(
                f"code-scanning dismissed_reason must be one of "
                f"{CODE_SCANNING_DISMISS_REASONS}, got {reason!r}"
            )
        r = self._client.patch(
            f"/repos/{owner}/{name}/code-scanning/alerts/{number}",
            json={
                "state": "dismissed",
                "dismissed_reason": reason,
                "dismissed_comment": comment,
            },
        )
        r.raise_for_status()
        return True

    # v2: secret scanning has no auto-dismiss method on this client by design.
    # If you reach for it, you are about to do the wrong thing. The bot opens
    # a "rotate now" Issue; a human closes it manually after rotation.

    # ---- Issues ----------------------------------------------------------

    def list_issues(
        self,
        owner: str,
        name: str,
        *,
        label: str | None = None,
        state: str = "open",
    ) -> list[dict]:
        """List Issues. `label=None` means no label filter — needed by
        `_find_existing` so the marker-based dedupe still works on repos
        where the `autotriage` label was never applied (e.g. because it
        did not exist yet at the time of the first create)."""
        params: dict[str, str | int] = {"state": state, "per_page": 100}
        if label is not None:
            params["labels"] = label
        r = self._client.get(f"/repos/{owner}/{name}/issues", params=params)
        r.raise_for_status()
        return r.json()

    def ensure_label(
        self,
        owner: str,
        name: str,
        label: str,
        *,
        color: str = "d97706",
        description: str = "Created by appsec-triage bot.",
    ) -> None:
        """Create `label` on the repo if it does not already exist.

        Idempotent: GitHub returns 422 when the label already exists; we
        swallow that single case and return. Any other failure raises so
        the operator notices auth or permission problems immediately.

        The triage Issues lookup historically filtered by this label,
        and a missing label silently broke dedupe — every create produced
        a new duplicate Issue. Calling this once per repo at cycle start
        prevents that silent regression."""
        r = self._client.post(
            f"/repos/{owner}/{name}/labels",
            json={"name": label, "color": color, "description": description},
        )
        if r.status_code == 422:
            return  # already exists
        r.raise_for_status()

    def create_issue(
        self,
        owner: str,
        name: str,
        title: str,
        body: str,
        labels: list[str] | tuple[str, ...] = (),
    ) -> int:
        r = self._client.post(
            f"/repos/{owner}/{name}/issues",
            json={"title": title, "body": body, "labels": list(labels)},
        )
        r.raise_for_status()
        return int(r.json()["number"])

    def add_comment(self, owner: str, name: str, issue_number: int, body: str) -> int:
        r = self._client.post(
            f"/repos/{owner}/{name}/issues/{issue_number}/comments",
            json={"body": body},
        )
        r.raise_for_status()
        return int(r.json()["id"])

    def close_issue(self, owner: str, name: str, issue_number: int) -> bool:
        r = self._client.patch(
            f"/repos/{owner}/{name}/issues/{issue_number}",
            json={"state": "closed"},
        )
        r.raise_for_status()
        return True

    # ---- v2 extension hooks (not wired in v1) ------------------------------
    #
    # CodeQL alerts:
    #     def list_code_scanning_alerts(self, owner, name, state="open"):
    #         GET /repos/{o}/{r}/code-scanning/alerts?state=open&per_page=100
    #     def dismiss_code_scanning_alert(self, owner, name, number, reason, comment):
    #         PATCH /repos/{o}/{r}/code-scanning/alerts/{n}
    #         body: {"state":"dismissed","dismissed_reason":"won't fix"|"false positive"|"used in tests"}
    #     A separate `Alert.from_code_scanning_payload` classmethod fills the
    #     same flat shape so the rest of the pipeline does not branch.
    #
    # Secret scanning alerts:
    #     def list_secret_scanning_alerts(self, owner, name, state="open"):
    #         GET /repos/{o}/{r}/secret-scanning/alerts
    #     Auto-dismiss is permanently DISABLED for this source — never expose a
    #     `dismiss_secret_scanning_alert` method here. Humans must confirm rotation
    #     by closing the Issue manually after the secret is rotated upstream.
    # ------------------------------------------------------------------------


class OfflineGitHubClient:
    """Offline backend backed by fixtures/alerts/*.json.

    Groups fixture alerts by their `_meta.repo_profile_hint` so each (owner,name)
    becomes a synthetic repo with its own Alerts. Iterating over
    `load_repo_alert_sets()` mirrors the online flow: get_repo then
    list_dependabot_alerts.
    """

    def __init__(self, fixtures_dir: Path):
        self.fixtures_dir = fixtures_dir
        # In-memory side-effect logs. Fresh per process — the offline mode is
        # deliberately not persisted across invocations; same-cycle behavior
        # (within one --offline run) is what matters for the PoC demo.
        self._issues: dict[tuple[str, str], list[dict]] = {}
        self._next_issue_number: int = 1001
        self._comments: list[dict] = []
        self._dismissed: list[dict] = []

    def close(self) -> None:
        return None

    def __enter__(self) -> "OfflineGitHubClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- Issue stubs (in-memory) ----------------------------------------

    def list_issues(
        self,
        owner: str,
        name: str,
        *,
        label: str | None = None,
        state: str = "open",
    ) -> list[dict]:
        return [
            i for i in self._issues.get((owner, name), [])
            if (state == "all" or i.get("state", "open") == state)
            and (label is None or label in i.get("labels", []))
        ]

    def ensure_label(
        self,
        owner: str,
        name: str,
        label: str,
        *,
        color: str = "d97706",
        description: str = "Created by appsec-triage bot.",
    ) -> None:
        """No-op in offline mode — there is no labels API and the in-memory
        Issue store does not enforce label existence. Method exists so the
        cycle-start ensure_label call works regardless of client type."""
        return None

    def create_issue(
        self,
        owner: str,
        name: str,
        title: str,
        body: str,
        labels: list[str] | tuple[str, ...] = (),
    ) -> int:
        n = self._next_issue_number
        self._next_issue_number += 1
        self._issues.setdefault((owner, name), []).append({
            "number": n,
            "title": title,
            "body": body,
            "labels": list(labels),
            "state": "open",
        })
        return n

    def add_comment(self, owner: str, name: str, issue_number: int, body: str) -> int:
        cid = len(self._comments) + 1
        self._comments.append({
            "owner": owner, "name": name, "issue_number": issue_number,
            "id": cid, "body": body,
        })
        return cid

    def close_issue(self, owner: str, name: str, issue_number: int) -> bool:
        for i in self._issues.get((owner, name), []):
            if i["number"] == issue_number:
                i["state"] = "closed"
                return True
        return False

    def dismiss_alert(
        self, owner: str, name: str, number: int, reason: str, comment: str = "",
    ) -> bool:
        if reason not in DEPENDABOT_DISMISS_REASONS:
            raise ValueError(
                f"Dependabot dismissed_reason must be one of "
                f"{DEPENDABOT_DISMISS_REASONS}, got {reason!r}"
            )
        self._dismissed.append({
            "owner": owner, "name": name, "number": number,
            "source": AlertSource.DEPENDABOT.value,
            "reason": reason, "comment": comment,
        })
        return True

    # v2: offline shadow of the real dismiss_dependabot_alert alias.
    dismiss_dependabot_alert = dismiss_alert

    def dismiss_code_scanning_alert(
        self, owner: str, name: str, number: int, reason: str, comment: str = "",
    ) -> bool:
        if reason not in CODE_SCANNING_DISMISS_REASONS:
            raise ValueError(
                f"code-scanning dismissed_reason must be one of "
                f"{CODE_SCANNING_DISMISS_REASONS}, got {reason!r}"
            )
        self._dismissed.append({
            "owner": owner, "name": name, "number": number,
            "source": AlertSource.CODE_SCANNING.value,
            "reason": reason, "comment": comment,
        })
        return True

    # v2: NO dismiss_secret_scanning_alert on offline client either —
    # intentional asymmetry mirrors the real client.

    def load_repo_alert_sets(
        self,
        sources: frozenset[AlertSource] | None = None,
    ) -> list[RepoAlertSet]:
        """Load fixtures, optionally filtered to a subset of sources.

        v2: `sources=None` is shorthand for "everything"; pass a frozenset to
        restrict to one or two of the three v2 sources. The dispatch by payload
        shape happens inside `Alert.from_payload`.
        """
        groups: dict[str, tuple[RepoProfile, list[Alert]]] = {}
        for path in sorted(self.fixtures_dir.glob("*.json")):
            with path.open(encoding="utf-8") as f:
                payload = json.load(f)
            alert = Alert.from_payload(payload)
            if sources is not None and alert.source not in sources:
                continue
            hint = alert.meta.get("repo_profile_hint")
            if not hint:
                raise RuntimeError(
                    f"offline fixture {path.name} has no _meta.repo_profile_hint — "
                    f"add one or the Truth Table can't classify the repo"
                )
            repo = RepoProfile.from_hint(hint)
            key = repo.full_name
            if key not in groups:
                groups[key] = (repo, [])
            groups[key][1].append(alert)
        return [RepoAlertSet(repo, alerts) for repo, alerts in groups.values()]
