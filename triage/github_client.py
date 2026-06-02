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

from triage.types import Alert, RepoProfile

GITHUB_API = "https://api.github.com"
USER_AGENT = "appsec-triage-bot/0.1"
DISMISS_REASONS = {"not_used", "inaccurate", "tolerable_risk"}


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
        return [Alert.from_payload(p) for p in r.json()]

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
        if reason not in DISMISS_REASONS:
            raise ValueError(f"dismissed_reason must be one of {DISMISS_REASONS}, got {reason!r}")
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

    # ---- Issues ----------------------------------------------------------

    def list_issues(self, owner: str, name: str, *, label: str, state: str = "open") -> list[dict]:
        r = self._client.get(
            f"/repos/{owner}/{name}/issues",
            params={"labels": label, "state": state, "per_page": 100},
        )
        r.raise_for_status()
        return r.json()

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

    def list_issues(self, owner: str, name: str, *, label: str, state: str = "open") -> list[dict]:
        return [
            i for i in self._issues.get((owner, name), [])
            if (state == "all" or i.get("state", "open") == state)
            and label in i.get("labels", [])
        ]

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
        if reason not in DISMISS_REASONS:
            raise ValueError(f"dismissed_reason must be one of {DISMISS_REASONS}, got {reason!r}")
        self._dismissed.append({
            "owner": owner, "name": name, "number": number,
            "reason": reason, "comment": comment,
        })
        return True

    def load_repo_alert_sets(self) -> list[RepoAlertSet]:
        groups: dict[str, tuple[RepoProfile, list[Alert]]] = {}
        for path in sorted(self.fixtures_dir.glob("*.json")):
            with path.open(encoding="utf-8") as f:
                payload = json.load(f)
            alert = Alert.from_payload(payload)
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
