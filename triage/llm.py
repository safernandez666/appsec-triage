"""OpenAI-compatible chat completions client.

Single external dep (httpx). Reads LLM_BASE_URL / LLM_API_KEY / LLM_MODEL from
the environment. Every call is `temperature=0` by contract — same input → same
output. The pipeline depends on that determinism: with non-zero temperature the
Consistency Gate (Phase 9) would chase its own tail across runs.

Importing this module does NOT import httpx. httpx is imported lazily inside
`chat()` so that --offline runs that never reach the LLM keep working without
the dep installed.

The same client is used by both the Advisory Agent (Phase 6) and the Final
Judge (Phase 7). The Judge will pass `response_format={"type":"json_object"}`
to force its strict-JSON contract; the Advisory does too.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

DEFAULT_TIMEOUT = 30.0
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"


class LLMNotConfigured(Exception):
    """Raised when LLM_API_KEY is missing.

    Callers should treat this as a degraded mode, not a crash: the Advisory
    Agent returns `()`, the Final Judge falls back to needs_review. The bot
    keeps running.
    """


@dataclass(frozen=True)
class LLMConfig:
    base_url: str
    api_key: str
    model: str

    @classmethod
    def from_env(cls) -> "LLMConfig":
        key = os.environ.get("LLM_API_KEY")
        if not key:
            raise LLMNotConfigured("LLM_API_KEY not set in environment")
        return cls(
            base_url=os.environ.get("LLM_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            api_key=key,
            model=os.environ.get("LLM_MODEL", DEFAULT_MODEL),
        )


def chat(
    messages: list[dict[str, str]],
    *,
    config: LLMConfig | None = None,
    response_format: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Single-turn chat completion. Returns the assistant content string.

    Always `temperature=0`. If `response_format={"type":"json_object"}`, the
    upstream is asked for strict JSON; the caller still validates the shape —
    we never trust the model to honor the request perfectly.
    """
    # Resolve config FIRST so LLMNotConfigured fires before we attempt the
    # httpx import. Order matters: subcase "no LLM_API_KEY AND no httpx
    # installed" must surface as `LLM not configured`, not as `ModuleNotFoundError`.
    cfg = config or LLMConfig.from_env()
    import httpx  # lazy on purpose, see module docstring
    body: dict[str, object] = {
        "model": cfg.model,
        "messages": messages,
        "temperature": 0,
    }
    if response_format is not None:
        body["response_format"] = response_format
    with httpx.Client(timeout=timeout) as c:
        r = c.post(
            f"{cfg.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {cfg.api_key}",
                "Content-Type": "application/json",
            },
            json=body,
        )
        r.raise_for_status()
        data = r.json()
    return data["choices"][0]["message"]["content"]
