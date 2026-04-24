#!/usr/bin/env python3
"""Shared helpers for talking to an OpenAI-compatible Chat Completions endpoint.

The HTTP call shape (`POST {base}/chat/completions`, `Bearer` auth, `messages`
array, `choices[0].message.content`) is the de-facto standard used by OpenAI,
DeepSeek, Groq, Together, Fireworks, OpenRouter, Mistral, local Ollama/vLLM/
LM Studio, and many others. As a result this module is provider-agnostic: the
user picks an endpoint via `--model-url`, a model id via `--model-name`, and an
API key via `LLM_API_KEY` (or the legacy `DEEPSEEK_API_KEY`).
"""

from __future__ import annotations

import dataclasses
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from rpc import mcpd_call

DEFAULT_MODEL_URL = os.getenv(
    "LLM_MODEL_URL",
    os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions"),
)
DEFAULT_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "deepseek-chat")

# Backward-compatible aliases (older imports reference these names).
DEFAULT_DEEPSEEK_URL = DEFAULT_MODEL_URL
DEFAULT_DEEPSEEK_MODEL = DEFAULT_MODEL_NAME


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    model_url: str
    model_name: str
    model_timeout_sec: int


@dataclasses.dataclass
class SessionInfo:
    # Not frozen: rebind-on-catalog-stale mutates session_id/agent_id in place
    # so long-lived plan executions can transparently survive a kernel-side
    # catalog_epoch bump without the planner having to re-thread state.
    session_id: str
    agent_id: str
    expires_at_ms: int
    ttl_ms: int
    client_name: str


def require_api_key() -> str:
    api_key = os.getenv("LLM_API_KEY", "") or os.getenv("DEEPSEEK_API_KEY", "")
    if not api_key:
        raise RuntimeError(
            "no LLM API key found: set LLM_API_KEY (or legacy DEEPSEEK_API_KEY)"
        )
    return api_key


def extract_json_object(text: str) -> Dict[str, Any]:
    decoder = json.JSONDecoder()
    for idx, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            obj, _end = decoder.raw_decode(text[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
    raise ValueError(f"no JSON object found in model output: {text!r}")


def call_model(prompt: Dict[str, Any], system_text: str, api_key: str, cfg: SelectorConfig) -> Dict[str, Any]:
    content = call_model_text(prompt, system_text, api_key, cfg)
    return extract_json_object(content)


def call_model_text(prompt: Dict[str, Any], system_text: str, api_key: str, cfg: SelectorConfig) -> str:
    req_obj = {
        "model": cfg.model_name,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
        ],
    }
    payload = json.dumps(req_obj, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        cfg.model_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.model_timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM request failed: {exc}") from exc

    data = json.loads(raw.decode("utf-8"))
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError(f"invalid LLM response, missing choices: {data}")
    msg = choices[0].get("message", {})
    content = msg.get("content", "")
    if not isinstance(content, str) or not content:
        raise RuntimeError(f"invalid LLM response content: {data}")
    return content


def current_time_context() -> Dict[str, str]:
    now = datetime.now(timezone.utc)
    return {
        "current_utc_time": now.isoformat(),
        "current_utc_date": now.date().isoformat(),
        "current_timezone": "UTC",
    }


def runtime_context() -> Dict[str, str]:
    repo_root = Path(__file__).resolve().parent.parent
    home_dir = Path.home()
    desktop_dir = home_dir / "Desktop"
    if not desktop_dir.exists():
        desktop_dir = home_dir / "desktop"
    return {
        "workspace_root_rel": ".",
        "cwd_abs": os.getcwd(),
        "repo_root_abs": str(repo_root),
        "home_dir_abs": str(home_dir),
        "desktop_dir_abs": str(desktop_dir),
    }


def open_session(sock_path: str, client_name: str, ttl_ms: int) -> SessionInfo:
    resp = mcpd_call(
        {
            "sys": "open_session",
            "client_name": client_name,
            "ttl_ms": ttl_ms,
        },
        sock_path=sock_path,
        timeout_s=5,
    )
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", "open_session failed"))
    session_id = resp.get("session_id", "")
    agent_id = resp.get("agent_id", "")
    expires_at_ms = resp.get("expires_at_ms", 0)
    ttl_ms_resp = resp.get("ttl_ms", 0)
    if (
        not isinstance(session_id, str)
        or not session_id
        or not isinstance(agent_id, str)
        or not agent_id
        or isinstance(expires_at_ms, bool)
        or not isinstance(expires_at_ms, int)
        or expires_at_ms <= 0
        or isinstance(ttl_ms_resp, bool)
        or not isinstance(ttl_ms_resp, int)
        or ttl_ms_resp <= 0
    ):
        raise RuntimeError(f"invalid open_session response: {resp}")
    return SessionInfo(
        session_id=session_id,
        agent_id=agent_id,
        expires_at_ms=expires_at_ms,
        ttl_ms=ttl_ms_resp,
        client_name=client_name,
    )
