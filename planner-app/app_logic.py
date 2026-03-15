#!/usr/bin/env python3
"""Planner-side capability intent selection for planner-app."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Sequence, Tuple

DEFAULT_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    mode: str
    deepseek_url: str
    deepseek_model: str
    deepseek_timeout_sec: int


@dataclasses.dataclass(frozen=True)
class CapabilityIntent:
    capability_domain: str
    capability_id: int
    capability_hash: str
    intent_text: str
    preferred_provider_id: str
    hints: Dict[str, Any]
    selector_source: str
    selector_reason: str


def _index_capabilities(capabilities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by_name: Dict[str, Dict[str, Any]] = {}
    for capability in capabilities:
        capability_name = capability.get("capability_domain")
        if isinstance(capability_name, str) and capability_name:
            by_name[capability_name] = capability
    return by_name


def _tokenize(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(_TOKEN_RE.findall(value.lower()))
    if isinstance(value, dict):
        tokens: List[str] = []
        for key, item in value.items():
            tokens.extend(_tokenize(key))
            tokens.extend(_tokenize(item))
        return tuple(tokens)
    if isinstance(value, (list, tuple, set)):
        tokens = []
        for item in value:
            tokens.extend(_tokenize(item))
        return tuple(tokens)
    return tuple(_TOKEN_RE.findall(str(value).lower()))


def _normalize_tokens(tokens: Sequence[str]) -> Tuple[str, ...]:
    normalized: List[str] = []
    for token in tokens:
        if not token:
            continue
        normalized.append(token)
        if len(token) > 5 and token.endswith("e"):
            normalized.append(token[:-1])
        for suffix in ("ations", "ation", "ions", "ion", "ing", "ed", "es", "s"):
            if len(token) > len(suffix) + 2 and token.endswith(suffix):
                normalized.append(token[: -len(suffix)])
    return tuple(dict.fromkeys(normalized))


def _soft_token_matches(intent_tokens: set[str], metadata_tokens: set[str]) -> int:
    matches = 0
    for intent_token in intent_tokens:
        for metadata_token in metadata_tokens:
            if intent_token == metadata_token:
                continue
            if min(len(intent_token), len(metadata_token)) < 5:
                continue
            if intent_token.startswith(metadata_token) or metadata_token.startswith(intent_token):
                matches += 1
                break
    return matches


def _score_capability_metadata(user_text: str, capability: Dict[str, Any]) -> int:
    intent_tokens = set(_normalize_tokens(_tokenize(user_text)))
    if not intent_tokens:
        return 0

    tag_tokens = set(_normalize_tokens(_tokenize(capability.get("intent_tags", []))))
    example_tokens = set(_normalize_tokens(_tokenize(capability.get("examples", []))))
    desc_tokens = set(_normalize_tokens(_tokenize(capability.get("description", ""))))
    provider_tokens = set(_normalize_tokens(_tokenize(capability.get("provider_ids", []))))
    domain_tokens = set(_normalize_tokens(_tokenize(capability.get("capability_domain", ""))))

    score = 0
    score += 22 * len(intent_tokens & tag_tokens)
    score += 10 * _soft_token_matches(intent_tokens, tag_tokens)
    score += 12 * len(intent_tokens & example_tokens)
    score += 5 * _soft_token_matches(intent_tokens, example_tokens)
    score += 6 * len(intent_tokens & desc_tokens)
    score += 3 * _soft_token_matches(intent_tokens, desc_tokens)
    score += 4 * len(intent_tokens & domain_tokens)
    score += 2 * _soft_token_matches(intent_tokens, domain_tokens)
    score += 2 * len(intent_tokens & provider_tokens)
    if capability.get("examples"):
        score += 2
    if capability.get("intent_tags"):
        score += 2
    return score


def select_capability_from_catalog(
    user_text: str,
    capability_catalog: Iterable[Dict[str, Any]],
) -> Tuple[Dict[str, Any], str]:
    capabilities = [item for item in capability_catalog if isinstance(item, dict)]
    if not capabilities:
        raise RuntimeError("capability catalog is empty")

    best_capability: Dict[str, Any] | None = None
    best_rank: Tuple[int, int, str] | None = None
    for capability in capabilities:
        capability_domain = str(capability.get("capability_domain", ""))
        if not capability_domain:
            continue
        score = _score_capability_metadata(user_text, capability)
        risk_level = int(capability.get("risk_level", 0) or 0)
        rank = (score, -risk_level, capability_domain)
        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_capability = capability

    if best_capability is None or best_rank is None:
        raise RuntimeError("no valid capability selected from catalog")
    return best_capability, f"catalog_score={best_rank[0]}"


def _extract_json_object(text: str) -> Dict[str, Any]:
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


def _call_deepseek_capability_selector(
    user_text: str,
    capabilities: List[Dict[str, Any]],
    api_key: str,
    cfg: SelectorConfig,
) -> Tuple[str, str]:
    capability_brief: List[Dict[str, Any]] = []
    allowed_capabilities: List[str] = []
    for capability in capabilities:
        capability_name = capability.get("capability_domain")
        if not isinstance(capability_name, str) or not capability_name:
            continue
        allowed_capabilities.append(capability_name)
        capability_brief.append(
            {
                "capability_domain": capability_name,
                "description": capability.get("description", ""),
                "intent_tags": capability.get("intent_tags", []),
                "examples": capability.get("examples", []),
                "risk_level": capability.get("risk_level", 0),
                "broker_id": capability.get("broker_id", ""),
                "provider_ids": capability.get("provider_ids", []),
            }
        )

    prompt = {
        "user_input": user_text,
        "allowed_capability_domains": allowed_capabilities,
        "capabilities": capability_brief,
        "output_format": {"capability_domain": "string", "reason": "string"},
        "rule": "Return one JSON object only. No markdown. capability_domain must be one of allowed_capability_domains.",
    }
    req_obj = {
        "model": cfg.deepseek_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a capability router. Select exactly one capability_domain "
                    "from the provided catalog. Do not invent capabilities. Respond with strict JSON only: "
                    "{\"capability_domain\":\"...\",\"reason\":\"...\"}."
                ),
            },
            {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
        ],
    }

    payload = json.dumps(req_obj, ensure_ascii=True).encode("utf-8")
    req = urllib.request.Request(
        cfg.deepseek_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=cfg.deepseek_timeout_sec) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"DeepSeek HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"DeepSeek request failed: {exc}") from exc

    data = json.loads(raw.decode("utf-8"))
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError(f"invalid DeepSeek response, missing choices: {data}")
    msg = choices[0].get("message", {})
    content = msg.get("content", "")
    if not isinstance(content, str) or not content:
        raise RuntimeError(f"invalid DeepSeek response content: {data}")

    obj = _extract_json_object(content)
    capability_name = obj.get("capability_domain")
    if not isinstance(capability_name, str) or not capability_name:
        raise RuntimeError(f"DeepSeek returned invalid capability_domain: {obj}")
    if capability_name not in allowed_capabilities:
        raise RuntimeError(f"DeepSeek returned unavailable capability_domain={capability_name}")
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)
    return capability_name, reason


def _extract_preferred_provider_id(
    user_text: str,
    capability: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    hints: Dict[str, Any] = {}
    provider_ids = capability.get("provider_ids", [])
    if not isinstance(provider_ids, list):
        return "", hints

    lower = user_text.lower()
    generic_tokens = {"provider", "app", "service", "tool", "tools", "local", "file"}
    for provider_id in provider_ids:
        if not isinstance(provider_id, str):
            continue
        provider_tokens = [
            token
            for token in re.split(r"[-_]", provider_id.lower())
            if token and token not in generic_tokens
        ]
        if provider_id.lower() in lower:
            hints["preferred_provider_match"] = provider_id
            return provider_id, hints
        specific_matches = [token for token in provider_tokens if len(token) >= 5 and token in lower]
        if specific_matches:
            hints["preferred_provider_match"] = provider_id
            return provider_id, hints
    return "", hints


def select_capability_for_input(
    user_text: str,
    capabilities: List[Dict[str, Any]],
    cfg: SelectorConfig,
    warn_cb: Callable[[str], None] | None = None,
) -> Tuple[Dict[str, Any], str, str]:
    """Compatibility helper returning the selected capability metadata."""
    intent = plan_capability_intent(user_text, capabilities, cfg, warn_cb=warn_cb)
    by_name = _index_capabilities(capabilities)
    selected = by_name.get(intent.capability_domain)
    if selected is None:
        raise RuntimeError(f"selected capability missing from catalog: {intent.capability_domain}")
    return selected, intent.selector_source, intent.selector_reason


def plan_capability_intent(
    user_text: str,
    capabilities: List[Dict[str, Any]],
    cfg: SelectorConfig,
    warn_cb: Callable[[str], None] | None = None,
) -> CapabilityIntent:
    """Planner-side responsibility: choose a capability and emit intent-level hints only."""
    by_name = _index_capabilities(capabilities)
    if not by_name:
        raise RuntimeError("no valid capabilities discovered from mcpd")

    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if cfg.mode in ("auto", "deepseek"):
        if api_key:
            try:
                selected_name, reason = _call_deepseek_capability_selector(
                    user_text,
                    capabilities,
                    api_key,
                    cfg,
                )
                selected = by_name.get(selected_name)
                if selected is None:
                    raise RuntimeError(
                        f"DeepSeek selected unavailable capability_domain={selected_name}; "
                        f"available={sorted(by_name.keys())}"
                    )
                preferred_provider_id, hints = _extract_preferred_provider_id(user_text, selected)
                if preferred_provider_id:
                    hints.setdefault("preferred_provider_id", preferred_provider_id)
                return CapabilityIntent(
                    capability_domain=selected_name,
                    capability_id=int(selected.get("capability_id", 0)),
                    capability_hash=str(selected.get("hash", "") or ""),
                    intent_text=user_text,
                    preferred_provider_id=preferred_provider_id,
                    hints=hints,
                    selector_source="deepseek",
                    selector_reason=reason or "model-selected",
                )
            except Exception as exc:  # noqa: BLE001
                if cfg.mode == "deepseek":
                    raise RuntimeError(f"DeepSeek capability selection failed: {exc}") from exc
                if warn_cb is not None:
                    warn_cb(f"DeepSeek unavailable ({exc}), fallback to catalog selector")
        elif cfg.mode == "deepseek":
            raise RuntimeError("DEEPSEEK_API_KEY not set, cannot use deepseek mode")

    try:
        selected, reason = select_capability_from_catalog(user_text, capabilities)
        preferred_provider_id, hints = _extract_preferred_provider_id(user_text, selected)
        if preferred_provider_id:
            hints.setdefault("preferred_provider_id", preferred_provider_id)
        return CapabilityIntent(
            capability_domain=str(selected.get("capability_domain", "")),
            capability_id=int(selected.get("capability_id", 0)),
            capability_hash=str(selected.get("hash", "") or ""),
            intent_text=user_text,
            preferred_provider_id=preferred_provider_id,
            hints=hints,
            selector_source="catalog",
            selector_reason=reason,
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"catalog capability selection failed: {exc}") from exc
