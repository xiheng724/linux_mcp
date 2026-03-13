#!/usr/bin/env python3
"""Shared capability selection and payload logic for llm-app."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Tuple

DEFAULT_DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_DEEPSEEK_MODEL = "deepseek-chat"


@dataclasses.dataclass(frozen=True)
class SelectorConfig:
    mode: str
    deepseek_url: str
    deepseek_model: str
    deepseek_timeout_sec: int


def _index_capabilities(capabilities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    by_name: Dict[str, Dict[str, Any]] = {}
    for capability in capabilities:
        capability_name = capability.get("capability_domain")
        if isinstance(capability_name, str) and capability_name:
            by_name[capability_name] = capability
    return by_name


def _heuristic_capability_domain(user_text: str) -> Tuple[str, str]:
    lower = user_text.lower()
    if any(k in lower for k in ("wechat", "message", "send", "email", "短信", "发消息", "发送")):
        return "message.send", "keyword(message/send/wechat)"
    if any(k in lower for k in ("inbox", "read message", "messages", "收件箱", "读消息")):
        return "message.read", "keyword(message/read)"
    if any(k in lower for k in ("browser", "open website", "click", "网页", "浏览器")):
        return "browser.automation", "keyword(browser/网页)"
    if any(k in lower for k in ("github", "notion", "issue", "update page", "post", "api", "外部", "同步")):
        return "external.write", "keyword(github/notion/external)"
    if any(
        k in lower
        for k in ("create file", "write file", "copy", "rename", "delete", "remove", "touch", "写文件", "删除文件")
    ):
        return "file.write", "keyword(file/write/copy/delete)"
    if any(k in lower for k in ("list files", "preview", "read file", "show file", "open file", "读文件", "查看文件")):
        return "file.read", "keyword(file/read/preview)"
    if any(k in lower for k in ("run", "execute", "stress", "command", "执行", "运行", "压力")):
        return "exec.run", "keyword(exec/run)"
    if any(k in lower for k in ("weather", "fetch", "http", "download", "tomorrow", "网络", "天气")):
        return "network.fetch.readonly", "keyword(network/weather/fetch)"
    return "info.lookup", "default(info.lookup)"


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
    for capability in capabilities:
        capability_name = capability.get("capability_domain")
        if not isinstance(capability_name, str) or not capability_name:
            continue
        capability_brief.append(
            {
                "capability_domain": capability_name,
                "description": capability.get("description", ""),
                "risk_level": capability.get("risk_level", 0),
                "broker_id": capability.get("broker_id", ""),
                "provider_ids": capability.get("provider_ids", []),
            }
        )

    prompt = {
        "user_input": user_text,
        "capabilities": capability_brief,
        "output_format": {"capability_domain": "string", "reason": "string"},
        "rule": "Return one JSON object only. No markdown.",
    }
    req_obj = {
        "model": cfg.deepseek_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a capability router. Select exactly one capability_domain "
                    "from the provided capabilities. Respond with strict JSON only: "
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
    reason = obj.get("reason", "")
    if not isinstance(reason, str):
        reason = str(reason)
    return capability_name, reason


def select_capability_for_input(
    user_text: str,
    capabilities: List[Dict[str, Any]],
    cfg: SelectorConfig,
    warn_cb: Callable[[str], None] | None = None,
) -> Tuple[Dict[str, Any], str, str]:
    """Select one capability domain from list by DeepSeek/heuristic."""
    by_name = _index_capabilities(capabilities)
    if not by_name:
        raise RuntimeError("no valid capabilities discovered from mcpd")

    api_key = os.getenv("DEEPSEEK_API_KEY", "")
    if cfg.mode in ("auto", "deepseek"):
        if api_key:
            try:
                selected_name, reason = _call_deepseek_capability_selector(
                    user_text, capabilities, api_key, cfg
                )
                selected = by_name.get(selected_name)
                if selected is None:
                    raise RuntimeError(
                        f"DeepSeek selected unavailable capability_domain={selected_name}; "
                        f"available={sorted(by_name.keys())}"
                    )
                return selected, "deepseek", reason or "model-selected"
            except Exception as exc:  # noqa: BLE001
                if cfg.mode == "deepseek":
                    raise RuntimeError(f"DeepSeek capability selection failed: {exc}") from exc
                if warn_cb is not None:
                    warn_cb(f"DeepSeek unavailable ({exc}), fallback to heuristic")
        elif cfg.mode == "deepseek":
            raise RuntimeError("DEEPSEEK_API_KEY not set, cannot use deepseek mode")

    selected_name, reason = _heuristic_capability_domain(user_text)
    selected = by_name.get(selected_name)
    if selected is None:
        fallback_name = sorted(by_name.keys())[0]
        selected = by_name[fallback_name]
        reason = f"{reason}; fallback_first_available={fallback_name}"
    return selected, "heuristic", reason


def _extract_burn_ms(user_text: str) -> int:
    found = re.search(r"(\d+)", user_text)
    if not found:
        return 200
    ms = int(found.group(1))
    if ms < 1:
        return 1
    if ms > 10_000:
        return 10_000
    return ms


def _extract_calc_expression(user_text: str) -> str:
    quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", user_text)
    if quoted:
        for idx in (1, 2, 3):
            part = quoted.group(idx)
            if part:
                return part.strip()

    sanitized = re.sub(
        r"(?i)\b(calc|calculate|compute|eval|evaluate|what is|what's|是多少|等于多少)\b",
        " ",
        user_text,
    )
    candidates = re.findall(r"[0-9\.\+\-\*\/%\(\)\s]{3,}", sanitized)
    for cand in sorted(candidates, key=len, reverse=True):
        expr = " ".join(cand.split())
        has_digit = any(ch.isdigit() for ch in expr)
        has_op = any(ch in expr for ch in "+-*/%")
        if has_digit and has_op:
            return expr
    return user_text.strip()


def _extract_file_path(user_text: str, default_path: str = "README.md") -> str:
    quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", user_text)
    if quoted:
        for idx in (1, 2, 3):
            part = quoted.group(idx)
            if part:
                candidate = part.strip()
                if candidate:
                    return candidate

    key_match = re.search(r"(?i)\b(?:file|path)\b\s*[:=]?\s*([A-Za-z0-9_./\-]+)", user_text)
    if key_match:
        return key_match.group(1).strip()

    for token in re.findall(r"[A-Za-z0-9_./\-]+", user_text):
        cleaned = token.strip(".,;:()[]{}")
        if not cleaned:
            continue
        if cleaned.replace(".", "", 1).isdigit():
            continue
        if "/" in cleaned or "." in cleaned:
            return cleaned
    return default_path


def _extract_max_lines(user_text: str) -> int:
    found = re.search(r"(\d+)\s*(?:lines?|行)", user_text, re.IGNORECASE)
    if not found:
        return 30
    lines = int(found.group(1))
    if lines < 1:
        return 1
    if lines > 200:
        return 200
    return lines


def _extract_hash_algorithm(user_text: str) -> str:
    lower = user_text.lower()
    if "md5" in lower:
        return "md5"
    if "sha1" in lower or "sha-1" in lower:
        return "sha1"
    return "sha256"


def _extract_hash_text(user_text: str) -> str:
    quoted = re.search(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", user_text)
    if quoted:
        for idx in (1, 2, 3):
            part = quoted.group(idx)
            if part:
                return part
    cleaned = re.sub(r"(?i)\b(hash|digest|sha256|sha1|sha-1|md5|with)\b", " ", user_text)
    cleaned = " ".join(cleaned.split())
    return cleaned or user_text


def _extract_timezone(user_text: str) -> str:
    lower = user_text.lower()
    if any(k in lower for k in ("utc", "gmt", "zulu", "协调世界时")):
        return "utc"
    return "local"


def _extract_volume_payload(user_text: str) -> Dict[str, Any]:
    lower = user_text.lower()
    if any(k in lower for k in ("current volume", "get volume", "what volume", "音量多少")):
        return {"action": "get"}
    if any(k in lower for k in ("mute", "静音")) and "unmute" not in lower:
        return {"action": "mute"}
    if any(k in lower for k in ("unmute", "取消静音")):
        return {"action": "unmute"}

    found = re.search(r"(\d+)", lower)
    value = 10
    if found:
        value = max(1, min(100, int(found.group(1))))

    if any(k in lower for k in ("increase", "up", "louder", "raise", "调高", "增大")):
        return {"action": "change", "step": value}
    if any(k in lower for k in ("decrease", "down", "quieter", "lower", "调低", "减小")):
        return {"action": "change", "step": -value}
    if "set" in lower or "to " in lower or "音量" in lower:
        return {"action": "set", "level": value}
    return {"action": "get"}


def _extract_create_file_payload(user_text: str) -> Dict[str, Any]:
    path = ""
    path_match = re.search(
        r"(?i)\b(?:create|new|write|touch)\s+(?:a\s+)?(?:file\s+)?([A-Za-z0-9_./\-]+)",
        user_text,
    )
    if path_match:
        path = path_match.group(1).strip()
    if not path:
        key_match = re.search(r"(?i)\b(?:file|path)\s*[:=]?\s*([A-Za-z0-9_./\-]+)", user_text)
        if key_match:
            path = key_match.group(1).strip()
    if not path:
        path = _extract_file_path(user_text, default_path="notes.txt")

    quoted = re.findall(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", user_text)
    values: List[str] = []
    for tup in quoted:
        for part in tup:
            if part:
                values.append(part)
    content = ""
    if values:
        content = values[-1]
    else:
        m = re.search(r"(?i)(?:with|content)\s*[:=]?\s+(.+)$", user_text)
        if m:
            content = m.group(1).strip()

    overwrite = bool(
        re.search(r"(?i)\b(overwrite|replace|force|覆盖|替换|强制)\b", user_text)
    )
    return {"path": path, "content": content, "overwrite": overwrite}


def _extract_list_files_payload(user_text: str) -> Dict[str, Any]:
    path = _extract_file_path(user_text, default_path=".")
    max_entries = 100
    found = re.search(r"(?i)\b(\d+)\s*(?:entries|files|items|条)\b", user_text)
    if found:
        max_entries = int(found.group(1))
    if max_entries < 1:
        max_entries = 1
    if max_entries > 1000:
        max_entries = 1000
    return {"path": path, "max_entries": max_entries}


def _extract_delete_file_payload(user_text: str) -> Dict[str, Any]:
    path = ""
    path_match = re.search(
        r"(?i)\b(?:delete|remove|unlink)\s+(?:file\s+)?([A-Za-z0-9_./\-]+)",
        user_text,
    )
    if path_match:
        path = path_match.group(1).strip()
    if not path:
        path = _extract_file_path(user_text, default_path="")
    if not path:
        path = "tmp/demo_created_by_mcp.txt"

    recursive = bool(re.search(r"(?i)\b(recursive|directory|dir|目录|递归)\b", user_text))
    allow_missing = bool(re.search(r"(?i)\b(ignore missing|allow missing|忽略不存在)\b", user_text))
    return {"path": path, "recursive": recursive, "allow_missing": allow_missing}


def _extract_src_dst_paths(user_text: str) -> Tuple[str, str]:
    lower = user_text.lower()
    m = re.search(
        r"(?i)\b(?:copy|rename|move)\s+(?:file\s+)?([A-Za-z0-9_./\-]+)\s+(?:to|as|->)\s+([A-Za-z0-9_./\-]+)",
        user_text,
    )
    if m:
        return m.group(1).strip(), m.group(2).strip()

    quoted = re.findall(r"`([^`]+)`|\"([^\"]+)\"|'([^']+)'", user_text)
    values: List[str] = []
    for tup in quoted:
        for part in tup:
            if part:
                values.append(part.strip())
    if len(values) >= 2:
        return values[0], values[1]

    tokens = [t.strip(".,;:()[]{}") for t in re.findall(r"[A-Za-z0-9_./\-]+", user_text)]
    paths = [t for t in tokens if ("/" in t or "." in t) and t not in {"to", "as"}]
    if len(paths) >= 2:
        return paths[0], paths[1]

    if "rename" in lower or "move" in lower:
        return "tmp/a.txt", "tmp/a_renamed.txt"
    return "README.md", "tmp/README.copy.md"


def _extract_copy_file_payload(user_text: str) -> Dict[str, Any]:
    src_path, dst_path = _extract_src_dst_paths(user_text)
    overwrite = bool(re.search(r"(?i)\b(overwrite|replace|force|覆盖|替换|强制)\b", user_text))
    return {
        "src_path": src_path,
        "dst_path": dst_path,
        "overwrite": overwrite,
        "create_parents": True,
    }


def _extract_rename_file_payload(user_text: str) -> Dict[str, Any]:
    src_path, dst_path = _extract_src_dst_paths(user_text)
    overwrite = bool(re.search(r"(?i)\b(overwrite|replace|force|覆盖|替换|强制)\b", user_text))
    return {
        "src_path": src_path,
        "dst_path": dst_path,
        "overwrite": overwrite,
        "create_parents": True,
    }


def build_payload_for_action(action_name: str, user_text: str) -> Dict[str, Any]:
    if action_name == "file_copy":
        return _extract_copy_file_payload(user_text)
    if action_name == "file_rename":
        return _extract_rename_file_payload(user_text)
    if action_name == "file_list":
        return _extract_list_files_payload(user_text)
    if action_name == "file_delete":
        return _extract_delete_file_payload(user_text)
    if action_name == "volume_control":
        return _extract_volume_payload(user_text)
    if action_name == "file_create":
        return _extract_create_file_payload(user_text)
    if action_name == "cpu_burn":
        return {"ms": _extract_burn_ms(user_text)}
    if action_name == "text_stats":
        return {"text": user_text}
    if action_name == "sys_info":
        path = _extract_file_path(user_text, default_path="")
        if path:
            return {"path": path}
        return {}
    if action_name == "calc":
        return {"expression": _extract_calc_expression(user_text)}
    if action_name == "file_preview":
        return {"path": _extract_file_path(user_text), "max_lines": _extract_max_lines(user_text)}
    if action_name == "hash_text":
        return {"text": _extract_hash_text(user_text), "algorithm": _extract_hash_algorithm(user_text)}
    if action_name == "time_now":
        return {"timezone": _extract_timezone(user_text)}
    return {"message": user_text}


# Deprecated compatibility alias. Prefer build_payload_for_action().
