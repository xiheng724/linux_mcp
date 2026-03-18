import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Mapping, Sequence

from architecture import ProviderAction, fill_action_payload, validate_action_payload

LOGGER = logging.getLogger(__name__)

def _log_structured(level: int, event_type: str, **fields: Any) -> None:
    payload = {"event_type": event_type}
    payload.update(fields)
    LOGGER.log(level, json.dumps(payload, sort_keys=True, ensure_ascii=True))


_PATH_TOKEN_RE = re.compile(
    r"(?:\.\.?/)?[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*|[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+"
)
_INTEGER_RE = re.compile(r"(?<![A-Za-z0-9])(-?\d+)(?![A-Za-z0-9])")
_FLOAT_RE = re.compile(r"(?<![A-Za-z0-9])(-?\d+(?:\.\d+)?)(?![A-Za-z0-9])")
_QUOTED_RE = re.compile(r"['\"]([^'\"]+)['\"]")
_MATH_RE = re.compile(r"([0-9(][0-9\s+\-*/().%]+)")
_JSON_OBJECT_RE = re.compile(r"\{.*\}", flags=re.DOTALL)

INFERENCE_MODE_SCHEMA = "schema_arg_hints"
INFERENCE_MODE_LLM_STRICT = "llm_strict"
INFERENCE_MODE_HYBRID = "hybrid"


def _collect_quoted_values(text: str) -> List[str]:
    return [value.strip() for value in _QUOTED_RE.findall(text) if value.strip()]


def _extract_after_keywords(
    text: str,
    keywords: Sequence[str],
    *,
    quoted_only: bool = False,
) -> List[str]:
    matches: List[str] = []
    for keyword in keywords:
        pattern = re.compile(
            rf"\b{re.escape(keyword.lower())}\b\s+(?:['\"]([^'\"]+)['\"]|([^\s,;]+))",
            flags=re.IGNORECASE,
        )
        for match in pattern.finditer(text):
            quoted = match.group(1)
            raw = quoted if quoted is not None else ("" if quoted_only else match.group(2) or "")
            raw = raw.strip()
            if raw:
                matches.append(raw)
    return matches


def _extract_paths(text: str) -> List[str]:
    values: List[str] = []
    for raw in _collect_quoted_values(text):
        if "/" in raw or "." in raw:
            values.append(raw)
    for raw in _PATH_TOKEN_RE.findall(text):
        cleaned = raw.strip().rstrip(".,)")
        if cleaned and ("/" in cleaned or "." in cleaned):
            values.append(cleaned)
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        if value not in seen:
            out.append(value)
            seen.add(value)
    return out


def _extract_integers(text: str) -> List[int]:
    out: List[int] = []
    for match in _INTEGER_RE.findall(text):
        try:
            out.append(int(match))
        except ValueError:
            continue
    return out


def _extract_numbers(text: str) -> List[float]:
    out: List[float] = []
    for match in _FLOAT_RE.findall(text):
        try:
            out.append(float(match))
        except ValueError:
            continue
    return out


def _extract_enum_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    aliases_by_choice = field_hints.get("aliases_by_choice", {})
    if isinstance(aliases_by_choice, Mapping):
        for choice, aliases in aliases_by_choice.items():
            if isinstance(choice, str) and isinstance(aliases, Sequence):
                for alias in aliases:
                    if isinstance(alias, str) and alias.lower() in lower:
                        return choice
    choices = field_hints.get("choices", [])
    if isinstance(choices, Sequence):
        for choice in choices:
            if isinstance(choice, str) and choice.lower() in lower:
                return choice
    default = field_hints.get("default")
    return default


def _extract_boolean_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    false_tokens = field_hints.get("false_tokens", [])
    if isinstance(false_tokens, Sequence):
        for token in false_tokens:
            if isinstance(token, str) and token.lower() in lower:
                return False
    true_tokens = field_hints.get("true_tokens", [])
    if isinstance(true_tokens, Sequence):
        for token in true_tokens:
            if isinstance(token, str) and token.lower() in lower:
                return True
    return field_hints.get("default")


def _extract_integer_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    units = field_hints.get("units", [])
    matched_context = False
    if isinstance(units, Sequence):
        for unit in units:
            if not isinstance(unit, str):
                continue
            pattern = re.compile(rf"(-?\d+)\s*{re.escape(unit.lower())}\b")
            match = pattern.search(lower)
            if match:
                matched_context = True
                return int(match.group(1))
    after = field_hints.get("after", [])
    values = _extract_after_keywords(lower, [item for item in after if isinstance(item, str)])
    for value in values:
        numbers = _extract_integers(value)
        if numbers:
            matched_context = True
            return numbers[0]
    if (after or units) and not matched_context and not bool(field_hints.get("allow_global_search", False)):
        return field_hints.get("default")
    numbers = _extract_integers(lower)
    if numbers:
        position = field_hints.get("position")
        if isinstance(position, int) and 0 <= position < len(numbers):
            return numbers[position]
        return numbers[0]
    return field_hints.get("default")


def _extract_number_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    lower = text.lower()
    after = field_hints.get("after", [])
    values = _extract_after_keywords(lower, [item for item in after if isinstance(item, str)])
    for value in values:
        numbers = _extract_numbers(value)
        if numbers:
            return numbers[0]
    numbers = _extract_numbers(lower)
    if numbers:
        return numbers[0]
    return field_hints.get("default")


def _extract_path_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    values = _extract_after_keywords(text, after)
    for value in values:
        return value
    paths = _extract_paths(text)
    position = field_hints.get("position")
    if isinstance(position, int) and 0 <= position < len(paths):
        return paths[position]
    if paths:
        return paths[0]
    return field_hints.get("default")


def _extract_list_value(
    text: str,
    field_hints: Mapping[str, Any],
    item_schema: Mapping[str, Any],
) -> List[Any] | None:
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    raw_value = ""
    if after:
        values = _extract_after_keywords(text, after)
        if values:
            raw_value = values[0]
    if not raw_value:
        quoted = _collect_quoted_values(text)
        if quoted:
            raw_value = quoted[0]
    if not raw_value:
        raw_value = field_hints.get("default", "")
    if raw_value in ("", None):
        return None

    item_type = str(item_schema.get("type", "string"))
    if isinstance(raw_value, list):
        raw_items = raw_value
    else:
        raw_items = [item.strip() for item in re.split(r"[,|]", str(raw_value)) if item.strip()]
        if len(raw_items) == 1 and " and " in str(raw_value):
            raw_items = [item.strip() for item in str(raw_value).split(" and ") if item.strip()]

    out: List[Any] = []
    for raw_item in raw_items:
        try:
            out.append(_coerce_schema_value(raw_item, {"type": item_type}, "list_item", "build_execution_payload"))
        except Exception:
            continue
    return out or None


def _extract_expression_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    quoted = _collect_quoted_values(text)
    for value in quoted:
        if any(ch in value for ch in "+-*/()%"):
            return value
    match = _MATH_RE.search(text)
    if match:
        candidate = match.group(1).strip()
        if any(ch in candidate for ch in "+-*/()%"):
            return candidate
    return field_hints.get("default")


def _strip_known_prefixes(text: str, prefixes: Sequence[str]) -> str:
    out = text.strip()
    for prefix in prefixes:
        if isinstance(prefix, str) and out.lower().startswith(prefix.lower() + " "):
            out = out[len(prefix) + 1 :].strip()
    return out


def _extract_tail_text_value(text: str, field_hints: Mapping[str, Any]) -> Any:
    quoted = _collect_quoted_values(text)
    if quoted:
        position = field_hints.get("position")
        if isinstance(position, int) and 0 <= position < len(quoted):
            return quoted[position]
        return quoted[0]
    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    for keyword in after:
        match = re.search(rf"\b{re.escape(keyword)}\b\s+(.+)$", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    stripped = _strip_known_prefixes(text, field_hints.get("strip_prefixes", []))
    return stripped or field_hints.get("default")


def _extract_string_value(
    field_name: str,
    text: str,
    field_hints: Mapping[str, Any],
) -> Any:
    kind = str(field_hints.get("kind", "string"))
    if kind == "enum":
        return _extract_enum_value(text, field_hints)
    if kind == "path":
        return _extract_path_value(text, field_hints)
    if kind == "expression":
        return _extract_expression_value(text, field_hints)
    if kind == "quoted_string":
        quoted = _collect_quoted_values(text)
        if quoted:
            position = field_hints.get("position")
            if isinstance(position, int) and 0 <= position < len(quoted):
                return quoted[position]
            return quoted[0]
        return field_hints.get("default")
    if kind in {"quoted_or_tail", "tail_text"}:
        after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
        if after:
            values = _extract_after_keywords(text, after)
            if values:
                position = field_hints.get("position")
                if isinstance(position, int) and 0 <= position < len(values):
                    return values[position]
                return values[0]
        return _extract_tail_text_value(text, field_hints)

    after = [item for item in field_hints.get("after", []) if isinstance(item, str)]
    if after:
        values = _extract_after_keywords(text, after)
        if values:
            position = field_hints.get("position")
            if isinstance(position, int) and 0 <= position < len(values):
                return values[position]
            return values[0]

    aliases = [item for item in field_hints.get("aliases", []) if isinstance(item, str)]
    if aliases:
        values = _extract_after_keywords(text, aliases)
        if values:
            return values[0]

    if field_name in {"message", "text", "content"}:
        return _extract_tail_text_value(text, field_hints)
    return field_hints.get("default")


def _resolve_inference_mode(hints: Mapping[str, Any] | None) -> str:
    if isinstance(hints, Mapping):
        mode = hints.get("payload_inference_mode")
        if isinstance(mode, str):
            normalized = mode.strip().lower()
            if normalized in {INFERENCE_MODE_SCHEMA, INFERENCE_MODE_LLM_STRICT, INFERENCE_MODE_HYBRID}:
                return normalized
    raw = os.getenv("MCPD_PAYLOAD_INFERENCE_MODE", INFERENCE_MODE_SCHEMA).strip().lower()
    if raw in {INFERENCE_MODE_SCHEMA, INFERENCE_MODE_LLM_STRICT, INFERENCE_MODE_HYBRID}:
        return raw
    return INFERENCE_MODE_SCHEMA


def _extract_json_object(raw: str) -> Dict[str, Any]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty LLM response")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        match = _JSON_OBJECT_RE.search(text)
        if not match:
            raise ValueError("LLM response is not valid JSON object")
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("LLM response must be JSON object")
    return parsed


def _request_llm_payload(
    action: ProviderAction,
    intent_text: str,
    *,
    context: Mapping[str, Any] | None = None,
    previous_payload: Mapping[str, Any] | None = None,
    previous_error: str = "",
    timeout_s: float = 8.0,
) -> Dict[str, Any]:
    endpoint = os.getenv("MCPD_LLM_ENDPOINT", "").strip()
    if not endpoint:
        raise ValueError("LLM endpoint not configured")
    model = os.getenv("MCPD_LLM_MODEL", "").strip()
    api_key = os.getenv("MCPD_LLM_API_KEY", "").strip()
    system_prompt = (
        "You are a strict JSON payload generator. Return ONLY a JSON object that matches the given JSON schema. "
        "Do not add comments or markdown."
    )
    user_parts = [
        f"Intent text:\n{intent_text}",
        "Action schema (JSON Schema):",
        json.dumps(action.input_schema, ensure_ascii=True, sort_keys=True),
    ]
    if isinstance(context, Mapping) and context:
        user_parts.append("Context (JSON):")
        user_parts.append(json.dumps(dict(context), ensure_ascii=True, sort_keys=True))
    if previous_payload is not None:
        user_parts.append("Previous invalid payload:")
        user_parts.append(json.dumps(dict(previous_payload), ensure_ascii=True, sort_keys=True))
    if previous_error:
        user_parts.append(f"Validation error: {previous_error}")
    request_body: Dict[str, Any] = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ],
        "temperature": 0,
    }
    if model:
        request_body["model"] = model
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(request_body, ensure_ascii=True).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as exc:
        raise ValueError(f"LLM request failed: {exc}") from exc
    payload = _extract_json_object(raw)
    if "choices" in payload and isinstance(payload["choices"], list):
        choices = payload["choices"]
        if choices and isinstance(choices[0], Mapping):
            message = choices[0].get("message", {})
            if isinstance(message, Mapping):
                content = message.get("content")
                if isinstance(content, str):
                    return _extract_json_object(content)
                if isinstance(content, list):
                    merged = " ".join(
                        str(item.get("text", ""))
                        for item in content
                        if isinstance(item, Mapping) and item.get("type") == "text"
                    )
                    return _extract_json_object(merged)
    return payload


def _validate_candidate_payload(
    action: ProviderAction,
    candidate_defaults: Mapping[str, Any],
    provided_payload: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    merged = fill_action_payload(action, provided_payload, defaults=candidate_defaults)
    return validate_action_payload(action, merged)


def _infer_payload_with_llm(
    action: ProviderAction,
    intent_text: str,
    *,
    provided_payload: Mapping[str, Any] | None = None,
    hints: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    max_repairs = 1
    timeout_s = 8.0
    if isinstance(hints, Mapping):
        raw_repairs = hints.get("llm_repair_attempts")
        if isinstance(raw_repairs, int) and raw_repairs >= 0:
            max_repairs = raw_repairs
        raw_timeout = hints.get("llm_timeout_s")
        if isinstance(raw_timeout, (int, float)) and not isinstance(raw_timeout, bool) and raw_timeout > 0:
            timeout_s = float(raw_timeout)
    last_error = ""
    previous_payload: Mapping[str, Any] | None = None
    attempts = max_repairs + 1
    for attempt in range(1, attempts + 1):
        raw_candidate = _request_llm_payload(
            action,
            intent_text,
            context=context,
            previous_payload=previous_payload,
            previous_error=last_error,
            timeout_s=timeout_s,
        )
        previous_payload = dict(raw_candidate)
        try:
            validated = _validate_candidate_payload(action, raw_candidate, provided_payload)
            return {
                "validated": validated,
                "attempts": attempt,
                "repairs_used": max(0, attempt - 1),
            }
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            if attempt >= attempts:
                raise ValueError(f"LLM payload validation failed: {last_error}") from exc
    raise ValueError("LLM payload inference exhausted without result")


def _coerce_schema_value(value: Any, schema: Mapping[str, Any], field_name: str, source: str) -> Any:
    expected_type = schema.get("type")
    if not isinstance(expected_type, str):
        return value
    if expected_type == "string":
        if isinstance(value, str):
            return value
        return str(value)
    if expected_type == "integer":
        if isinstance(value, bool):
            raise ValueError(f"{source}: field {field_name!r} must be integer")
        if isinstance(value, int):
            return value
        return int(value)
    if expected_type == "number":
        if isinstance(value, bool):
            raise ValueError(f"{source}: field {field_name!r} must be number")
        if isinstance(value, (int, float)):
            return value
        return float(value)
    if expected_type == "boolean":
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lower = value.lower().strip()
            if lower in {"true", "yes", "1", "on"}:
                return True
            if lower in {"false", "no", "0", "off"}:
                return False
        raise ValueError(f"{source}: field {field_name!r} must be boolean")
    return value


def _infer_field_value_from_intent(
    field_name: str,
    field_schema: Mapping[str, Any],
    field_hints: Mapping[str, Any],
    intent_text: str,
) -> Any:
    expected_type = str(field_schema.get("type", "string"))
    if expected_type == "boolean":
        value = _extract_boolean_value(intent_text, field_hints)
    elif expected_type == "integer":
        value = _extract_integer_value(intent_text, field_hints)
    elif expected_type == "number":
        value = _extract_number_value(intent_text, field_hints)
    elif expected_type == "array":
        item_schema = field_schema.get("items", {})
        if not isinstance(item_schema, Mapping):
            item_schema = {}
        value = _extract_list_value(intent_text, field_hints, item_schema)
    elif expected_type == "string":
        value = _extract_string_value(field_name, intent_text, field_hints)
    else:
        value = field_hints.get("default")
    if value is None:
        return None
    return _coerce_schema_value(value, field_schema, field_name, "build_execution_payload")


def _infer_payload_from_schema(
    action: ProviderAction,
    intent_text: str,
    *,
    hints: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    properties = action.input_schema.get("properties", {})
    if not isinstance(properties, Mapping):
        return payload

    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, Mapping):
            continue
        field_hints = action.arg_hints.get(field_name, {})
        if not isinstance(field_hints, Mapping):
            field_hints = {}
        value = _infer_field_value_from_intent(field_name, field_schema, field_hints, intent_text)
        if value is not None:
            payload[field_name] = value
    return payload


def build_execution_payload_with_explain(
    action: ProviderAction,
    intent_text: str,
    *,
    provided_payload: Mapping[str, Any] | None = None,
    hints: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    mode = _resolve_inference_mode(hints)
    provided_fields = sorted(list(provided_payload.keys())) if isinstance(provided_payload, Mapping) else []
    llm_backend = "none"
    llm_attempts = 0
    llm_repairs_used = 0
    inferred_fields: List[str] = []
    fill_mode = INFERENCE_MODE_SCHEMA
    if mode in {INFERENCE_MODE_LLM_STRICT, INFERENCE_MODE_HYBRID}:
        llm_backend = os.getenv("MCPD_LLM_ENDPOINT", "").strip() or "unconfigured"
        try:
            llm_result = _infer_payload_with_llm(
                action,
                intent_text,
                provided_payload=provided_payload,
                hints=hints,
                context=context,
            )
            validated = dict(llm_result["validated"])
            llm_attempts = int(llm_result["attempts"])
            llm_repairs_used = int(llm_result["repairs_used"])
            fill_mode = INFERENCE_MODE_LLM_STRICT
            _log_structured(
                logging.INFO,
                "payload_fill_mode",
                action_name=action.action_name,
                capability_domain=action.capability_domain,
                fill_mode=fill_mode,
                inferred_fields=sorted(validated.keys()),
                provided_fields=provided_fields,
                llm_backend=llm_backend,
                llm_attempts=llm_attempts,
                llm_repairs_used=llm_repairs_used,
                used_planner_payload_slots=False,
            )
            return validated, {
                "fill_mode": fill_mode,
                "inferred_fields": sorted(validated.keys()),
                "provided_fields": provided_fields,
                "llm_backend": llm_backend,
                "llm_attempts": llm_attempts,
                "llm_repairs_used": llm_repairs_used,
            }
        except Exception as exc:  # noqa: BLE001
            if mode == INFERENCE_MODE_LLM_STRICT:
                raise
            _log_structured(
                logging.WARNING,
                "payload_fill_mode_fallback",
                action_name=action.action_name,
                capability_domain=action.capability_domain,
                fill_mode=INFERENCE_MODE_SCHEMA,
                llm_backend=llm_backend,
                llm_error=str(exc),
            )

    defaults = _infer_payload_from_schema(action, intent_text, hints=hints)
    inferred_fields = sorted(defaults.keys())
    payload = fill_action_payload(action, provided_payload, defaults=defaults)
    validated = validate_action_payload(action, payload)
    _log_structured(
        logging.INFO,
        "payload_fill_mode",
        action_name=action.action_name,
        capability_domain=action.capability_domain,
        fill_mode=INFERENCE_MODE_SCHEMA,
        inferred_fields=inferred_fields,
        provided_fields=provided_fields,
        llm_backend=llm_backend,
        llm_attempts=llm_attempts,
        llm_repairs_used=llm_repairs_used,
        used_planner_payload_slots=False,
    )
    return validated, {
        "fill_mode": INFERENCE_MODE_SCHEMA,
        "inferred_fields": inferred_fields,
        "provided_fields": provided_fields,
        "llm_backend": llm_backend,
        "llm_attempts": llm_attempts,
        "llm_repairs_used": llm_repairs_used,
    }


def build_execution_payload(
    action: ProviderAction,
    intent_text: str,
    *,
    provided_payload: Mapping[str, Any] | None = None,
    hints: Mapping[str, Any] | None = None,
    context: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    payload, _explain = build_execution_payload_with_explain(
        action,
        intent_text,
        provided_payload=provided_payload,
        hints=hints,
        context=context,
    )
    return payload
