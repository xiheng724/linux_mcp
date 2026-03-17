import json
import logging
import re
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


def build_execution_payload(
    action: ProviderAction,
    intent_text: str,
    *,
    provided_payload: Mapping[str, Any] | None = None,
    hints: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    defaults = _infer_payload_from_schema(action, intent_text, hints=hints)
    payload = fill_action_payload(action, provided_payload, defaults=defaults)
    validated = validate_action_payload(action, payload)
    _log_structured(
        logging.INFO,
        "payload_fill_mode",
        action_name=action.action_name,
        capability_domain=action.capability_domain,
        fill_mode="schema_arg_hints",
        inferred_fields=sorted(defaults.keys()),
        provided_fields=sorted(list(provided_payload.keys())) if isinstance(provided_payload, Mapping) else [],
        used_planner_payload_slots=False,
    )
    return validated
