#!/usr/bin/env python3
"""Shared manifest loading for mcpd runtime and kernel reconciliation.

This module is the source of truth for the *logical* side of the two-layer
tool identity model. It parses tool-app/manifests/*.json and produces, per
tool:

  manifest_hash        Logical tool identity. SHA-256 over the fields in
                       SEMANTIC_HASH_FIELDS (name, description, schema,
                       risk_tags, operation, ...). What llm-app and the
                       kernel see as "this tool's semantic identity".

  binding_fingerprint  Runtime routing identity. SHA-256 over transport +
                       endpoint only. Drives reconcile actions but is NOT
                       part of logical identity — a host move must not
                       change the tool's identity as seen by consumers.

  script_digest        SHA-256 of the manifest-declared demo_entrypoint
                       script, computed at load time. Empty for native
                       binary tools. This is an INPUT to the serving
                       identity computed by mcpd/server.py:
                       _compute_serving_identity; it is not itself an
                       identity.

  script_path          Absolute filesystem path of demo_entrypoint, kept
                       so the probe can re-read the script at tool:exec
                       time — catching a script swap between daemon
                       startups that would otherwise stay trusted.

The *serving* side of the two-layer model (observation of /proc/<pid>/exe,
TOFU pinning in the kernel, composite digest strategy) lives in
mcpd/server.py. See ServingIdentity / _compute_serving_identity there and
the kernel comment block on `struct kernel_mcp_tool` for how the two
layers meet at the netlink boundary.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from schema_utils import ensure_int, ensure_non_empty_str
    from risk import normalize_risk_tags, risk_flags_from_tags
    from transport import TransportError, validate_endpoint
    from config import load_transport_config
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .schema_utils import ensure_int, ensure_non_empty_str
    from .risk import normalize_risk_tags, risk_flags_from_tags
    from .transport import TransportError, validate_endpoint
    from .config import load_transport_config

# Cached transport policy. Loaded on first manifest parse so tests can set
# $LINUX_MCP_CONFIG before importing. Accessible via reload_transport_config()
# if an operator needs a hot reload (not wired to a signal yet).
_transport_cfg = None


def reload_transport_config() -> None:
    global _transport_cfg
    _transport_cfg = load_transport_config()


def _get_transport_cfg():
    global _transport_cfg
    if _transport_cfg is None:
        _transport_cfg = load_transport_config()
    return _transport_cfg

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST_DIR = ROOT_DIR / "tool-app" / "manifests"
SEMANTIC_HASH_FIELDS = (
    "tool_id",
    "name",
    "app_id",
    "app_name",
    "risk_tags",
    "description",
    "input_schema",
    "examples",
    "path_semantics",
    "approval_policy",
    # `operation` is the RPC method actually invoked on the backend.
    # Changing it silently retargets the tool to different code paths
    # with potentially different side effects, so it IS part of
    # semantic identity — moving it out of binding_fingerprint keeps
    # planners, approvals, and kernel hash checks honest when a
    # manifest edit repoints the RPC. (transport/endpoint remain
    # binding-only because they only move where the backend lives.)
    "operation",
)


@dataclass(frozen=True)
class ToolManifest:
    tool_id: int
    name: str
    app_id: str
    app_name: str
    risk_tags: List[str]
    risk_flags: int
    description: str
    input_schema: Dict[str, Any]
    examples: List[Any]
    path_semantics: Dict[str, str]
    approval_policy: Dict[str, Any]
    transport: str
    endpoint: str
    operation: str
    timeout_ms: int
    # Semantic identity, exposed to llm-app as the canonical tool hash.
    # Intentionally excludes transport/endpoint so an operator can move
    # a backend between hosts without the tool looking like a different
    # tool to planners or to the kernel's exported identity. `operation`
    # IS part of semantic identity — see SEMANTIC_HASH_FIELDS.
    manifest_hash: str
    # Runtime routing fingerprint. Separate from manifest_hash because
    # binding changes must force a kernel-side unregister+register to
    # clear the TOFU binary_hash slot, but they must NOT make the tool
    # look semantically different to consumers. See server._load_runtime_registry
    # for how the two fingerprints drive distinct reconciliation paths.
    binding_fingerprint: str
    # SHA-256 of the demo entry script on disk, computed at manifest
    # load time. Empty when demo_entrypoint is missing, not a Python
    # file, or unreadable. Used by the probe to build a composite
    # binary_hash for interpreter-hosted backends so swapping the
    # script file invalidates the kernel's TOFU pin on next restart —
    # without this, hashing /proc/<pid>/exe alone pins only the
    # interpreter (python3) and misses application-code swaps.
    script_digest: str
    # Absolute on-disk path of the demo entry script. Empty when not
    # applicable. Held alongside `script_digest` so the probe can
    # re-hash the script at probe time without reloading manifests;
    # otherwise a script swap between mcpd startups would stay
    # trusted until the daemon is bounced.
    script_path: str


@dataclass(frozen=True)
class AppManifest:
    app_id: str
    app_name: str
    transport: str
    endpoint: str
    tools: List[ToolManifest]
    source: str


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _semantic_hash(tool: Dict[str, Any], path: Path) -> str:
    semantic: Dict[str, Any] = {}
    for field in SEMANTIC_HASH_FIELDS:
        if field not in tool:
            raise ValueError(f"{path}: missing semantic hash field '{field}'")
        semantic[field] = tool[field]
    # Full 64-character SHA-256 hex digest (256-bit security, no truncation).
    # Birthday-bound collision resistance requires the full output; truncating
    # to 8 chars (32 bits) would allow collisions after ~65k tool registrations.
    return hashlib.sha256(_canonical_json_bytes(semantic)).hexdigest()


def _ensure_non_empty_str_path(name: str, value: Any, path: Path) -> str:
    try:
        return ensure_non_empty_str(name, value)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc


def _ensure_rel_tool_path(name: str, value: Any, path: Path) -> str:
    text = _ensure_non_empty_str_path(name, value, path)
    if text.startswith("/"):
        raise ValueError(f"{path}: {name} must be relative to repo root")
    return text


def _compute_script_digest(demo_entrypoint: str | None, manifest_path: Path) -> Tuple[str, str]:
    """Return (sha256_hex, resolved_path) for the on-disk script file
    referenced by `demo_entrypoint`. Digest is "" if the entry doesn't
    look like a Python script or cannot be read; path is the absolute
    resolved path when `demo_entrypoint` is a .py file (kept even if
    the current read fails, so probe-time refresh can still find it).

    Called once per manifest at load time so the probe can present a
    composite hash (interpreter+script) when the backend is
    interpreter-hosted. The resolved path is returned so the probe
    can re-hash the script at call time without reloading manifests."""
    if not demo_entrypoint or not isinstance(demo_entrypoint, str):
        return "", ""
    if not demo_entrypoint.endswith(".py"):
        # Native binaries don't need this: /proc/<pid>/exe already
        # identifies the running code.
        return "", ""
    repo_root = manifest_path.resolve().parent.parent.parent
    script_path = (repo_root / demo_entrypoint).resolve()
    try:
        h = hashlib.sha256()
        with open(script_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest(), str(script_path)
    except OSError:
        return "", str(script_path)


def _load_tool(
    raw: Dict[str, Any],
    *,
    app_id: str,
    app_name: str,
    transport: str,
    endpoint: str,
    script_digest: str,
    script_path: str,
    path: Path,
) -> ToolManifest:
    required = (
        "tool_id",
        "name",
        "risk_tags",
        "operation",
        "description",
        "input_schema",
        "examples",
    )
    for field in required:
        if field not in raw:
            raise ValueError(f"{path}: tool missing field '{field}'")

    tool_id = ensure_int("tool_id", raw["tool_id"])
    timeout_ms = ensure_int("timeout_ms", raw.get("timeout_ms", 30_000))
    if timeout_ms <= 0:
        raise ValueError(f"{path}: timeout_ms must be positive")

    name = ensure_non_empty_str("name", raw["name"])
    risk_tags = normalize_risk_tags(raw["risk_tags"], source=str(path))
    operation = ensure_non_empty_str("operation", raw["operation"])
    description = ensure_non_empty_str("description", raw["description"])
    input_schema = raw["input_schema"]
    examples = raw["examples"]
    if not isinstance(input_schema, dict):
        raise ValueError(f"{path}: input_schema must be object")
    if not isinstance(examples, list):
        raise ValueError(f"{path}: examples must be list")
    path_semantics = raw.get("path_semantics", {})
    approval_policy = raw.get("approval_policy", {})
    if not isinstance(path_semantics, dict):
        raise ValueError(f"{path}: path_semantics must be object")
    if not isinstance(approval_policy, dict):
        raise ValueError(f"{path}: approval_policy must be object")
    normalized_path_semantics: Dict[str, str] = {}
    for field_name, field_mode in path_semantics.items():
        if not isinstance(field_name, str) or not field_name:
            raise ValueError(f"{path}: path_semantics field names must be non-empty strings")
        if not isinstance(field_mode, str) or not field_mode:
            raise ValueError(f"{path}: path_semantics values must be non-empty strings")
        normalized_path_semantics[field_name] = field_mode
    user_confirmation = approval_policy.get("user_confirmation", {})
    if user_confirmation not in ({}, None) and not isinstance(user_confirmation, dict):
        raise ValueError(f"{path}: approval_policy.user_confirmation must be object")
    normalized_approval_policy: Dict[str, Any] = {}
    if isinstance(user_confirmation, dict) and user_confirmation:
        when = ensure_non_empty_str("when", user_confirmation.get("when", ""))
        if when not in {"always", "path_outside_repo"}:
            raise ValueError(
                f"{path}: approval_policy.user_confirmation.when must be one of always,path_outside_repo"
            )
        path_fields = user_confirmation.get("path_fields", [])
        if not isinstance(path_fields, list) or not all(
            isinstance(item, str) and item for item in path_fields
        ):
            raise ValueError(
                f"{path}: approval_policy.user_confirmation.path_fields must be list[str]"
            )
        reason = ensure_non_empty_str("reason", user_confirmation.get("reason", ""))
        normalized_approval_policy = {
            "user_confirmation": {
                "when": when,
                "path_fields": path_fields,
                "reason": reason,
            }
        }

    semantic_raw: Dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "app_id": app_id,
        "app_name": app_name,
        "risk_tags": risk_tags,
        "description": description,
        "input_schema": input_schema,
        "examples": examples,
        "path_semantics": normalized_path_semantics,
        "approval_policy": normalized_approval_policy,
        "operation": operation,
    }

    # Runtime binding fingerprint. These fields describe *where* the
    # backend lives, not *what* it does. Transport/endpoint changes mean
    # we may now be talking to a different process at a different
    # address and must drop the kernel's TOFU binary_hash pin. The
    # invoked RPC method (`operation`) is NOT here — it belongs to
    # semantic identity above, so that a retarget from note_list to
    # workspace_overview changes the exported tool hash and cannot be
    # slipped in behind a hash-stable rebind.
    binding_fingerprint = hashlib.sha256(
        _canonical_json_bytes({
            "transport": transport,
            "endpoint": endpoint,
        })
    ).hexdigest()

    return ToolManifest(
        tool_id=tool_id,
        name=name,
        app_id=app_id,
        app_name=app_name,
        risk_tags=risk_tags,
        risk_flags=risk_flags_from_tags(risk_tags),
        description=description,
        input_schema=input_schema,
        examples=examples,
        path_semantics=normalized_path_semantics,
        approval_policy=normalized_approval_policy,
        transport=transport,
        endpoint=endpoint,
        operation=operation,
        timeout_ms=timeout_ms,
        manifest_hash=_semantic_hash(semantic_raw, path),
        binding_fingerprint=binding_fingerprint,
        script_digest=script_digest,
        script_path=script_path,
    )


def load_app_manifest(path: Path) -> AppManifest:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: manifest must be JSON object")

    required = ("app_id", "app_name", "transport", "endpoint", "tools")
    for field in required:
        if field not in raw:
            raise ValueError(f"{path}: missing field '{field}'")

    app_id = ensure_non_empty_str("app_id", raw["app_id"])
    app_name = ensure_non_empty_str("app_name", raw["app_name"])
    transport = ensure_non_empty_str("transport", raw["transport"])
    endpoint = ensure_non_empty_str("endpoint", raw["endpoint"])

    try:
        validate_endpoint(transport, endpoint, _get_transport_cfg())
    except TransportError as exc:
        raise ValueError(f"{path}: {exc}") from exc

    demo_entrypoint = raw.get("demo_entrypoint")
    if demo_entrypoint not in ("", None):
        _ensure_rel_tool_path("demo_entrypoint", demo_entrypoint, path)

    # Pre-compute once per app manifest: all tools in the same manifest
    # share the same demo_entrypoint and therefore the same script
    # digest. Done here (not inside _load_tool) to avoid re-hashing the
    # script file per tool in apps with many tools.
    script_digest, script_path = _compute_script_digest(
        demo_entrypoint if isinstance(demo_entrypoint, str) else "",
        path,
    )

    tools_raw = raw["tools"]
    if not isinstance(tools_raw, list) or not tools_raw:
        raise ValueError(f"{path}: tools must be non-empty list")

    tools: List[ToolManifest] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for item in tools_raw:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: tool item must be object")
        tool = _load_tool(
            item,
            app_id=app_id,
            app_name=app_name,
            transport=transport,
            endpoint=endpoint,
            script_digest=script_digest,
            script_path=script_path,
            path=path,
        )
        if tool.tool_id in seen_ids:
            raise ValueError(f"{path}: duplicate tool_id {tool.tool_id}")
        if tool.name in seen_names:
            raise ValueError(f"{path}: duplicate tool name {tool.name!r}")
        seen_ids.add(tool.tool_id)
        seen_names.add(tool.name)
        tools.append(tool)

    return AppManifest(
        app_id=app_id,
        app_name=app_name,
        transport=transport,
        endpoint=endpoint,
        tools=tools,
        source=str(path),
    )


def load_all_manifests(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> List[AppManifest]:
    if not manifest_dir.is_dir():
        raise ValueError(f"manifest directory missing: {manifest_dir}")

    apps: List[AppManifest] = []
    seen_app_ids: set[str] = set()
    seen_tool_ids: set[int] = set()

    for path in sorted(manifest_dir.glob("*.json")):
        app = load_app_manifest(path)
        if app.app_id in seen_app_ids:
            raise ValueError(f"duplicate app_id in manifests: {app.app_id}")
        seen_app_ids.add(app.app_id)
        for tool in app.tools:
            if tool.tool_id in seen_tool_ids:
                raise ValueError(f"duplicate tool_id in manifests: {tool.tool_id}")
            seen_tool_ids.add(tool.tool_id)
        apps.append(app)

    if not apps:
        raise ValueError(f"no manifests found in {manifest_dir}")
    return apps


def load_all_tools(manifest_dir: Path = DEFAULT_MANIFEST_DIR) -> List[ToolManifest]:
    tools: List[ToolManifest] = []
    for app in load_all_manifests(manifest_dir):
        tools.extend(app.tools)
    return tools
