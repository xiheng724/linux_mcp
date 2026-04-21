#!/usr/bin/env python3
"""mcpd configuration loader.

The daemon is deliberately tiny, so this only handles transport policy.
Search order:

  1. Path in $LINUX_MCP_CONFIG (operator override).
  2. /etc/linux-mcp/mcpd.toml (system default location).
  3. Built-in defaults — preserves legacy behaviour (path UDS under
     /tmp/linux-mcp-apps/ only, abstract namespace disabled).

Example /etc/linux-mcp/mcpd.toml:

    [transports.uds_rpc]
    allow_prefixes = ["/tmp/linux-mcp-apps/", "/run/linux-mcp/"]

    [transports.uds_abstract]
    allow_name_pattern = "^linux-mcp/[a-z0-9_.-]+$"
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

try:
    from transport import DEFAULT_TRANSPORT_CONFIG, TransportConfig
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from .transport import DEFAULT_TRANSPORT_CONFIG, TransportConfig

CONFIG_ENV = "LINUX_MCP_CONFIG"
DEFAULT_CONFIG_PATH = "/etc/linux-mcp/mcpd.toml"


def _coerce_str_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{field} must be a list of strings, got {value!r}")
    return list(value)


def _load_transport_config_from_toml(data: Dict[str, Any]) -> TransportConfig:
    cfg = TransportConfig()
    transports = data.get("transports", {})
    if not isinstance(transports, dict):
        raise ValueError("[transports] must be a table")

    uds = transports.get("uds_rpc")
    if isinstance(uds, dict):
        prefixes = uds.get("allow_prefixes")
        if prefixes is not None:
            cfg.uds_rpc_allow_prefixes = _coerce_str_list(
                prefixes, "transports.uds_rpc.allow_prefixes"
            )

    abstract = transports.get("uds_abstract")
    if isinstance(abstract, dict):
        pattern = abstract.get("allow_name_pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                raise ValueError("transports.uds_abstract.allow_name_pattern must be a string")
            cfg.uds_abstract_allow_name_pattern = pattern

    return cfg


def _resolve_config_path() -> Path | None:
    env_val = os.environ.get(CONFIG_ENV, "").strip()
    if env_val:
        return Path(env_val)
    default = Path(DEFAULT_CONFIG_PATH)
    return default if default.is_file() else None


def load_transport_config() -> TransportConfig:
    path = _resolve_config_path()
    if path is None:
        return TransportConfig(
            uds_rpc_allow_prefixes=list(DEFAULT_TRANSPORT_CONFIG.uds_rpc_allow_prefixes),
            uds_abstract_allow_name_pattern=
            DEFAULT_TRANSPORT_CONFIG.uds_abstract_allow_name_pattern,
        )
    if tomllib is None:
        raise RuntimeError(
            "Python tomllib is unavailable (need Python 3.11+) but a config "
            f"file was requested at {path}"
        )
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except FileNotFoundError:
        raise RuntimeError(f"mcpd config not found: {path}")
    return _load_transport_config_from_toml(data)
