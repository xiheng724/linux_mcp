#!/usr/bin/env python3
"""mcpd configuration loader.

The daemon is deliberately tiny, so this handles transport policy and
a small security section. Search order:

  1. Path in $LINUX_MCP_CONFIG (operator override).
  2. /etc/linux-mcp/mcpd.toml (system default location).
  3. Built-in defaults (path UDS under /tmp/linux-mcp-apps/ only,
     abstract namespace disabled).

Example /etc/linux-mcp/mcpd.toml:

    [transports.uds_rpc]
    allow_prefixes = ["/tmp/linux-mcp-apps/", "/run/linux-mcp/"]

    [transports.uds_abstract]
    allow_name_pattern = "^linux-mcp/[a-z0-9_.-]+$"
"""
from __future__ import annotations

import os
from dataclasses import dataclass
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
TRUST_SUDO_UID_ENV = "LINUX_MCP_TRUST_SUDO_UID"


class ConfigError(RuntimeError):
    """Raised when mcpd cannot resolve a safe configuration.

    The daemon must refuse to start rather than fall back to a default
    that silently mismatches the runtime model — e.g. mcpd running as
    root with an implicit allowlist of {0} while tool backends run as
    a normal user. Catching this in main() and exiting non-zero is the
    whole point.
    """


@dataclass
class SecurityConfig:
    """Security-sensitive policy knobs.

    allowed_backend_uids:
      - Tuple of UIDs permitted to serve as tool backends, enforced via
        SO_PEERCRED on both the probe dial and the exec dial.
      - `None` sentinel means "resolve at load time". Resolution depends
        on euid and environment — see _resolve_security_defaults.
    """
    allowed_backend_uids: tuple[int, ...] | None = None


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


def _load_security_config_from_toml(data: Dict[str, Any]) -> SecurityConfig:
    cfg = SecurityConfig()
    section = data.get("security")
    if section is None:
        _resolve_security_defaults(cfg)
        return cfg
    if not isinstance(section, dict):
        raise ValueError("[security] must be a table")
    uids = section.get("allowed_backend_uids")
    if uids is not None:
        if not isinstance(uids, list) or not all(
            isinstance(u, int) and not isinstance(u, bool) and u >= 0 for u in uids
        ):
            raise ValueError(
                "security.allowed_backend_uids must be a list of non-negative "
                f"integers, got {uids!r}"
            )
        cfg.allowed_backend_uids = tuple(uids)
    _resolve_security_defaults(cfg)
    return cfg


def _resolve_security_defaults(cfg: SecurityConfig) -> None:
    """Fill in runtime-sensitive defaults that can't be hardcoded in the
    dataclass.

    Decision matrix for `allowed_backend_uids` when not explicitly
    configured:

      - euid != 0 (unprivileged mcpd): default to `(euid,)`. Legacy
        mode where mcpd and backends share a uid; trusting self is safe.

      - euid == 0 (privileged mcpd): we CANNOT safely default to `(0,)`
        because the intended deployment model has tool backends running
        as a non-root service user. Silently trusting only root would
        reject every real backend and leave every tool's binary_hash
        unpinned — a security-significant state that used to be masked
        by a sysfs empty string. Two ways out:

          1. Operator configures [security].allowed_backend_uids in the
             TOML — that always wins (handled above the dataclass fill).
          2. Demo/launcher path sets LINUX_MCP_TRUST_SUDO_UID=1 to opt
             in to trusting $SUDO_UID. That keeps "sudo bash scripts/
             run_mcpd.sh" ergonomic without making the trust implicit.

        Anything else is a ConfigError. The old behavior (auto-trust
        $SUDO_UID without opt-in) was moved out on purpose: decisions
        about who mcpd trusts should live in the daemon's config/env,
        not in whichever launcher script happened to exec it.
    """
    if cfg.allowed_backend_uids is not None:
        return

    euid = os.geteuid()
    if euid != 0:
        cfg.allowed_backend_uids = (euid,)
        return

    if os.environ.get(TRUST_SUDO_UID_ENV, "").strip() in ("1", "true", "yes"):
        sudo_uid_raw = os.environ.get("SUDO_UID", "").strip()
        try:
            sudo_uid = int(sudo_uid_raw) if sudo_uid_raw else -1
        except ValueError:
            sudo_uid = -1
        if sudo_uid > 0:
            cfg.allowed_backend_uids = (0, sudo_uid)
            return

    raise ConfigError(
        "mcpd runs as root but security.allowed_backend_uids is not "
        "configured. Refusing to start with the implicit allowlist "
        "{0} because that silently rejects every non-root tool "
        "backend and leaves binary_hash unpinned. Fix one of:\n"
        f"  (a) set [security].allowed_backend_uids in ${CONFIG_ENV} "
        f"or {DEFAULT_CONFIG_PATH};\n"
        f"  (b) set {TRUST_SUDO_UID_ENV}=1 to trust $SUDO_UID (demo "
        "launcher path)."
    )


def _resolve_config_path() -> Path | None:
    env_val = os.environ.get(CONFIG_ENV, "").strip()
    if env_val:
        return Path(env_val)
    default = Path(DEFAULT_CONFIG_PATH)
    return default if default.is_file() else None


def _load_toml_if_any() -> Dict[str, Any] | None:
    path = _resolve_config_path()
    if path is None:
        return None
    if tomllib is None:
        raise RuntimeError(
            "Python tomllib is unavailable (need Python 3.11+) but a config "
            f"file was requested at {path}"
        )
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        raise RuntimeError(f"mcpd config not found: {path}")


def load_transport_config() -> TransportConfig:
    data = _load_toml_if_any()
    if data is None:
        return TransportConfig(
            uds_rpc_allow_prefixes=list(DEFAULT_TRANSPORT_CONFIG.uds_rpc_allow_prefixes),
            uds_abstract_allow_name_pattern=
            DEFAULT_TRANSPORT_CONFIG.uds_abstract_allow_name_pattern,
        )
    return _load_transport_config_from_toml(data)


def load_security_config() -> SecurityConfig:
    data = _load_toml_if_any()
    if data is None:
        cfg = SecurityConfig()
        _resolve_security_defaults(cfg)
        return cfg
    return _load_security_config_from_toml(data)
