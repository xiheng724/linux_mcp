#!/usr/bin/env python3
"""Transport validators and dialers for mcpd.

Each supported transport registers a pair:
  - validator(endpoint, cfg) — raises TransportError on an endpoint that the
    current TransportConfig does not allow.
  - dialer(endpoint, timeout_s) — returns a connected AF_UNIX / AF_VSOCK
    socket to the backend.

manifest_loader calls validate_endpoint() at load time so malformed or
disallowed manifests are rejected before ever reaching the kernel; server
calls dial() at tool:exec time for the actual RPC.

To add a new transport: implement validator + dialer, then
register_transport("my_transport", validator, dialer) at import time.
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Callable, Dict, List


@dataclass
class TransportConfig:
    """Operator-configurable transport policy.

    Kept small and flat so config.py can populate it from TOML without
    needing a schema migration when we add a field.
    """
    # uds_rpc: path-based AF_UNIX. Defaults preserve legacy behaviour.
    uds_rpc_allow_prefixes: List[str] = field(
        default_factory=lambda: ["/tmp/linux-mcp-apps/"]
    )
    # uds_abstract: Linux abstract namespace. Disabled when empty so a
    # missing config means "legacy behaviour" rather than "anyone can bind".
    uds_abstract_allow_name_pattern: str = ""


DEFAULT_TRANSPORT_CONFIG = TransportConfig()


class TransportError(ValueError):
    pass


Validator = Callable[[str, TransportConfig], None]
Dialer = Callable[[str, float], socket.socket]

_VALIDATORS: Dict[str, Validator] = {}
_DIALERS: Dict[str, Dialer] = {}


def register_transport(name: str, validator: Validator, dialer: Dialer) -> None:
    _VALIDATORS[name] = validator
    _DIALERS[name] = dialer


def supported_transports() -> List[str]:
    return sorted(_VALIDATORS.keys())


def validate_endpoint(transport: str, endpoint: str, cfg: TransportConfig) -> None:
    validator = _VALIDATORS.get(transport)
    if validator is None:
        raise TransportError(
            f"unsupported transport {transport!r}; known: {supported_transports()}"
        )
    if not endpoint:
        raise TransportError("endpoint must be non-empty")
    validator(endpoint, cfg)


def dial(transport: str, endpoint: str, timeout_s: float) -> socket.socket:
    dialer = _DIALERS.get(transport)
    if dialer is None:
        raise TransportError(f"unsupported transport {transport!r}")
    return dialer(endpoint, timeout_s)


# ---------------------------------------------------------------------------
# uds_rpc — path-based AF_UNIX
# ---------------------------------------------------------------------------
def _validate_uds_rpc(endpoint: str, cfg: TransportConfig) -> None:
    prefixes = cfg.uds_rpc_allow_prefixes
    if not prefixes:
        raise TransportError("uds_rpc is disabled (no allow_prefixes configured)")
    if not any(endpoint.startswith(p) for p in prefixes):
        raise TransportError(
            f"uds_rpc endpoint {endpoint!r} does not start with any allow prefix: {prefixes}"
        )


def _dial_uds_rpc(endpoint: str, timeout_s: float) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_s)
        sock.connect(endpoint)
    except Exception:
        sock.close()
        raise
    return sock


# ---------------------------------------------------------------------------
# uds_abstract — Linux abstract namespace (\0name). Same AF_UNIX, so
# SO_PEERCRED / binary_hash TOFU still works.
# ---------------------------------------------------------------------------
def _validate_uds_abstract(endpoint: str, cfg: TransportConfig) -> None:
    pattern = cfg.uds_abstract_allow_name_pattern
    if not pattern:
        raise TransportError(
            "uds_abstract is disabled (no allow_name_pattern configured)"
        )
    if endpoint.startswith("\x00"):
        raise TransportError(
            "uds_abstract endpoint must be the bare name without leading NUL"
        )
    if not re.fullmatch(pattern, endpoint):
        raise TransportError(
            f"uds_abstract endpoint {endpoint!r} does not match {pattern!r}"
        )


def _dial_uds_abstract(endpoint: str, timeout_s: float) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout_s)
        sock.connect(b"\x00" + endpoint.encode("utf-8"))
    except Exception:
        sock.close()
        raise
    return sock


# ---------------------------------------------------------------------------
# vsock_rpc — reserved name for VM/container attestor use cases. Not wired
# up this round; validator refuses so manifests cannot silently reach an
# unimplemented dialer.
# ---------------------------------------------------------------------------
def _validate_vsock_rpc(endpoint: str, cfg: TransportConfig) -> None:
    (endpoint, cfg)
    raise TransportError(
        "vsock_rpc is reserved but not implemented; follow-up work required"
    )


def _dial_vsock_rpc(endpoint: str, timeout_s: float) -> socket.socket:
    (endpoint, timeout_s)
    raise NotImplementedError("vsock_rpc dialer not implemented")


register_transport("uds_rpc", _validate_uds_rpc, _dial_uds_rpc)
register_transport("uds_abstract", _validate_uds_abstract, _dial_uds_abstract)
register_transport("vsock_rpc", _validate_vsock_rpc, _dial_vsock_rpc)
