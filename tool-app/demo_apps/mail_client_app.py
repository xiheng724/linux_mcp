#!/usr/bin/env python3
"""Semantic wrappers for the Thunderbird mail client."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

TOOL_APP_DIR = Path(__file__).resolve().parent.parent
if str(TOOL_APP_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_APP_DIR))

from demo_rpc import parse_args, serve
from real_app_support import (
    find_executable,
    optional_string,
    require_gui_session,
    spawn_detached,
    thunderbird_compose_value,
)


def open_inbox(payload: Dict[str, Any]) -> Dict[str, Any]:
    del payload
    require_gui_session()
    thunderbird = find_executable("thunderbird")
    proc = spawn_detached([thunderbird, "-mail"])
    return {"opened": True, "backend": "thunderbird", "pid": proc.pid}


def compose_email(payload: Dict[str, Any]) -> Dict[str, Any]:
    require_gui_session()
    thunderbird = find_executable("thunderbird")
    fields: List[str] = []
    for name in ("to", "cc", "bcc", "subject", "body"):
        value = optional_string(payload, name)
        if value:
            fields.append(f"{name}={thunderbird_compose_value(value)}")
    attachment_path = optional_string(payload, "attachment_path")
    if attachment_path:
        attachment = Path(attachment_path).expanduser().resolve()
        if not attachment.exists():
            raise ValueError(f"attachment_path does not exist: {attachment}")
        fields.append(f"attachment={thunderbird_compose_value(attachment.as_uri())}")
    if not fields:
        raise ValueError("compose_email requires at least one non-empty field")
    compose_spec = ",".join(fields)
    proc = spawn_detached([thunderbird, "-compose", compose_spec])
    return {"opened": True, "backend": "thunderbird", "compose_spec": compose_spec, "pid": proc.pid}


def main() -> int:
    args = parse_args()
    return serve(
        args.manifest,
        {
            "open_inbox": open_inbox,
            "compose_email": compose_email,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
