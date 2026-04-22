#!/usr/bin/env python3
"""Verify C/Python Generic Netlink schema constants are synchronized.

Also verifies the reason taxonomy (kernel_mcp_reasons.h ↔ client/kernel_mcp/
reasons.py) — every KERNEL_MCP_REASON_* string literal in the header must
appear with the same value as a Reason(...) instance in the Python module.
Append-only on both sides; a mismatch fails the build.
"""

from __future__ import annotations

import re
from pathlib import Path

HEADER_PATH = Path("kernel-mcp/include/uapi/linux/kernel_mcp_schema.h")
PYTHON_PATH = Path("client/kernel_mcp/schema.py")
REASONS_HEADER_PATH = Path("kernel-mcp/include/uapi/linux/kernel_mcp_reasons.h")
REASONS_PYTHON_PATH = Path("client/kernel_mcp/reasons.py")

RE_FAMILY_NAME_C = re.compile(r'^#define\s+KERNEL_MCP_GENL_FAMILY_NAME\s+"([^"]+)"')
RE_FAMILY_VER_C = re.compile(r"^#define\s+KERNEL_MCP_GENL_FAMILY_VERSION\s+(\d+)")
RE_CMD_C = re.compile(r"^#define\s+KERNEL_MCP_CMD_([A-Z0-9_]+)\s+(\d+)")
RE_ATTR_C = re.compile(r"^#define\s+KERNEL_MCP_ATTR_([A-Z0-9_]+)\s+(\d+)")

# Reason macros: `#define KERNEL_MCP_REASON_<NAME>  "<string>"`. Exclude
# KERNEL_MCP_REASON_CAT_* (category codes) from the string-map.
RE_REASON_C = re.compile(
    r'^#define\s+KERNEL_MCP_REASON_(?!CAT_)([A-Z0-9_]+)\s+"([^"]+)"'
)
# Python Reason instances: `<NAME> = Reason("<string>", ReasonCategory.<CAT>)`.
# Tolerate arbitrary whitespace and allow trailing comma / comment.
RE_REASON_PY = re.compile(
    r'^([A-Z][A-Z0-9_]+)\s*=\s*Reason\(\s*"([^"]+)"\s*,\s*ReasonCategory\.[A-Z]+\s*\)'
)

RE_FAMILY_NAME_PY = re.compile(r'^FAMILY_NAME:\s+Final\[str\]\s*=\s*"([^"]+)"')
RE_FAMILY_VER_PY = re.compile(r"^FAMILY_VERSION:\s+Final\[int\]\s*=\s*(\d+)")
RE_CMD_PY = re.compile(r'^\s*"([A-Z0-9_]+)"\s*:\s*(\d+),\s*$')


def parse_c_header(path: Path) -> tuple[str, int, dict[str, int], dict[str, int]]:
    family_name = ""
    family_ver = -1
    cmd: dict[str, int] = {}
    attr: dict[str, int] = {}

    for raw in path.read_text(encoding="utf-8").splitlines():
        if not family_name:
            m = RE_FAMILY_NAME_C.match(raw)
            if m:
                family_name = m.group(1)
                continue
        if family_ver < 0:
            m = RE_FAMILY_VER_C.match(raw)
            if m:
                family_ver = int(m.group(1))
                continue

        m = RE_CMD_C.match(raw)
        if m:
            cmd[m.group(1)] = int(m.group(2))
            continue

        m = RE_ATTR_C.match(raw)
        if m:
            attr[m.group(1)] = int(m.group(2))
            continue

    return family_name, family_ver, cmd, attr


def parse_python_schema(path: Path) -> tuple[str, int, dict[str, int], dict[str, int]]:
    family_name = ""
    family_ver = -1
    cmd: dict[str, int] = {}
    attr: dict[str, int] = {}
    section = ""

    for raw in path.read_text(encoding="utf-8").splitlines():
        if not family_name:
            m = RE_FAMILY_NAME_PY.match(raw)
            if m:
                family_name = m.group(1)
                continue
        if family_ver < 0:
            m = RE_FAMILY_VER_PY.match(raw)
            if m:
                family_ver = int(m.group(1))
                continue

        if raw.startswith("CMD:"):
            section = "cmd"
            continue
        if raw.startswith("ATTR:"):
            section = "attr"
            continue
        if raw.startswith("}"):
            section = ""
            continue

        m = RE_CMD_PY.match(raw)
        if m:
            if section == "cmd":
                cmd[m.group(1)] = int(m.group(2))
            elif section == "attr":
                attr[m.group(1)] = int(m.group(2))

    return family_name, family_ver, cmd, attr


def parse_reasons_header(path: Path) -> dict[str, str]:
    """Parse KERNEL_MCP_REASON_<NAME> "string" macros, skipping category codes.
    Returns {SYMBOL_WITHOUT_PREFIX: wire_string}.
    """
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = RE_REASON_C.match(raw)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def parse_reasons_python(path: Path) -> dict[str, str]:
    """Parse `<NAME> = Reason("string", ReasonCategory.<CAT>)` assignments.
    Returns {SYMBOL: wire_string}.
    """
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        m = RE_REASON_PY.match(raw)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def main() -> int:
    family_name_c, family_ver_c, cmd_c, attr_c = parse_c_header(HEADER_PATH)
    family_name_py, family_ver_py, cmd_py, attr_py = parse_python_schema(PYTHON_PATH)

    assert family_name_c == family_name_py, (
        f"family name mismatch: C={family_name_c}, PY={family_name_py}"
    )
    assert family_ver_c == family_ver_py, (
        f"family version mismatch: C={family_ver_c}, PY={family_ver_py}"
    )
    assert cmd_c == cmd_py, f"command mismatch: C={cmd_c}, PY={cmd_py}"
    assert attr_c == attr_py, f"attribute mismatch: C={attr_c}, PY={attr_py}"

    reasons_c = parse_reasons_header(REASONS_HEADER_PATH)
    reasons_py = parse_reasons_python(REASONS_PYTHON_PATH)
    assert reasons_c == reasons_py, (
        "reason taxonomy mismatch:\n"
        f"  only_in_C  = {sorted(set(reasons_c) - set(reasons_py))}\n"
        f"  only_in_PY = {sorted(set(reasons_py) - set(reasons_c))}\n"
        f"  value_diff = "
        f"{sorted((k, reasons_c[k], reasons_py[k]) for k in set(reasons_c) & set(reasons_py) if reasons_c[k] != reasons_py[k])}"
    )

    print("Schema sync OK")
    print(f"family={family_name_c} version={family_ver_c}")
    print(f"commands={len(cmd_c)} attrs={len(attr_c)} reasons={len(reasons_c)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

