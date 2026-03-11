#!/usr/bin/env python3
"""Kernel MCP Generic Netlink client (persistent socket, no subprocess)."""

from __future__ import annotations

import os
import socket
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import sys

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from client.kernel_mcp.schema import ATTR, CMD, FAMILY_NAME, FAMILY_VERSION

# Netlink base constants.
NETLINK_GENERIC = 16
NLM_F_REQUEST = 0x01
NLM_F_MULTI = 0x02
NLM_F_ACK = 0x04

NLMSG_NOOP = 0x01
NLMSG_ERROR = 0x02
NLMSG_DONE = 0x03

# Generic Netlink control family constants.
GENL_ID_CTRL = 0x10
CTRL_CMD_NEWFAMILY = 1
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

KERNEL_MCP_DECISION_MAP = {
    1: "ALLOW",
    2: "DENY",
    3: "DEFER",
}

NLMSG_HDR_FMT = "=IHHII"
GENL_HDR_FMT = "=BBH"
NLA_HDR_FMT = "=HH"
NLMSG_HDR_LEN = struct.calcsize(NLMSG_HDR_FMT)
GENL_HDR_LEN = struct.calcsize(GENL_HDR_FMT)
NLA_HDR_LEN = struct.calcsize(NLA_HDR_FMT)


def _align4(length: int) -> int:
    return (length + 3) & ~3


def _pack_attr(attr_type: int, data: bytes) -> bytes:
    raw_len = NLA_HDR_LEN + len(data)
    out = bytearray(_align4(raw_len))
    struct.pack_into(NLA_HDR_FMT, out, 0, raw_len, attr_type)
    out[NLA_HDR_LEN:NLA_HDR_LEN + len(data)] = data
    return bytes(out)


def _parse_attrs(payload: bytes) -> Dict[int, List[bytes]]:
    attrs: Dict[int, List[bytes]] = {}
    offset = 0
    total = len(payload)
    while offset + NLA_HDR_LEN <= total:
        nla_len, nla_type = struct.unpack_from(NLA_HDR_FMT, payload, offset)
        if nla_len < NLA_HDR_LEN:
            raise RuntimeError(f"invalid nla_len: {nla_len}")
        end = offset + nla_len
        if end > total:
            raise RuntimeError("malformed netlink attribute payload")
        value = payload[offset + NLA_HDR_LEN:end]
        attrs.setdefault(nla_type, []).append(value)
        offset += _align4(nla_len)
    return attrs


def _attr_first(attrs: Dict[int, List[bytes]], key: int) -> bytes:
    values = attrs.get(key, [])
    if not values:
        raise RuntimeError(f"missing required netlink attr: {key}")
    return values[0]


def _attr_u32(attrs: Dict[int, List[bytes]], key: int) -> int:
    raw = _attr_first(attrs, key)
    if len(raw) < 4:
        raise RuntimeError(f"invalid u32 attr length key={key} len={len(raw)}")
    return struct.unpack_from("=I", raw, 0)[0]


def _attr_u16(attrs: Dict[int, List[bytes]], key: int) -> int:
    raw = _attr_first(attrs, key)
    if len(raw) < 2:
        raise RuntimeError(f"invalid u16 attr length key={key} len={len(raw)}")
    return struct.unpack_from("=H", raw, 0)[0]


def _attr_string(attrs: Dict[int, List[bytes]], key: int) -> str:
    raw = _attr_first(attrs, key)
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class ToolDecision:
    decision: str
    wait_ms: int
    tokens_left: int
    reason: str


class KernelMcpNetlinkClient:
    """Persistent Generic Netlink client for kernel_mcp family."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self._sock.bind((os.getpid(), 0))
        self._family_id = self._resolve_family_id()

    def close(self) -> None:
        self._sock.close()

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        if self._seq == 0:
            self._seq = 1
        return self._seq

    def _build_msg(
        self,
        *,
        msg_type: int,
        flags: int,
        seq: int,
        cmd: int,
        attrs: List[Tuple[int, bytes]],
    ) -> bytes:
        payload = bytearray(struct.pack(GENL_HDR_FMT, cmd, FAMILY_VERSION, 0))
        for attr_type, data in attrs:
            payload.extend(_pack_attr(attr_type, data))

        nlmsg_len = NLMSG_HDR_LEN + len(payload)
        header = struct.pack(NLMSG_HDR_FMT, nlmsg_len, msg_type, flags, seq, os.getpid())
        return header + payload

    def _recv_one(self, expected_seq: int) -> Tuple[int, int, bytes]:
        while True:
            raw = self._sock.recv(65535)
            offset = 0
            while offset + NLMSG_HDR_LEN <= len(raw):
                nlmsg_len, msg_type, msg_flags, msg_seq, _msg_pid = struct.unpack_from(
                    NLMSG_HDR_FMT, raw, offset
                )
                if nlmsg_len < NLMSG_HDR_LEN:
                    raise RuntimeError(f"invalid nlmsg_len: {nlmsg_len}")
                end = offset + nlmsg_len
                if end > len(raw):
                    raise RuntimeError("malformed netlink packet")
                payload = raw[offset + NLMSG_HDR_LEN:end]
                offset += _align4(nlmsg_len)

                if msg_seq != expected_seq:
                    continue
                if msg_type == NLMSG_NOOP:
                    continue
                if msg_type == NLMSG_DONE and (msg_flags & NLM_F_MULTI):
                    continue
                return msg_type, msg_flags, payload

    def _parse_ack_error(self, payload: bytes) -> int:
        if len(payload) < 4:
            raise RuntimeError("short NLMSG_ERROR payload")
        return struct.unpack_from("=i", payload, 0)[0]

    def _request(
        self,
        *,
        msg_type: int,
        cmd: int,
        attrs: List[Tuple[int, bytes]],
        need_ack: bool,
    ) -> Tuple[int, Dict[int, List[bytes]]]:
        with self._lock:
            seq = self._next_seq()
            flags = NLM_F_REQUEST | (NLM_F_ACK if need_ack else 0)
            msg = self._build_msg(msg_type=msg_type, flags=flags, seq=seq, cmd=cmd, attrs=attrs)
            self._sock.sendto(msg, (0, 0))

            resp_type, _resp_flags, resp_payload = self._recv_one(seq)
            if resp_type == NLMSG_ERROR:
                err = self._parse_ack_error(resp_payload)
                if err != 0:
                    raise RuntimeError(f"netlink NLMSG_ERROR={err} ({os.strerror(-err)})")
                return resp_type, {}

            if len(resp_payload) < GENL_HDR_LEN:
                raise RuntimeError("short generic netlink payload")
            genl_cmd, _version, _reserved = struct.unpack_from(GENL_HDR_FMT, resp_payload, 0)
            attrs_dict = _parse_attrs(resp_payload[GENL_HDR_LEN:])
            return genl_cmd, attrs_dict

    def _resolve_family_id(self) -> int:
        genl_cmd, attrs = self._request(
            msg_type=GENL_ID_CTRL,
            cmd=CTRL_CMD_GETFAMILY,
            attrs=[(CTRL_ATTR_FAMILY_NAME, FAMILY_NAME.encode("utf-8") + b"\x00")],
            need_ack=False,
        )
        # GETFAMILY request is typically answered with NEWFAMILY payload.
        if genl_cmd != CTRL_CMD_NEWFAMILY:
            raise RuntimeError(f"unexpected ctrl cmd in family reply: {genl_cmd}")
        family_id = _attr_u16(attrs, CTRL_ATTR_FAMILY_ID)
        if family_id <= 0:
            raise RuntimeError(f"invalid family_id: {family_id}")
        return family_id

    def register_agent(self, agent_id: str, *, pid: int, uid: int) -> None:
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        attrs = [
            (ATTR["AGENT_ID"], agent_id.encode("utf-8") + b"\x00"),
            (ATTR["PID"], struct.pack("=I", pid)),
            (ATTR["UID"], struct.pack("=I", uid)),
        ]
        self._request(
            msg_type=self._family_id,
            cmd=CMD["AGENT_REGISTER"],
            attrs=attrs,
            need_ack=True,
        )

    def register_tool(
        self,
        *,
        tool_id: int,
        name: str,
        perm: int,
        cost: int,
        tool_hash: str = "",
    ) -> None:
        if tool_id <= 0:
            raise ValueError("tool_id must be positive")
        if not name:
            raise ValueError("name must be non-empty")
        attrs = [
            (ATTR["TOOL_ID"], struct.pack("=I", tool_id)),
            (ATTR["TOOL_NAME"], name.encode("utf-8") + b"\x00"),
            (ATTR["TOOL_PERM"], struct.pack("=I", perm)),
            (ATTR["TOOL_COST"], struct.pack("=I", cost)),
        ]
        if tool_hash:
            attrs.append((ATTR["TOOL_HASH"], tool_hash.encode("utf-8") + b"\x00"))
        self._request(
            msg_type=self._family_id,
            cmd=CMD["TOOL_REGISTER"],
            attrs=attrs,
            need_ack=True,
        )

    def tool_request(
        self,
        *,
        req_id: int,
        agent_id: str,
        tool_id: int,
        tool_hash: str,
    ) -> ToolDecision:
        attrs = [
            (ATTR["AGENT_ID"], agent_id.encode("utf-8") + b"\x00"),
            (ATTR["TOOL_ID"], struct.pack("=I", tool_id)),
            (ATTR["REQ_ID"], struct.pack("=Q", req_id)),
        ]
        if tool_hash:
            attrs.append((ATTR["TOOL_HASH"], tool_hash.encode("utf-8") + b"\x00"))

        genl_cmd, resp_attrs = self._request(
            msg_type=self._family_id,
            cmd=CMD["TOOL_REQUEST"],
            attrs=attrs,
            need_ack=False,
        )
        if genl_cmd != CMD["TOOL_DECISION"]:
            raise RuntimeError(f"unexpected response cmd for TOOL_REQUEST: {genl_cmd}")

        decision_raw = _attr_u32(resp_attrs, ATTR["DECISION"])
        decision = KERNEL_MCP_DECISION_MAP.get(decision_raw, "UNKNOWN")
        return ToolDecision(
            decision=decision,
            wait_ms=_attr_u32(resp_attrs, ATTR["WAIT_MS"]),
            tokens_left=_attr_u32(resp_attrs, ATTR["TOKENS_LEFT"]),
            reason=_attr_string(resp_attrs, ATTR["MESSAGE"]),
        )

    def tool_complete(
        self,
        *,
        req_id: int,
        agent_id: str,
        tool_id: int,
        status_code: int,
        exec_ms: int,
    ) -> None:
        attrs = [
            (ATTR["REQ_ID"], struct.pack("=Q", req_id)),
            (ATTR["AGENT_ID"], agent_id.encode("utf-8") + b"\x00"),
            (ATTR["TOOL_ID"], struct.pack("=I", tool_id)),
            (ATTR["STATUS"], struct.pack("=I", status_code)),
            (ATTR["EXEC_MS"], struct.pack("=I", exec_ms)),
        ]
        self._request(
            msg_type=self._family_id,
            cmd=CMD["TOOL_COMPLETE"],
            attrs=attrs,
            need_ack=True,
        )
