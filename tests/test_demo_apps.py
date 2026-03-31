from __future__ import annotations

import json
import socket
import struct
import subprocess
import time
import unittest
from pathlib import Path
from typing import Any, Dict

ROOT_DIR = Path(__file__).resolve().parent.parent


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def _rpc(sock_path: str, req: Dict[str, Any]) -> Dict[str, Any]:
    payload = json.dumps(req, ensure_ascii=True).encode("utf-8")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2.0)
        conn.connect(sock_path)
        conn.sendall(struct.pack(">I", len(payload)))
        conn.sendall(payload)
        header = _recv_exact(conn, 4)
        (length,) = struct.unpack(">I", header)
        raw = _recv_exact(conn, length)
    obj = json.loads(raw.decode("utf-8"))
    if not isinstance(obj, dict):
        raise AssertionError("response must be dict")
    return obj


class DemoAppTest(unittest.TestCase):
    def test_utility_app_roundtrip(self) -> None:
        manifest = ROOT_DIR / "tool-app" / "manifests" / "04_utility_app.json"
        endpoint = "/tmp/linux-mcp-apps/utility_app.sock"
        proc = subprocess.Popen(
            ["python3", "tool-app/demo_apps/utility_app.py", "--manifest", str(manifest)],
            cwd=str(ROOT_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            resp = None
            for _ in range(30):
                if not Path(endpoint).exists():
                    time.sleep(0.1)
                    continue
                try:
                    resp = _rpc(
                        endpoint,
                        {
                            "req_id": 7,
                            "agent_id": "t1",
                            "tool_id": 1,
                            "operation": "echo",
                            "payload": {"message": "hello"},
                        },
                    )
                    break
                except ConnectionRefusedError:
                    time.sleep(0.1)
            self.assertIsNotNone(resp)
            self.assertEqual("ok", resp.get("status"))
            result = resp.get("result", {})
            self.assertEqual("hello", result.get("message"))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            if Path(endpoint).exists():
                Path(endpoint).unlink()


if __name__ == "__main__":
    unittest.main()
