#!/usr/bin/env python3
"""PySide6 GUI demo app for linux-mcp."""

from __future__ import annotations

import json
import sys
import time
import argparse
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import QObject, QThread, Qt, Signal
    from PySide6.QtWidgets import (
        QApplication,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QPushButton,
        QPlainTextEdit,
        QSplitter,
        QVBoxLayout,
        QWidget,
    )
except Exception:
    print("PySide6 not installed.", flush=True)
    print(
        "Install guide: sudo apt-get install python3-pyside6  (or)  pip install PySide6",
        flush=True,
    )
    raise SystemExit(2)

from app_logic import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    SelectorConfig,
    build_payload_for_tool,
    select_route_for_request,
)
from rpc import mcpd_call

DEFAULT_SOCK_PATH = "/tmp/mcpd.sock"
TOOLS_CACHE_TTL_S = 10.0


def _fmt_json(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False)
    except Exception:
        return str(data)


@dataclass
class ExecRequest:
    user_text: str
    agent_id: str
    sock_path: str
    selector_cfg: SelectorConfig
    cached_apps: List[Dict[str, Any]]
    cached_tools: List[Dict[str, Any]]
    cached_at: float


class ExecWorker(QObject):
    finished = Signal(dict)

    def __init__(self, req: ExecRequest) -> None:
        super().__init__()
        self.req = req

    def run(self) -> None:
        now = time.time()
        apps = self.req.cached_apps
        if not apps or (now - self.req.cached_at) > TOOLS_CACHE_TTL_S:
            resp = mcpd_call({"sys": "list_apps"}, sock_path=self.req.sock_path, timeout_s=5)
            if resp.get("status") != "ok":
                self.finished.emit(
                    {
                        "status": "error",
                        "error": resp.get("error", "list_apps failed"),
                    }
                )
                return
            raw_apps = resp.get("apps", [])
            apps = raw_apps if isinstance(raw_apps, list) else []

        try:
            (
                selected_app,
                selected_tool,
                app_selector_source,
                app_selector_reason,
                tool_selector_source,
                tool_selector_reason,
                apps,
                tools,
            ) = select_route_for_request(
                self.req.user_text,
                self.req.sock_path,
                self.req.selector_cfg,
            )
        except Exception as exc:  # noqa: BLE001
            self.finished.emit({"status": "error", "error": str(exc), "warnings": []})
            return

        app_id = selected_app.get("app_id")
        app_name = selected_app.get("app_name", "")
        if not isinstance(app_id, str) or not app_id:
            self.finished.emit({"status": "error", "error": "selected app missing app_id"})
            return

        tool_id = selected_tool.get("tool_id")
        tool_name = selected_tool.get("name", "unknown")
        tool_hash = selected_tool.get("hash", "")
        if not isinstance(tool_id, int):
            self.finished.emit({"status": "error", "error": "selected tool missing tool_id"})
            return
        if not isinstance(tool_name, str):
            tool_name = str(tool_name)
        if not isinstance(tool_hash, str):
            tool_hash = ""
        if not isinstance(app_name, str):
            app_name = str(app_name)

        req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
        payload = build_payload_for_tool(selected_tool, self.req.user_text, self.req.selector_cfg)
        exec_resp = mcpd_call(
            {
                "kind": "tool:exec",
                "req_id": req_id,
                "agent_id": self.req.agent_id,
                "app_id": app_id,
                "tool_id": tool_id,
                "tool_hash": tool_hash,
                "payload": payload,
            },
            sock_path=self.req.sock_path,
            timeout_s=10,
        )
        self.finished.emit(
            {
                "status": "ok",
                "selected": {
                    "app_id": app_id,
                    "app_name": app_name,
                    "tool_id": tool_id,
                    "tool_name": tool_name,
                    "tool_hash": tool_hash,
                },
                "app_selector_source": app_selector_source,
                "app_selector_reason": app_selector_reason,
                "tool_selector_source": tool_selector_source,
                "tool_selector_reason": tool_selector_reason,
                "warnings": [],
                "req_id": req_id,
                "response": exec_resp,
                "apps": apps,
                "tools": tools,
                "tools_at": time.time(),
            }
        )


class MainWindow(QMainWindow):
    def __init__(self, sock_path: str, agent_id: str, selector_cfg: SelectorConfig) -> None:
        super().__init__()
        self.sock_path = sock_path
        self.agent_id = agent_id
        self.selector_cfg = selector_cfg
        self.apps_cache: List[Dict[str, Any]] = []
        self.tools_cache: List[Dict[str, Any]] = []
        self.tools_cache_at: float = 0.0
        self._thread: Optional[QThread] = None
        self._worker: Optional[ExecWorker] = None

        self.setWindowTitle("Linux MCP LLM App")
        self.resize(980, 620)

        root = QWidget(self)
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        layout.addWidget(splitter)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        self.refresh_btn = QPushButton("Refresh Apps/Tools", self)
        self.tools_list = QListWidget(self)
        left_layout.addWidget(self.refresh_btn)
        left_layout.addWidget(self.tools_list)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        self.chat = QPlainTextEdit(self)
        self.chat.setReadOnly(True)
        right_layout.addWidget(QLabel("Conversation", self))
        right_layout.addWidget(self.chat)

        input_row = QHBoxLayout()
        self.input_box = QLineEdit(self)
        self.input_box.setPlaceholderText("Type message and press Enter...")
        self.send_btn = QPushButton("Send", self)
        input_row.addWidget(self.input_box)
        input_row.addWidget(self.send_btn)
        right_layout.addLayout(input_row)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([320, 660])

        self.refresh_btn.clicked.connect(self.refresh_tools)
        self.send_btn.clicked.connect(self.handle_send)
        self.input_box.returnPressed.connect(self.handle_send)

        self._append("[system] GUI started")
        self.refresh_tools()

    def _append(self, text: str) -> None:
        self.chat.appendPlainText(text)

    def _set_busy(self, busy: bool) -> None:
        self.send_btn.setEnabled(not busy)
        self.input_box.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)

    def refresh_tools(self) -> None:
        apps_resp = mcpd_call({"sys": "list_apps"}, sock_path=self.sock_path, timeout_s=5)
        if apps_resp.get("status") != "ok":
            self._append(f"[system] app refresh failed: {apps_resp.get('error', 'unknown error')}")
            return
        raw_apps = apps_resp.get("apps", [])
        if not isinstance(raw_apps, list):
            self._append("[system] app refresh failed: invalid apps list")
            return

        resp = mcpd_call({"sys": "list_tools"}, sock_path=self.sock_path, timeout_s=5)
        if resp.get("status") != "ok":
            self._append(f"[system] tool refresh failed: {resp.get('error', 'unknown error')}")
            return
        raw_tools = resp.get("tools", [])
        if not isinstance(raw_tools, list):
            self._append("[system] tool refresh failed: invalid tools list")
            return

        self.apps_cache = raw_apps
        self.tools_cache = raw_tools
        self.tools_cache_at = time.time()
        self.tools_list.clear()
        for app in self.apps_cache:
            app_id = app.get("app_id")
            app_name = app.get("app_name")
            item = QListWidgetItem(f"[APP] id={app_id}  name={app_name}")
            self.tools_list.addItem(item)
        for tool in self.tools_cache:
            tid = tool.get("tool_id")
            name = tool.get("name")
            app_name = tool.get("app_name", "-")
            desc = tool.get("description")
            item = QListWidgetItem(f"[TOOL] id={tid}  name={name}  app={app_name}\n{desc}")
            self.tools_list.addItem(item)
        self._append(
            f"[system] catalog refreshed: apps={len(self.apps_cache)} tools={len(self.tools_cache)}"
        )

    def handle_send(self) -> None:
        text = self.input_box.text().strip()
        if not text:
            return
        if self._thread is not None:
            self._append("[system] busy, please wait...")
            return

        self._append(f"You: {text}")
        self._set_busy(True)
        req = ExecRequest(
            user_text=text,
            agent_id=self.agent_id,
            sock_path=self.sock_path,
            selector_cfg=self.selector_cfg,
            cached_apps=self.apps_cache,
            cached_tools=self.tools_cache,
            cached_at=self.tools_cache_at,
        )
        self._thread = QThread(self)
        self._worker = ExecWorker(req)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_worker_done)
        self._worker.finished.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.start()

    def _on_worker_done(self, payload: Dict[str, Any]) -> None:
        self._set_busy(False)
        self.input_box.clear()
        self.input_box.setFocus()

        if payload.get("status") != "ok":
            for msg in payload.get("warnings", []):
                self._append(f"Warn: {msg}")
            self._append(f"Error: {payload.get('error', 'unknown error')}")
            self._thread = None
            self._worker = None
            return

        apps = payload.get("apps")
        if isinstance(apps, list):
            self.apps_cache = apps
        tools = payload.get("tools")
        tools_at = payload.get("tools_at")
        if isinstance(tools, list):
            self.tools_cache = tools
        if isinstance(tools_at, (int, float)):
            self.tools_cache_at = float(tools_at)

        selected = payload.get("selected", {})
        resp = payload.get("response", {})
        if not isinstance(selected, dict):
            selected = {}
        if not isinstance(resp, dict):
            resp = {"status": "error", "error": "invalid response"}
        app_name = selected.get("app_name", "unknown")
        app_id = selected.get("app_id", "?")
        tool_name = selected.get("tool_name", "unknown")
        tool_id = selected.get("tool_id", "?")
        req_id = payload.get("req_id", "?")
        app_selector_source = payload.get("app_selector_source", "unknown")
        app_selector_reason = payload.get("app_selector_reason", "")
        tool_selector_source = payload.get("tool_selector_source", "unknown")
        tool_selector_reason = payload.get("tool_selector_reason", "")

        for msg in payload.get("warnings", []):
            self._append(f"Warn: {msg}")
        self._append(f"Selected app: {app_name} (id={app_id})")
        self._append(f"Selected tool: {tool_name} (id={tool_id})")
        self._append(f"App Selector: {app_selector_source} ({app_selector_reason})")
        self._append(f"Tool Selector: {tool_selector_source} ({tool_selector_reason})")
        self._append(f"req_id: {req_id}")
        self._append(f"status: {resp.get('status')}  t_ms: {resp.get('t_ms')}")
        if resp.get("status") == "ok":
            self._append(f"Result: {_fmt_json(resp.get('result', {}))}")
        else:
            self._append(f"Error: {resp.get('error', 'unknown error')}")
        self._append("")

        self._thread = None
        self._worker = None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sock", default=DEFAULT_SOCK_PATH)
    parser.add_argument("--agent-id", default="a1")
    parser.add_argument(
        "--selector",
        choices=["deepseek"],
        default="deepseek",
    )
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument("--deepseek-url", default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL))
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    args = parser.parse_args()

    if sys.platform.startswith("linux"):
        has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if not has_display:
            print("No GUI display detected: DISPLAY/WAYLAND_DISPLAY are both unset.", flush=True)
            print("Current session appears to be a TTY-only shell.", flush=True)
            print("Use CLI instead: python llm-app/cli.py --repl", flush=True)
            print("Or start from a desktop/X11/Wayland session and retry.", flush=True)
            return 2

    app = QApplication(sys.argv)
    selector_cfg = SelectorConfig(
        mode=args.selector,
        deepseek_url=args.deepseek_url,
        deepseek_model=args.deepseek_model,
        deepseek_timeout_sec=args.deepseek_timeout_sec,
    )
    win = MainWindow(sock_path=args.sock, agent_id=args.agent_id, selector_cfg=selector_cfg)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
