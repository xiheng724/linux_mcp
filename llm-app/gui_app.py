#!/usr/bin/env python3
"""PySide6 GUI demo app for linux-mcp."""

from __future__ import annotations

import sys
import time
import argparse
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

try:
    from PySide6.QtCore import QObject, QThread, Qt, Signal
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QSplitter,
        QTextEdit,
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
    ApprovalRequest,
    execute_plan,
)
from gui_support import approval_message, execution_lines, fetch_catalog, pull_worker_state, render_catalog_view
from model_client import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    SelectorConfig,
    SessionInfo,
    open_session,
)
DEFAULT_SOCK_PATH = "/tmp/mcpd.sock"
TOOLS_CACHE_TTL_S = 10.0
DEFAULT_SESSION_TTL_MS = 30 * 60 * 1000
DisplayMode = Literal["user", "dev"]

@dataclass
class ExecRequest:
    user_text: str
    client_name: str
    sock_path: str
    selector_cfg: SelectorConfig
    cached_apps: List[Dict[str, Any]]
    cached_tools: List[Dict[str, Any]]
    cached_at: float
    session: SessionInfo | None


class ExecWorker(QObject):
    finished = Signal(dict)
    approval_needed = Signal(dict)

    def __init__(self, req: ExecRequest) -> None:
        super().__init__()
        self.req = req
        self._approval_event = threading.Event()
        self._approval_result = False

    def resolve_approval(self, approved: bool) -> None:
        self._approval_result = approved
        self._approval_event.set()

    def _approval_prompt(self, request: ApprovalRequest) -> bool:
        self._approval_result = False
        self._approval_event.clear()
        self.approval_needed.emit(
            {
                "step_id": request.step_id,
                "app_name": request.app_name,
                "tool_name": request.tool_name,
                "purpose": request.purpose,
                "ticket_id": request.ticket_id,
                "reason": request.reason,
                "payload": request.payload,
            }
        )
        self._approval_event.wait()
        return self._approval_result

    def run(self) -> None:
        now = time.time()
        apps = self.req.cached_apps
        tools = self.req.cached_tools
        if not apps or not tools or (now - self.req.cached_at) > TOOLS_CACHE_TTL_S:
            catalog = fetch_catalog(self.req.sock_path)
            if catalog.get("status") != "ok":
                self.finished.emit(
                    {"status": "error", "error": catalog.get("error", "catalog refresh failed")}
                )
                return
            apps = catalog["apps"]
            tools = catalog["tools"]

        try:
            session = self.req.session
            now_ms = int(time.time() * 1000)
            if session is None or session.expires_at_ms <= (now_ms + 5_000):
                session = open_session(
                    self.req.sock_path,
                    self.req.client_name,
                    DEFAULT_SESSION_TTL_MS,
                )
            execution = execute_plan(
                self.req.user_text,
                session,
                self.req.sock_path,
                self.req.selector_cfg,
                apps=apps,
                tools=tools,
                approval_handler=self._approval_prompt,
            )
        except Exception as exc:  # noqa: BLE001
            self.finished.emit({"status": "error", "error": str(exc), "warnings": []})
            return

        self.finished.emit(
            {
                "status": execution.get("status", "error"),
                "error": execution.get("error", ""),
                "warnings": [],
                "execution": execution,
                "apps": execution.get("apps", apps),
                "tools": execution.get("tools", self.req.cached_tools),
                "tools_at": time.time(),
                "session": session,
            }
        )


class MainWindow(QMainWindow):
    def __init__(
        self,
        sock_path: str,
        client_name: str,
        selector_cfg: SelectorConfig,
        initial_mode: DisplayMode,
    ) -> None:
        super().__init__()
        self.sock_path = sock_path
        self.client_name = client_name
        self.selector_cfg = selector_cfg
        self.apps_cache: List[Dict[str, Any]] = []
        self.tools_cache: List[Dict[str, Any]] = []
        self.tools_cache_at: float = 0.0
        self.session: SessionInfo | None = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[ExecWorker] = None
        self._tools_visible = False

        self.setWindowTitle("Linux MCP LLM App")
        self.resize(980, 620)

        root = QWidget(self)
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        layout.addWidget(splitter)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        top_row = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh", self)
        self.mode_combo = QComboBox(self)
        self.mode_combo.addItems(["user", "dev"])
        self.mode_combo.setCurrentText(initial_mode)
        top_row.addWidget(self.refresh_btn)
        top_row.addWidget(QLabel("Mode", self))
        top_row.addWidget(self.mode_combo)
        self.catalog_label = QLabel("Catalog not loaded", self)
        self.apps_list = QListWidget(self)
        self.toggle_tools_btn = QPushButton("Show Tool Details", self)
        self.tools_text = QTextEdit(self)
        self.tools_text.setReadOnly(True)
        self.tools_text.setVisible(False)
        left_layout.addLayout(top_row)
        left_layout.addWidget(self.catalog_label)
        left_layout.addWidget(QLabel("Apps", self))
        left_layout.addWidget(self.apps_list)
        left_layout.addWidget(self.toggle_tools_btn)
        left_layout.addWidget(self.tools_text)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        self.chat = QPlainTextEdit(self)
        self.chat.setReadOnly(True)
        right_layout.addWidget(QLabel("Conversation", self))
        right_layout.addWidget(self.chat)

        input_row = QHBoxLayout()
        self.input_box = QLineEdit(self)
        self.input_box.setPlaceholderText(
            "Ask naturally, for example: create a note titled Daily Standup"
        )
        self.send_btn = QPushButton("Send", self)
        input_row.addWidget(self.input_box)
        input_row.addWidget(self.send_btn)
        right_layout.addLayout(input_row)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([320, 660])

        self.refresh_btn.clicked.connect(self.refresh_tools)
        self.toggle_tools_btn.clicked.connect(self._toggle_tool_details)
        self.mode_combo.currentTextChanged.connect(lambda _text: self._render_catalog_views())
        self.send_btn.clicked.connect(self.handle_send)
        self.input_box.returnPressed.connect(self.handle_send)

        self._append(f"[system] GUI started in {initial_mode} mode")
        self.refresh_tools()

    def _append(self, text: str) -> None:
        self.chat.appendPlainText(text)

    def _set_busy(self, busy: bool) -> None:
        self.send_btn.setEnabled(not busy)
        self.input_box.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self.mode_combo.setEnabled(not busy)

    def _mode(self) -> DisplayMode:
        value = self.mode_combo.currentText()
        return "dev" if value == "dev" else "user"

    def _toggle_tool_details(self) -> None:
        self._tools_visible = not self._tools_visible
        self.tools_text.setVisible(self._tools_visible)
        self.toggle_tools_btn.setText("Hide Tool Details" if self._tools_visible else "Show Tool Details")

    def _render_catalog_views(self) -> None:
        view = render_catalog_view(
            self.apps_cache,
            self.tools_cache,
            detailed=(self._mode() == "dev"),
        )
        self.catalog_label.setText(view["label"])
        self.apps_list.clear()
        for line in view["app_lines"]:
            self.apps_list.addItem(QListWidgetItem(line))
        self.tools_text.setPlainText(view["tool_text"])

    def refresh_tools(self) -> None:
        catalog = fetch_catalog(self.sock_path)
        if catalog.get("status") != "ok":
            self._append(f"[system] catalog refresh failed: {catalog.get('error', 'unknown error')}")
            return

        self.apps_cache = catalog["apps"]
        self.tools_cache = catalog["tools"]
        self.tools_cache_at = float(catalog["tools_at"])
        self._render_catalog_views()
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
        if self._mode() == "user":
            self._append("Assistant: Working on it...")
        else:
            self._append("[system] executing request...")
        self._set_busy(True)
        req = ExecRequest(
            user_text=text,
            client_name=self.client_name,
            sock_path=self.sock_path,
            selector_cfg=self.selector_cfg,
            cached_apps=self.apps_cache,
            cached_tools=self.tools_cache,
            cached_at=self.tools_cache_at,
            session=self.session,
        )
        self._thread = QThread(self)
        self._worker = ExecWorker(req)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_worker_done)
        self._worker.approval_needed.connect(self._on_approval_needed)
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

        state = pull_worker_state(payload, self.session)
        if isinstance(state["apps"], list):
            self.apps_cache = state["apps"]
        if isinstance(state["tools"], list):
            self.tools_cache = state["tools"]
        if isinstance(state["tools_at"], float):
            self.tools_cache_at = state["tools_at"]
        if isinstance(state["session"], SessionInfo):
            self.session = state["session"]
        self._render_catalog_views()

        for msg in payload.get("warnings", []):
            self._append(f"Warn: {msg}")
        execution = payload.get("execution", {})
        if not isinstance(execution, dict):
            execution = {}
        for line in execution_lines(execution, dev_mode=(self._mode() == "dev")):
            self._append(line)
        resp = execution.get("response", {})
        if not isinstance(resp, dict):
            resp = {}
        if execution.get("status") != "ok" and self._mode() == "dev":
            self._append(f"Error: {resp.get('error', execution.get('error', 'unknown error'))}")
        self._append("")

        self._thread = None
        self._worker = None

    def _on_approval_needed(self, payload: Dict[str, Any]) -> None:
        choice = QMessageBox.question(
            self,
            "Approval Required",
            approval_message(payload),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if self._worker is not None:
            self._worker.resolve_approval(choice == QMessageBox.StandardButton.Yes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sock", default=DEFAULT_SOCK_PATH)
    parser.add_argument("--agent-id", default="a1", help="client name hint for session opening")
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument("--deepseek-url", default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL))
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    parser.add_argument("--mode", choices=("user", "dev"), default="user")
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
        deepseek_url=args.deepseek_url,
        deepseek_model=args.deepseek_model,
        deepseek_timeout_sec=args.deepseek_timeout_sec,
    )
    win = MainWindow(
        sock_path=args.sock,
        client_name=args.agent_id,
        selector_cfg=selector_cfg,
        initial_mode=args.mode,
    )
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
