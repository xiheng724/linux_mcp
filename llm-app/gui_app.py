#!/usr/bin/env python3
"""PySide6 GUI demo app for linux-mcp."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Literal, Optional

try:
    from PySide6.QtCore import QObject, QThread, Qt, QTimer, Signal
    from PySide6.QtGui import QKeySequence, QShortcut, QTextCursor
    from PySide6.QtWidgets import (
        QApplication,
        QComboBox,
        QFrame,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPlainTextEdit,
        QPushButton,
        QSplitter,
        QStatusBar,
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

from app_logic import ApprovalRequest, execute_plan
from gui_support import (
    approval_message,
    execution_lines,
    fetch_catalog,
    pull_worker_state,
    render_catalog_view,
)
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

STYLE_SHEET = """
QMainWindow, QWidget {
    background-color: #17181c;
    color: #d7d8df;
    font-family: "Noto Sans", "Segoe UI", sans-serif;
    font-size: 13px;
}

#sidebar {
    background-color: #111217;
    border-right: 1px solid #2a2d36;
}

#sidebarTitle {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    color: #848b9a;
    padding: 2px 0;
    text-transform: uppercase;
}

#catalogLabel {
    font-size: 11px;
    color: #8f96a6;
    padding: 2px 0 6px 0;
}

#sectionLabel {
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    color: #7c8596;
    text-transform: uppercase;
}

QListWidget {
    background-color: #1d2027;
    border: 1px solid #2d313b;
    border-radius: 8px;
    padding: 4px;
    outline: 0;
}

QListWidget::item {
    padding: 6px 8px;
    border-radius: 6px;
    color: #d1d5df;
}

QListWidget::item:selected {
    background-color: #2b3240;
    color: #f3f4f7;
}

QListWidget::item:hover {
    background-color: #252a34;
}

#toolsText {
    background-color: #15171d;
    border: 1px solid #2d313b;
    border-radius: 8px;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 11.5px;
    color: #aab1bf;
    padding: 6px;
}

#chatPane {
    background-color: #15171d;
    border: 1px solid #2d313b;
    border-radius: 10px;
    color: #d7d8df;
    padding: 8px;
}

#inputBox {
    background-color: #1d2027;
    border: 1px solid #393f4d;
    border-radius: 10px;
    padding: 8px 12px;
    color: #eef0f6;
    selection-background-color: #4c5972;
}

#inputBox:focus {
    border-color: #5f86e8;
}

#inputBox::placeholder {
    color: #697286;
}

QPushButton {
    background-color: #242933;
    border: 1px solid #3a404e;
    border-radius: 8px;
    padding: 6px 14px;
    color: #d7d8df;
    font-size: 13px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #2b3240;
    border-color: #51596b;
}

QPushButton:pressed {
    background-color: #1d2027;
}

QPushButton:disabled {
    color: #697286;
    border-color: #2d313b;
    background-color: #17181c;
}

#sendBtn {
    background-color: #3f74e0;
    border: none;
    color: #ffffff;
    font-weight: 600;
    padding: 8px 20px;
    min-width: 80px;
}

#sendBtn:hover {
    background-color: #4a81ee;
}

#sendBtn:pressed {
    background-color: #3464c6;
}

#sendBtn:disabled {
    background-color: #2d4c85;
    color: #9db0d8;
}

#refreshBtn {
    padding: 5px 12px;
    font-size: 12px;
}

QComboBox {
    background-color: #1d2027;
    border: 1px solid #393f4d;
    border-radius: 8px;
    padding: 4px 10px;
    color: #d7d8df;
    font-size: 12px;
    min-width: 70px;
}

QComboBox::drop-down {
    border: none;
    width: 18px;
}

QComboBox QAbstractItemView {
    background-color: #242933;
    border: 1px solid #393f4d;
    selection-background-color: #34415a;
    color: #d7d8df;
}

#toggleBtn {
    font-size: 12px;
    color: #8fb3ff;
    background: transparent;
    border: 1px solid #2d313b;
    border-radius: 8px;
    padding: 5px 10px;
    text-align: left;
}

#toggleBtn:hover {
    border-color: #3f74e0;
    background: #1d2027;
}

QStatusBar {
    background: #111217;
    border-top: 1px solid #2a2d36;
    color: #8a92a4;
    font-size: 11px;
    padding: 2px 8px;
}

QSplitter::handle {
    background: #2a2d36;
    width: 1px;
}

QScrollBar:vertical {
    background: #17181c;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background: #3a404e;
    border-radius: 4px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background: #52596b;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: #17181c;
    height: 8px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background: #3a404e;
    border-radius: 4px;
    min-width: 24px;
}

QScrollBar::handle:horizontal:hover {
    background: #52596b;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

QFrame[frameShape="4"], QFrame[frameShape="5"] {
    color: #2a2d36;
}
"""


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


class TypingDots(QLabel):
    """Animated indicator shown while the worker is running."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("", parent)
        self.setStyleSheet("color: #5f86e8; font-size: 16px; letter-spacing: 2px;")
        self._tick = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._update)

    def start(self) -> None:
        self._tick = 0
        self._timer.start(350)
        self.setVisible(True)

    def stop(self) -> None:
        self._timer.stop()
        self.setVisible(False)
        self.setText("")

    def _update(self) -> None:
        dots = "." * ((self._tick % 3) + 1)
        self.setText(f"Working{dots}")
        self._tick += 1


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

        self.setWindowTitle("Linux MCP")
        self.resize(1060, 680)
        self.setMinimumSize(760, 520)
        self.setStyleSheet(STYLE_SHEET)

        self._build_ui(initial_mode)
        self._connect_signals()
        self._setup_shortcuts()

        self._log_system(f"GUI started in {initial_mode} mode")
        self.refresh_tools()

    def _build_ui(self, initial_mode: DisplayMode) -> None:
        root = QWidget(self)
        self.setCentralWidget(root)
        main_layout = QHBoxLayout(root)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        main_layout.addWidget(splitter)

        sidebar = QWidget(self)
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(300)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(12, 12, 12, 12)
        sidebar_layout.setSpacing(8)

        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        self.refresh_btn = QPushButton("Refresh", self)
        self.refresh_btn.setObjectName("refreshBtn")
        self.refresh_btn.setToolTip("Reload catalog from MCP daemon (Ctrl+R)")
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)

        mode_label = QLabel("Mode", self)
        mode_label.setObjectName("sidebarTitle")
        mode_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        self.mode_combo = QComboBox(self)
        self.mode_combo.addItems(["user", "dev"])
        self.mode_combo.setCurrentText(initial_mode)
        self.mode_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_combo.setToolTip("user: friendly output, dev: full trace")

        top_row.addWidget(self.refresh_btn)
        top_row.addStretch()
        top_row.addWidget(mode_label)
        top_row.addWidget(self.mode_combo)
        sidebar_layout.addLayout(top_row)
        sidebar_layout.addWidget(self._hline())

        self.catalog_label = QLabel("Loading catalog...", self)
        self.catalog_label.setObjectName("catalogLabel")
        self.catalog_label.setWordWrap(True)
        sidebar_layout.addWidget(self.catalog_label)

        apps_heading = QLabel("Apps", self)
        apps_heading.setObjectName("sectionLabel")
        sidebar_layout.addWidget(apps_heading)

        self.apps_list = QListWidget(self)
        self.apps_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.apps_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        sidebar_layout.addWidget(self.apps_list, stretch=1)

        self.toggle_tools_btn = QPushButton("+ Tool Details", self)
        self.toggle_tools_btn.setObjectName("toggleBtn")
        self.toggle_tools_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        sidebar_layout.addWidget(self.toggle_tools_btn)

        self.tools_text = QTextEdit(self)
        self.tools_text.setObjectName("toolsText")
        self.tools_text.setReadOnly(True)
        self.tools_text.setVisible(False)
        self.tools_text.setFixedHeight(190)
        sidebar_layout.addWidget(self.tools_text)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(12, 12, 12, 12)
        right_layout.setSpacing(8)

        conv_label = QLabel("Conversation", self)
        conv_label.setObjectName("sectionLabel")
        right_layout.addWidget(conv_label)

        self.chat = QPlainTextEdit(self)
        self.chat.setObjectName("chatPane")
        self.chat.setReadOnly(True)
        self.chat.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        right_layout.addWidget(self.chat, stretch=1)

        input_block = QVBoxLayout()
        input_block.setSpacing(4)

        self.typing_dots = TypingDots(self)
        self.typing_dots.setVisible(False)
        input_block.addWidget(self.typing_dots)

        input_row = QHBoxLayout()
        input_row.setSpacing(8)
        self.input_box = QLineEdit(self)
        self.input_box.setObjectName("inputBox")
        self.input_box.setPlaceholderText(
            'Ask naturally, for example: "create a note titled Daily Standup"'
        )
        self.send_btn = QPushButton("Send", self)
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.setDefault(True)
        self.send_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        input_row.addWidget(self.input_box)
        input_row.addWidget(self.send_btn)
        input_block.addLayout(input_row)
        right_layout.addLayout(input_block)

        splitter.addWidget(sidebar)
        splitter.addWidget(right)
        splitter.setHandleWidth(1)
        splitter.setSizes([300, 760])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self._show_status("Ready")

    def _hline(self) -> QFrame:
        line = QFrame(self)
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        return line

    def _connect_signals(self) -> None:
        self.refresh_btn.clicked.connect(self.refresh_tools)
        self.toggle_tools_btn.clicked.connect(self._toggle_tool_details)
        self.mode_combo.currentTextChanged.connect(lambda _text: self._render_catalog_views())
        self.send_btn.clicked.connect(self.handle_send)
        self.input_box.returnPressed.connect(self.handle_send)

    def _setup_shortcuts(self) -> None:
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self.refresh_tools)
        QShortcut(QKeySequence("Ctrl+L"), self).activated.connect(self.chat.clear)

    def _show_status(self, msg: str) -> None:
        self.status_bar.showMessage(msg)

    def _append(self, text: str) -> None:
        self.chat.appendPlainText(text)
        self._scroll_chat()

    def _log_you(self, msg: str) -> None:
        self._append(f"You: {msg}")

    def _log_asst(self, msg: str) -> None:
        self._append(f"Assistant: {msg}")

    def _log_system(self, msg: str) -> None:
        self._append(f"[system] {msg}")

    def _log_warn(self, msg: str) -> None:
        self._append(f"Warn: {msg}")

    def _log_error(self, msg: str) -> None:
        self._append(f"Error: {msg}")

    def _scroll_chat(self) -> None:
        self.chat.moveCursor(QTextCursor.MoveOperation.End)

    def _set_busy(self, busy: bool) -> None:
        self.send_btn.setEnabled(not busy)
        self.input_box.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self.mode_combo.setEnabled(not busy)
        if busy:
            self.typing_dots.start()
            self._show_status("Processing request...")
        else:
            self.typing_dots.stop()
            self._show_status("Ready")

    def _mode(self) -> DisplayMode:
        value = self.mode_combo.currentText()
        return "dev" if value == "dev" else "user"

    def _toggle_tool_details(self) -> None:
        self._tools_visible = not self._tools_visible
        self.tools_text.setVisible(self._tools_visible)
        self.toggle_tools_btn.setText("- Tool Details" if self._tools_visible else "+ Tool Details")

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
        self._show_status("Refreshing catalog...")
        catalog = fetch_catalog(self.sock_path)
        if catalog.get("status") != "ok":
            self._log_error(f"catalog refresh failed: {catalog.get('error', 'unknown error')}")
            self._show_status("Catalog refresh failed")
            return

        self.apps_cache = catalog["apps"]
        self.tools_cache = catalog["tools"]
        self.tools_cache_at = float(catalog["tools_at"])
        self._render_catalog_views()
        self._log_system(
            f"catalog refreshed: apps={len(self.apps_cache)} tools={len(self.tools_cache)}"
        )
        self._show_status(f"Catalog loaded: {len(self.apps_cache)} apps, {len(self.tools_cache)} tools")

    def handle_send(self) -> None:
        text = self.input_box.text().strip()
        if not text:
            return
        if self._thread is not None:
            self._log_system("busy, please wait...")
            return

        self.input_box.clear()
        self._log_you(text)
        if self._mode() == "user":
            self._log_asst("Working on it...")
        else:
            self._log_system("executing request...")
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
        self.input_box.setFocus()

        if payload.get("status") != "ok":
            for msg in payload.get("warnings", []):
                self._log_warn(msg)
            self._log_error(payload.get("error", "unknown error"))
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
            self._log_warn(msg)
        execution = payload.get("execution", {})
        if not isinstance(execution, dict):
            execution = {}
        for line in execution_lines(execution, dev_mode=(self._mode() == "dev")):
            self._append(line)
        resp = execution.get("response", {})
        if not isinstance(resp, dict):
            resp = {}
        if execution.get("status") != "ok" and self._mode() == "dev":
            self._log_error(resp.get("error", execution.get("error", "unknown error")))
        self._append("")

        self._thread = None
        self._worker = None

    def _on_approval_needed(self, payload: Dict[str, Any]) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Approval Required")
        dialog.setText(approval_message(payload))
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.No)
        dialog.setIcon(QMessageBox.Icon.Question)
        choice = dialog.exec()
        if self._worker is not None:
            self._worker.resolve_approval(choice == QMessageBox.StandardButton.Yes)


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux MCP GUI client")
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
    app.setApplicationName("Linux MCP")
    app.setOrganizationName("linux-mcp")
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
