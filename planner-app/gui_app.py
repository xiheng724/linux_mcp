#!/usr/bin/env python3
"""PySide6 GUI for capability-domain MCP execution."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

try:
    from PySide6.QtCore import QObject, QThread, Qt, Signal
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QListWidgetItem,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QSizePolicy,
        QSplitter,
        QVBoxLayout,
        QWidget,
    )
except Exception:
    print("PySide6 not installed.", flush=True)
    print("Install guide: sudo apt-get install python3-pyside6  (or)  pip install PySide6", flush=True)
    raise SystemExit(2)

from app_logic import (
    DEFAULT_DEEPSEEK_MODEL,
    DEFAULT_DEEPSEEK_URL,
    CapabilityIntent,
    SelectorConfig,
    plan_capability_intent,
)
from rpc import mcpd_call

DEFAULT_SOCK_PATH = "/tmp/mcpd.sock"
CATALOG_TTL_S = 10.0


def _json_pretty(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        return str(data)


def _ensure_list(resp: Dict[str, Any], key: str, label: str) -> List[Dict[str, Any]]:
    if resp.get("status") != "ok":
        raise RuntimeError(resp.get("error", f"{label} failed"))
    raw = resp.get(key, [])
    if not isinstance(raw, list):
        raise RuntimeError(f"{label} response missing {key} list")
    return [item for item in raw if isinstance(item, dict)]


def _list_providers(sock_path: str) -> List[Dict[str, Any]]:
    return _ensure_list(
        mcpd_call({"sys": "list_providers"}, sock_path=sock_path, timeout_s=5),
        "providers",
        "list_providers",
    )


def _list_actions(sock_path: str) -> List[Dict[str, Any]]:
    return _ensure_list(
        mcpd_call({"sys": "list_actions"}, sock_path=sock_path, timeout_s=5),
        "actions",
        "list_actions",
    )


def _list_capabilities(sock_path: str) -> List[Dict[str, Any]]:
    return _ensure_list(
        mcpd_call({"sys": "list_capabilities"}, sock_path=sock_path, timeout_s=5),
        "capabilities",
        "list_capabilities",
    )


@dataclass
class CatalogSnapshot:
    providers: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    capabilities: List[Dict[str, Any]]
    fetched_at: float


@dataclass
class ExecRequest:
    user_text: str
    participant_id: str
    sock_path: str
    selector_cfg: SelectorConfig
    interactive: bool
    explicit_approval: bool
    approval_token: str
    preferred_provider_id: str
    manual_capability: Optional[Dict[str, Any]]
    catalog: Optional[CatalogSnapshot]


class CatalogWorker(QObject):
    finished = Signal(object)

    def __init__(self, sock_path: str) -> None:
        super().__init__()
        self.sock_path = sock_path

    def run(self) -> None:
        try:
            providers = _list_providers(self.sock_path)
            actions = _list_actions(self.sock_path)
            capabilities = _list_capabilities(self.sock_path)
            self.finished.emit(
                {
                    "status": "ok",
                    "catalog": CatalogSnapshot(
                        providers=providers,
                        actions=actions,
                        capabilities=capabilities,
                        fetched_at=time.time(),
                    ),
                }
            )
        except Exception as exc:  # noqa: BLE001
            self.finished.emit({"status": "error", "error": str(exc)})


class ExecWorker(QObject):
    finished = Signal(object)

    def __init__(self, req: ExecRequest) -> None:
        super().__init__()
        self.req = req

    def _load_catalog(self) -> CatalogSnapshot:
        catalog = self.req.catalog
        if catalog is not None and (time.time() - catalog.fetched_at) <= CATALOG_TTL_S:
            return catalog
        return CatalogSnapshot(
            providers=_list_providers(self.req.sock_path),
            actions=_list_actions(self.req.sock_path),
            capabilities=_list_capabilities(self.req.sock_path),
            fetched_at=time.time(),
        )

    def run(self) -> None:
        warnings: List[str] = []
        try:
            catalog = self._load_catalog()
            if not catalog.capabilities:
                raise RuntimeError("no capabilities returned by mcpd")

            if self.req.manual_capability is not None:
                capability = self.req.manual_capability
                intent = CapabilityIntent(
                    capability_domain=str(capability.get("capability_domain", "")),
                    capability_id=int(capability.get("capability_id", 0)),
                    capability_hash=str(capability.get("hash", "") or ""),
                    intent_text=self.req.user_text,
                    preferred_provider_id=self.req.preferred_provider_id,
                    hints={},
                    selector_source="manual",
                    selector_reason="manually selected in GUI",
                )
            else:
                intent = plan_capability_intent(
                    self.req.user_text,
                    catalog.capabilities,
                    self.req.selector_cfg,
                    warn_cb=lambda msg: warnings.append(msg),
                )
                capability = next(
                    (
                        item
                        for item in catalog.capabilities
                        if item.get("capability_domain") == intent.capability_domain
                    ),
                    None,
                )
                if capability is None:
                    raise RuntimeError(
                        f"selected capability missing from catalog: {intent.capability_domain}"
                    )

            req_id = int(time.time_ns() & 0xFFFFFFFFFFFF)
            payload: Dict[str, Any] = {
                "kind": "capability:exec",
                "req_id": req_id,
                "participant_id": self.req.participant_id,
                "capability_domain": intent.capability_domain,
                "intent_text": intent.intent_text,
            }
            if self.req.interactive:
                payload["interactive"] = True
            if self.req.explicit_approval:
                payload["explicit_approval"] = True
            if self.req.approval_token:
                payload["approval_token"] = self.req.approval_token
            hints = dict(intent.hints)
            hints["selector_source"] = intent.selector_source
            hints["selector_reason"] = intent.selector_reason
            if intent.preferred_provider_id:
                hints.setdefault("preferred_provider_id", intent.preferred_provider_id)
            if hints:
                payload["hints"] = hints

            resp = mcpd_call(payload, sock_path=self.req.sock_path, timeout_s=30)
            self.finished.emit(
                {
                    "status": "ok",
                    "req_id": req_id,
                    "response": resp,
                    "selector_source": intent.selector_source,
                    "selector_reason": intent.selector_reason,
                    "selected_capability": capability,
                    "warnings": warnings,
                    "catalog": catalog,
                }
            )
        except Exception as exc:  # noqa: BLE001
            self.finished.emit({"status": "error", "error": str(exc), "warnings": warnings})


class MainWindow(QMainWindow):
    def __init__(self, sock_path: str, participant_id: str, selector_cfg: SelectorConfig) -> None:
        super().__init__()
        self.sock_path = sock_path
        self.participant_id = participant_id
        self.selector_cfg = selector_cfg
        self.catalog: Optional[CatalogSnapshot] = None
        self._thread: Optional[QThread] = None
        self._worker: Optional[QObject] = None

        self.setWindowTitle("Linux MCP Capability Console")
        self.resize(1280, 820)
        self._build_ui()
        self._apply_style()
        self._append_log("GUI ready")
        self.refresh_catalog()

    def _build_ui(self) -> None:
        root = QWidget(self)
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        title = QLabel("Linux MCP Capability Console", self)
        title.setObjectName("title")
        subtitle = QLabel(
            "Planner requests capability domains; mcpd selects broker/provider/action; kernel MCP arbitrates leases.",
            self,
        )
        subtitle.setWordWrap(True)
        subtitle.setObjectName("subtitle")

        top_bar = QFrame(self)
        top_bar.setObjectName("panel")
        top_grid = QGridLayout(top_bar)
        top_grid.setContentsMargins(12, 12, 12, 12)
        top_grid.setHorizontalSpacing(10)
        top_grid.setVerticalSpacing(8)

        self.agent_input = QLineEdit(self.participant_id, self)
        self.sock_input = QLineEdit(self.sock_path, self)
        self.selector_combo = QComboBox(self)
        self.selector_combo.addItems(["auto", "catalog", "deepseek"])
        idx = self.selector_combo.findText(self.selector_cfg.mode)
        if idx >= 0:
            self.selector_combo.setCurrentIndex(idx)
        self.interactive_check = QCheckBox("interactive", self)
        self.explicit_check = QCheckBox("explicit approval", self)
        self.approval_token_input = QLineEdit(self)
        self.approval_token_input.setPlaceholderText("approval token")
        self.provider_pref_combo = QComboBox(self)
        self.provider_pref_combo.addItem("auto", "")
        self.refresh_btn = QPushButton("Refresh Catalog", self)

        top_grid.addWidget(QLabel("Participant"), 0, 0)
        top_grid.addWidget(self.agent_input, 0, 1)
        top_grid.addWidget(QLabel("Socket"), 0, 2)
        top_grid.addWidget(self.sock_input, 0, 3)
        top_grid.addWidget(self.refresh_btn, 0, 4)

        top_grid.addWidget(QLabel("Selector"), 1, 0)
        top_grid.addWidget(self.selector_combo, 1, 1)
        top_grid.addWidget(QLabel("Preferred Provider"), 1, 2)
        top_grid.addWidget(self.provider_pref_combo, 1, 3)
        top_grid.addWidget(self.interactive_check, 1, 4)

        top_grid.addWidget(QLabel("Approval Token"), 2, 0)
        top_grid.addWidget(self.approval_token_input, 2, 1, 1, 3)
        top_grid.addWidget(self.explicit_check, 2, 4)

        splitter = QSplitter(Qt.Orientation.Horizontal, self)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(top_bar)
        layout.addWidget(splitter, 1)

        left = QWidget(self)
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        self.cap_list = QListWidget(self)
        self.provider_list = QListWidget(self)
        self.tool_list = QListWidget(self)
        self.cap_list.setObjectName("catalogList")
        self.provider_list.setObjectName("catalogList")
        self.tool_list.setObjectName("catalogList")

        left_layout.addWidget(self._wrap_section("Capabilities", self.cap_list), 3)
        left_layout.addWidget(self._wrap_section("Providers", self.provider_list), 2)
        left_layout.addWidget(self._wrap_section("Actions", self.tool_list), 3)

        right = QWidget(self)
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        self.prompt_input = QPlainTextEdit(self)
        self.prompt_input.setPlaceholderText("Describe the intent, for example: create a file tmp/demo.txt with content hello")
        self.prompt_input.setTabChangesFocus(True)
        self.prompt_input.setMaximumBlockCount(200)
        self.prompt_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.MinimumExpanding)

        prompt_bar = QHBoxLayout()
        self.execute_btn = QPushButton("Execute", self)
        self.clear_btn = QPushButton("Clear Output", self)
        self.manual_cap_check = QCheckBox("use selected capability", self)
        prompt_bar.addWidget(self.manual_cap_check)
        prompt_bar.addStretch(1)
        prompt_bar.addWidget(self.clear_btn)
        prompt_bar.addWidget(self.execute_btn)

        self.detail_view = QPlainTextEdit(self)
        self.detail_view.setReadOnly(True)
        self.result_view = QPlainTextEdit(self)
        self.result_view.setReadOnly(True)
        self.log_view = QPlainTextEdit(self)
        self.log_view.setReadOnly(True)

        right_layout.addWidget(self._wrap_section("Intent", self.prompt_input), 2)
        right_layout.addLayout(prompt_bar)
        right_layout.addWidget(self._wrap_section("Selection / Response", self.result_view), 3)
        right_layout.addWidget(self._wrap_section("Object Detail", self.detail_view), 3)
        right_layout.addWidget(self._wrap_section("Event Log", self.log_view), 2)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([420, 860])

        self.refresh_btn.clicked.connect(self.refresh_catalog)
        self.clear_btn.clicked.connect(self.log_view.clear)
        self.execute_btn.clicked.connect(self.execute_request)
        self.cap_list.currentItemChanged.connect(self._update_detail_from_selection)
        self.provider_list.currentItemChanged.connect(self._update_detail_from_selection)
        self.tool_list.currentItemChanged.connect(self._update_detail_from_selection)

    def _wrap_section(self, title: str, widget: QWidget) -> QFrame:
        frame = QFrame(self)
        frame.setObjectName("panel")
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        label = QLabel(title, self)
        label.setObjectName("sectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget, 1)
        return frame

    def _apply_style(self) -> None:
        base_font = QFont("DejaVu Sans Mono")
        base_font.setStyleHint(QFont.StyleHint.Monospace)
        self.detail_view.setFont(base_font)
        self.result_view.setFont(base_font)
        self.log_view.setFont(base_font)

        self.setStyleSheet(
            """
            QWidget {
                background: #f4f1ea;
                color: #1f1d1a;
            }
            QFrame#panel {
                background: #fbf8f2;
                border: 1px solid #d8d1c4;
                border-radius: 12px;
            }
            QLabel#title {
                font-size: 28px;
                font-weight: 700;
                color: #1f3b2d;
            }
            QLabel#subtitle {
                color: #5f5b53;
                margin-bottom: 4px;
            }
            QLabel#sectionTitle {
                font-size: 14px;
                font-weight: 700;
                color: #7a3d19;
                text-transform: uppercase;
                letter-spacing: 0.08em;
            }
            QPlainTextEdit, QListWidget, QLineEdit, QComboBox {
                background: #fffdf8;
                border: 1px solid #cfc6b6;
                border-radius: 8px;
                padding: 6px;
                selection-background-color: #264653;
                selection-color: #fefcf8;
            }
            QPushButton {
                background: #264653;
                color: #fefcf8;
                border: none;
                border-radius: 8px;
                padding: 8px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #315c6d;
            }
            QPushButton:disabled {
                background: #9aa6ac;
            }
            """
        )

    def _append_log(self, message: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{ts}] {message}")

    def _set_busy(self, busy: bool) -> None:
        self.execute_btn.setEnabled(not busy)
        self.refresh_btn.setEnabled(not busy)
        self.agent_input.setEnabled(not busy)
        self.sock_input.setEnabled(not busy)

    def _current_manual_capability(self) -> Optional[Dict[str, Any]]:
        if not self.manual_cap_check.isChecked():
            return None
        item = self.cap_list.currentItem()
        if item is None:
            return None
        data = item.data(Qt.ItemDataRole.UserRole)
        return data if isinstance(data, dict) else None

    def _selected_provider_id(self) -> str:
        return str(self.provider_pref_combo.currentData() or "")

    def _refresh_provider_combo(self, providers: List[Dict[str, Any]]) -> None:
        current = self._selected_provider_id()
        self.provider_pref_combo.blockSignals(True)
        self.provider_pref_combo.clear()
        self.provider_pref_combo.addItem("auto", "")
        for provider in providers:
            provider_id = str(provider.get("provider_id", ""))
            label = f"{provider_id} ({provider.get('provider_type', '-')})"
            self.provider_pref_combo.addItem(label, provider_id)
        idx = self.provider_pref_combo.findData(current)
        self.provider_pref_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.provider_pref_combo.blockSignals(False)

    def _populate_catalog(self, catalog: CatalogSnapshot) -> None:
        self.catalog = catalog
        self._refresh_provider_combo(catalog.providers)

        self.cap_list.clear()
        for capability in catalog.capabilities:
            domain = str(capability.get("capability_domain", "?"))
            broker = str(capability.get("broker_id", "?"))
            risk = capability.get("risk_level", "?")
            item = QListWidgetItem(f"{domain}\nbroker={broker}  risk={risk}")
            item.setData(Qt.ItemDataRole.UserRole, capability)
            self.cap_list.addItem(item)

        self.provider_list.clear()
        for provider in catalog.providers:
            provider_id = str(provider.get("provider_id", "?"))
            broker_domain = str(provider.get("broker_domain", "?"))
            count = provider.get("action_count", "?")
            item = QListWidgetItem(f"{provider_id}\ndomain={broker_domain}  actions={count}")
            item.setData(Qt.ItemDataRole.UserRole, provider)
            self.provider_list.addItem(item)

        self.tool_list.clear()
        for action in catalog.actions:
            name = str(action.get("name", "?"))
            capability = str(action.get("capability_domain", "?"))
            provider_id = str(action.get("provider_id", "?"))
            item = QListWidgetItem(f"{name}\nprovider={provider_id}  capability={capability}")
            item.setData(Qt.ItemDataRole.UserRole, action)
            self.tool_list.addItem(item)

        if self.cap_list.count() > 0 and self.cap_list.currentRow() < 0:
            self.cap_list.setCurrentRow(0)
        self._append_log(
            f"catalog refreshed providers={len(catalog.providers)} actions={len(catalog.actions)} capabilities={len(catalog.capabilities)}"
        )

    def _update_detail_from_selection(self) -> None:
        for widget in (self.cap_list, self.provider_list, self.tool_list):
            item = widget.currentItem()
            if item is None:
                continue
            data = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(data, dict):
                self.detail_view.setPlainText(_json_pretty(data))
                return
        self.detail_view.clear()

    def refresh_catalog(self) -> None:
        self._set_busy(True)
        thread = QThread(self)
        worker = CatalogWorker(self.sock_input.text().strip() or DEFAULT_SOCK_PATH)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_catalog_ready)
        worker.finished.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        thread.start()
        self._thread = thread
        self._worker = worker
        self._append_log("refreshing catalog")

    def execute_request(self) -> None:
        user_text = self.prompt_input.toPlainText().strip()
        if not user_text:
            QMessageBox.warning(self, "Missing Intent", "Enter an intent before executing.")
            return
        if self._thread is not None:
            self._append_log("request ignored while another operation is running")
            return

        cfg = SelectorConfig(
            mode=self.selector_combo.currentText(),
            deepseek_url=self.selector_cfg.deepseek_url,
            deepseek_model=self.selector_cfg.deepseek_model,
            deepseek_timeout_sec=self.selector_cfg.deepseek_timeout_sec,
        )
        req = ExecRequest(
            user_text=user_text,
            participant_id=self.agent_input.text().strip() or "planner-main",
            sock_path=self.sock_input.text().strip() or DEFAULT_SOCK_PATH,
            selector_cfg=cfg,
            interactive=self.interactive_check.isChecked(),
            explicit_approval=self.explicit_check.isChecked(),
            approval_token=self.approval_token_input.text().strip(),
            preferred_provider_id=self._selected_provider_id(),
            manual_capability=self._current_manual_capability(),
            catalog=self.catalog,
        )
        self._set_busy(True)
        thread = QThread(self)
        worker = ExecWorker(req)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_exec_done)
        worker.finished.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        thread.start()
        self._thread = thread
        self._worker = worker
        self._append_log(f"submitted intent: {user_text}")

    def _reset_worker(self) -> None:
        self._thread = None
        self._worker = None
        self._set_busy(False)

    def _on_catalog_ready(self, payload: Dict[str, Any]) -> None:
        self._reset_worker()
        if payload.get("status") != "ok":
            self._append_log(f"catalog refresh failed: {payload.get('error', 'unknown error')}")
            QMessageBox.critical(self, "Catalog Refresh Failed", str(payload.get("error", "unknown error")))
            return
        catalog = payload.get("catalog")
        if not isinstance(catalog, CatalogSnapshot):
            self._append_log("catalog refresh failed: invalid worker payload")
            return
        self._populate_catalog(catalog)

    def _on_exec_done(self, payload: Dict[str, Any]) -> None:
        self._reset_worker()
        warnings = payload.get("warnings", [])
        if isinstance(warnings, list):
            for msg in warnings:
                self._append_log(f"warning: {msg}")

        if payload.get("status") != "ok":
            err = str(payload.get("error", "unknown error"))
            self.result_view.setPlainText(err)
            self._append_log(f"execution failed: {err}")
            return

        catalog = payload.get("catalog")
        if isinstance(catalog, CatalogSnapshot):
            self._populate_catalog(catalog)

        selected_capability = payload.get("selected_capability", {})
        resp = payload.get("response", {})
        selector_source = payload.get("selector_source", "unknown")
        selector_reason = payload.get("selector_reason", "")
        req_id = payload.get("req_id", 0)

        response_block = {
            "req_id": req_id,
            "selector_source": selector_source,
            "selector_reason": selector_reason,
            "selected_capability": selected_capability,
            "response": resp,
        }
        self.result_view.setPlainText(_json_pretty(response_block))

        if isinstance(resp, dict) and resp.get("status") == "ok":
            self._append_log(
                "ok req_id={} capability={} broker={} provider={} action={}".format(
                    req_id,
                    selected_capability.get("capability_domain", "?"),
                    resp.get("broker_id", "-"),
                    resp.get("provider_id", "-"),
                    resp.get("action_name", "-"),
                )
            )
        else:
            self._append_log(
                f"request error req_id={req_id} err={resp.get('error', 'unknown error') if isinstance(resp, dict) else resp}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sock", default=DEFAULT_SOCK_PATH)
    parser.add_argument("--participant-id", default="planner-main")
    parser.add_argument(
        "--selector",
        choices=["auto", "catalog", "deepseek"],
        default="auto",
    )
    parser.add_argument("--deepseek-model", default=DEFAULT_DEEPSEEK_MODEL)
    parser.add_argument(
        "--deepseek-url",
        default=os.getenv("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL),
    )
    parser.add_argument("--deepseek-timeout-sec", type=int, default=20)
    args = parser.parse_args()

    if sys.platform.startswith("linux"):
        has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
        if not has_display:
            print("No GUI display detected: DISPLAY/WAYLAND_DISPLAY are both unset.", flush=True)
            print("Use CLI instead: python3 planner-app/cli.py --repl", flush=True)
            return 2

    app = QApplication(sys.argv)
    selector_cfg = SelectorConfig(
        mode=args.selector,
        deepseek_url=args.deepseek_url,
        deepseek_model=args.deepseek_model,
        deepseek_timeout_sec=args.deepseek_timeout_sec,
    )
    win = MainWindow(sock_path=args.sock, participant_id=args.participant_id, selector_cfg=selector_cfg)
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
