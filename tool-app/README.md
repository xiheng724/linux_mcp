# tool-app

`tool-app` 目录现在提供 14 个更像独立应用的 demo services，而不是单纯的零散 utility tools。

当前系统里，`mcpd` 不会 import 这些 app 的 Python 代码直接执行函数。它只会：

1. 读取 manifest
2. 把 app/tool 语义字段暴露给 `llm-app`
3. 按 manifest 声明的 `transport + endpoint + operation` 调对应 app 服务

## 目录结构

- `tool-app/manifests/*.json`
  app/tool 声明式定义
- `tool-app/demo_apps/*.py`
  demo app 服务进程
- `tool-app/demo_data/`
  notes/planner 这类 demo app 的本地数据目录
- `tool-app/demo_rpc.py`
  所有 demo app 共享的 UDS framed JSON RPC helper

## 当前 demo apps

### notes_app

manifest：

- [01_notes_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/01_notes_app.json)

服务：

- [notes_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/notes_app.py)

工具：

- `note_create`
- `note_list`
- `note_read`
- `note_search`

说明：

- 数据存放在 `tool-app/demo_data/notes/`
- `note_list` 现在支持 `query`，`note_search` 返回更适合后续 `note_read` 的标识符和摘录
- 更像一个轻量本地笔记应用

### workspace_app

manifest：

- [02_workspace_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/02_workspace_app.json)

服务：

- [workspace_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/workspace_app.py)

工具：

- `workspace_overview`
- `read_document`
- `write_document`
- `move_document`

说明：

- 仍然只允许仓库根目录下的相对路径
- 更像一个面向当前工作区的文档应用

### planner_app

manifest：

- [03_planner_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/03_planner_app.json)

服务：

- [planner_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/planner_app.py)

工具：

- `task_add`
- `task_list`
- `task_update`

说明：

- 数据存放在 `tool-app/demo_data/planner/tasks.json`
- `task_list` 现在支持 `query` 和 `priority` 过滤，更适合作为 `task_update` 前的解析步骤
- 更像一个本地待办/计划应用

### desktop_app

manifest：

- [04_desktop_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/04_desktop_app.json)

服务：

- [desktop_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/desktop_app.py)

工具：

- `desktop_snapshot`
- `open_url`
- `show_notification`

说明：

- `open_url` 依赖 `xdg-open` 或 `gio`
- `show_notification` 依赖 `notify-send`
- 更像桌面伴随型 app，而不是调试工具集合

### calendar_app

manifest：

- [05_calendar_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/05_calendar_app.json)

服务：

- [calendar_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/calendar_app.py)

工具：

- `event_create`
- `event_list`
- `event_update`

说明：

- 数据存放在 `tool-app/demo_data/calendar/events.json`
- `event_list` 现在支持 `query`，更适合作为 `event_update` 前的解析步骤
- 更像一个轻量本地日历应用

### contacts_app

manifest：

- [06_contacts_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/06_contacts_app.json)

服务：

- [contacts_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/contacts_app.py)

工具：

- `contact_add`
- `contact_list`
- `contact_find`

说明：

- 数据存放在 `tool-app/demo_data/contacts/contacts.json`
- 更像一个轻量本地联系人应用

### launcher_app

manifest：

- [07_launcher_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/07_launcher_app.json)

服务：

- [launcher_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/launcher_app.py)

工具：

- `list_launchable_apps`
- `launch_app`
- `open_with_app`

说明：

- 直接桥接 Linux 系统中已有的 `.desktop` 应用和可执行文件
- 更像一个真实应用入口桥接层，而不是本地数据型 demo app
- `launch_app` / `open_with_app` 依赖图形桌面会话

### bridge_app

manifest：

- [08_bridge_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/08_bridge_app.json)

服务：

- [bridge_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/bridge_app.py)

工具：

- `list_desktop_entries`
- `launch_desktop_entry`
- `run_cli_entry`
- `call_dbus_method`

说明：

- 把 Linux 真实应用入口整理成 manifest 可调用工具
- 覆盖三类真实入口：
  - CLI 参数
  - `.desktop` / GApplication
  - D-Bus / Freedesktop 接口
- 更像一个真实接口桥接样本库，而不是本地数据型 app

### file_manager_app

manifest：

- [09_file_manager_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/09_file_manager_app.json)

服务：

- [file_manager_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/file_manager_app.py)

工具：

- `open_directory`
- `reveal_path`
- `show_item_properties`

说明：

- manifest 直接描述文件管理语义，而不是 generic D-Bus 调用
- 底层桥接标准 `org.freedesktop.FileManager1` 接口

### calendar_desktop_app

manifest：

- [10_calendar_desktop_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/10_calendar_desktop_app.json)

服务：

- [calendar_desktop_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/calendar_desktop_app.py)

工具：

- `open_calendar`
- `open_calendar_file`

说明：

- manifest 直接描述 GNOME Calendar 的语义能力
- 底层桥接 `org.freedesktop.Application` D-Bus 接口

### mail_client_app

manifest：

- [11_mail_client_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/11_mail_client_app.json)

服务：

- [mail_client_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/mail_client_app.py)

工具：

- `open_inbox`
- `compose_email`

说明：

- manifest 直接描述 Thunderbird 的邮件能力
- 底层桥接 Thunderbird 的真实 CLI compose 入口

### document_viewer_app

manifest：

- [12_document_viewer_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/12_document_viewer_app.json)

服务：

- [document_viewer_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/document_viewer_app.py)

工具：

- `open_document`
- `open_document_page`

说明：

- manifest 直接描述 Evince 的文档查看能力
- 底层桥接 Evince 的真实 CLI 参数

### browser_app

manifest：

- [13_browser_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/13_browser_app.json)

服务：

- [browser_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/browser_app.py)

工具：

- `open_tab`
- `open_private_window`
- `search_web`

说明：

- manifest 直接描述 Firefox 的浏览器语义能力
- 底层桥接 Firefox 的真实 CLI 参数

### code_editor_app

manifest：

- [14_code_editor_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/14_code_editor_app.json)

服务：

- [code_editor_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/code_editor_app.py)

工具：

- `open_path`
- `open_file_at_line`
- `compare_files`

说明：

- manifest 直接描述 VS Code 的编辑器语义能力
- 底层桥接 `code` 的真实 CLI 参数

## manifest 作用

manifest 同时承载两类信息：

- 语义信息
  - `name`
  - `description`
  - `input_schema`
  - `examples`
- 运行时绑定信息
  - `transport`
  - `endpoint`
  - `operation`

其中：

- `llm-app` 只使用语义信息
- `mcpd` 同时使用语义信息和运行时绑定信息

语义 hash 只覆盖语义字段本身，不覆盖 `transport` / `endpoint` / `operation` 这类运行时绑定信息。

## 当前约束

- `uds_rpc` 仍是主力 transport，仓库默认 demo 同时提供一个 `uds_abstract` backend（[manifests/16_abstract_demo_app.json](manifests/16_abstract_demo_app.json)）
- `vsock_rpc` 名字保留但 dialer 未实现，validator 直接拒绝——后续随 peer attestation 设计一并评估
- path-based `uds_rpc` endpoint 默认需要位于 `/tmp/linux-mcp-apps/`，或匹配 operator 配置的 allow prefixes
- `uds_abstract` endpoint 需要匹配 operator 配置的 `allow_name_pattern`（默认由 [config/mcpd.demo.toml](../config/mcpd.demo.toml) 放行）
- `tool_id` 需要在所有 manifest 中全局唯一

## demo RPC 协议

共享 helper 在 [demo_rpc.py](/home/lxh/Code/linux-mcp/tool-app/demo_rpc.py)。

当前协议：

- Unix Domain Socket
- 4-byte big-endian length prefix
- UTF-8 JSON object

`mcpd` 发给 app 的请求：

```json
{
  "req_id": 1,
  "agent_id": "a1",
  "tool_id": 1,
  "operation": "note_create",
  "payload": {
    "title": "Daily Standup",
    "body": "Blocked on schema sync review."
  }
}
```

app 返回：

```json
{
  "req_id": 1,
  "status": "ok",
  "result": {},
  "error": "",
  "t_ms": 12
}
```

## 启动方式

推荐用统一脚本启动全部 demo app：

```bash
bash scripts/run_tool_services.sh
```

这个脚本会：

- 遍历 `tool-app/manifests/*.json`
- 读取每个 manifest 的 `demo_entrypoint`
- 自动构建仓库自带的 native demo 二进制（如果缺失）
- 对 `uds_rpc` 和 `uds_abstract` manifest 启动对应服务
- 等待 endpoint socket ready

停止：

```bash
bash scripts/stop_tool_services.sh
```

## 当前边界与限制

- 这些 app 仍然是 demo services，但比之前更接近独立 app 语义
- 仓库当前提供的 demo manifests 都走 `uds_rpc`；非 `uds_rpc` transport 需要额外配置与自定义启动方式
- 返回结果仍然是 JSON object
- 语义字段变更会影响 `mcpd` registry 和内核里的 `tool_hash`
- 运行时绑定字段变更会影响 `mcpd` 的路由与内核 catalog epoch，但不会改变语义 hash
