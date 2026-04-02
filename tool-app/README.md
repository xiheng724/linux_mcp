# tool-app

`tool-app` 目录现在提供 6 个更像独立应用的 demo services，而不是单纯的零散 utility tools。

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

## 当前约束

- 只支持 `transport = "uds_rpc"`
- endpoint 必须位于 `/tmp/linux-mcp-apps/`
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
- 后台启动对应服务
- 等待 endpoint socket ready

停止：

```bash
bash scripts/stop_tool_services.sh
```

## 当前边界与限制

- 这些 app 仍然是 demo services，但比之前更接近独立 app 语义
- 目前所有 app 都走同一种 transport：`uds_rpc`
- 返回结果仍然是 JSON object
- manifest 变更会影响 `mcpd` registry 和内核里的 `tool_hash`
