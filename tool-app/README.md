# tool-app

`tool-app` 目录包含两类内容：

- manifest 定义
- demo tool services

当前系统里，`mcpd` 不会 import 这些 app 的 Python 代码来直接执行函数。它只会：

1. 读取 manifest
2. 把语义字段暴露给 `llm-app`
3. 按 manifest 声明的 `transport + endpoint + operation` 调用对应 app 服务

## 目录结构

- `tool-app/manifests/*.json`
  app/tool 声明式定义
- `tool-app/demo_apps/*.py`
  demo app 服务进程
- `tool-app/demo_rpc.py`
  所有 demo app 共享的 UDS framed JSON RPC helper

## manifest 作用

manifest 是当前工具目录的来源。

它同时承载两种信息：

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

## 当前 manifest 字段

app 级字段：

- `app_id`
- `app_name`
- `transport`
- `endpoint`
- `demo_entrypoint`
- `tools`

tool 级字段：

- `tool_id`
- `name`
- `risk_tags`
- `operation`
- `timeout_ms`
- `description`
- `input_schema`
- `examples`

当前约束：

- 只支持 `transport = "uds_rpc"`
- endpoint 必须位于 `/tmp/linux-mcp-apps/`
- `tool_id` 需要在所有 manifest 中全局唯一

## 当前 demo apps

### settings_app

manifest：

- [01_settings_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/01_settings_app.json)

服务：

- [settings_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/settings_app.py)

当前工具：

- `cpu_burn`
- `sys_info`
- `time_now`
- `volume_control`

说明：

- `cpu_burn` 当前带有 `resource_intensive` 静态风险标签，供内核在请求时结合上下文做动态决策
- `volume_control` 依赖宿主机 `pactl` 或 `amixer`

### file_manager_app

manifest：

- [02_file_manager_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/02_file_manager_app.json)

服务：

- [file_manager_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/file_manager_app.py)

当前工具：

- `text_stats`
- `file_preview`
- `hash_text`
- `file_create`
- `file_list`
- `file_delete`
- `file_copy`
- `file_rename`

说明：

- 只允许仓库根目录下的相对路径
- 禁止绝对路径
- 禁止 `..`
- 对读取、写入、复制做了大小上限保护

### calculator_app

manifest：

- [03_calculator_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/03_calculator_app.json)

服务：

- [calculator_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/calculator_app.py)

当前工具：

- `calc`

说明：

- 使用受限 AST 解析算术表达式
- 不是任意 Python 执行器

### utility_app

manifest：

- [04_utility_app.json](/home/lxh/Code/linux-mcp/tool-app/manifests/04_utility_app.json)

服务：

- [utility_app.py](/home/lxh/Code/linux-mcp/tool-app/demo_apps/utility_app.py)

当前工具：

- `echo`

说明：

- 主要用于调试回路和最简单的端到端检查

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
  "tool_id": 2,
  "operation": "cpu_burn",
  "payload": {"ms": 200}
}
```

app 返回：

```json
{
  "req_id": 1,
  "status": "ok",
  "result": {},
  "error": "",
  "t_ms": 200
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

- 这些 app 是 demo services，不是完整生产实现
- 目前所有 app 都走同一种 transport：`uds_rpc`
- 返回结果仍然是 JSON object
- 还没有单独的大输出数据面
- manifest 变更会影响 `mcpd` registry 和内核里的 `tool_hash`
