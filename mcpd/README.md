# mcpd

`mcpd` 是当前系统里的用户态网关，也是唯一同时理解以下两层信息的进程：

- manifest 语义目录
- tool app 运行时 endpoint / operation

它位于 `llm-app` 和内核治理面、tool app 执行面之间。

## 当前职责

主入口在 [server.py](/home/lxh/Code/linux-mcp/mcpd/server.py)。

当前实现中，`mcpd` 负责：

- 加载 `tool-app/manifests/*.json`
- 校验 manifest 格式
- 计算语义 hash
- 把 manifest tool 注册进内核
- 维护 app/tool runtime registry
- 提供 `/tmp/mcpd.sock` 上的 framed JSON RPC
- 处理 `list_apps` / `list_tools`
- 基于 UDS `SO_PEERCRED` 读取真实客户端 `pid/uid/gid`
- 处理 `open_session`
- 处理 `tool:exec`
- 将 session 绑定到 peer identity
- 为每个 session 派生 `binding_hash / binding_epoch`
- 为首次出现的服务端 `agent_id` 做带 binding 元数据的 netlink agent register
- 通过内核做仲裁
- 调用 tool app 的 UDS endpoint
- 向内核回报 `tool_complete`

## 运行模型

```text
llm-app -> mcpd -> kernel netlink
                -> tool app UDS RPC
```

更具体地说：

1. 启动时加载所有 manifest
2. 将每个 tool 注册到内核
3. 对外暴露 app/tool catalog
4. 通过 UDS peer credentials 识别本地客户端
5. 为客户端签发短期 session 和服务端生成的 `agent_id`
6. 从 session 派生 `binding_hash / binding_epoch`
7. 接收带 `session_id` 的 `tool:exec`
8. 校验 session、请求和 payload
9. 调用内核 `tool_request`
10. 若 `ALLOW`，再调用对应 app 的 `operation`
11. 执行后调用内核 `tool_complete`

## public RPC

当前 socket：

- `/tmp/mcpd.sock`

当前协议：

- 4-byte big-endian length prefix
- UTF-8 JSON object

支持的公开请求：

```json
{"sys":"list_apps"}
{"sys":"list_tools"}
{"sys":"list_tools","app_id":"notes_app"}
{"sys":"open_session","client_name":"llm-app","ttl_ms":1800000}
{"sys":"approval_reply","session_id":"32hex","ticket_id":2,"decision":"approve","reason":"approved in llm-app","ttl_ms":300000}
{"kind":"tool:exec","req_id":1,"session_id":"32hex","app_id":"notes_app","tool_id":1,"tool_hash":"8hex","payload":{"title":"Daily Standup","body":"Blocked on review"}} 
```

`list_apps` 返回每个 app 的：

- `app_id`
- `app_name`
- `tool_count`
- `tool_ids`
- `tool_names`

`list_tools` 返回每个 tool 的：

- `tool_id`
- `name`
- `app_id`
- `app_name`
- `description`
- `input_schema`
- `examples`
- `path_semantics`
- `approval_policy`
- `risk_tags`
- `risk_flags`
- `hash`

`tool:exec` 返回统一结构：

```json
{
  "req_id": 1,
  "status": "ok",
  "result": {},
  "error": "",
  "t_ms": 12
}
```

如果是仲裁错误或工具错误，`status` 会是 `"error"`。

## 与内核的关系

netlink client 在 [netlink_client.py](/home/lxh/Code/linux-mcp/mcpd/netlink_client.py)。

`mcpd` 会调用：

- `register_tool`
- `register_agent`
- `tool_request`
- `tool_complete`
- `approval_decide`

其中 `register_agent` / `tool_request` / `approval_decide` 都会带上 agent binding 元数据：

- `binding_hash`
- `binding_epoch`

当前 `mcpd` 对 `DEFER` 的处理方式是：

- 先把 `ticket_id` 和原始待执行请求缓存到用户态 pending approval 表
- 把 `ticket_id` 返回给调用方
- 由同一 session / peer identity 的用户态审批端再调用 `{"sys":"approval_reply",...}` 返回批准或拒绝
- `mcpd` 在批准后带同一 agent binding 调用 `approval_decide`，然后继续执行原始请求
- 如果用户拒绝，`mcpd` 直接返回 `approval declined by user`

当前仓库约定里，rate limiting 和重试策略应由 `mcpd` 在用户空间完成，不在内核协议或 agent 内核状态里维护 token bucket。

另外，`mcpd` 运行期间会在处理 `list_apps`、`list_tools` 和 `tool:exec` 前检查 manifest 目录是否变化；如果 `tool-app/manifests/*.json` 有新增、删除或修改，它会自动刷新内存 registry 并重新把当前 manifest tools 同步到内核 registry，无需手动重启 `mcpd`。

## 与 manifest 的关系

manifest loader 在 [manifest_loader.py](/home/lxh/Code/linux-mcp/mcpd/manifest_loader.py)。

当前 manifest 约束：

- app 级必填：
  - `app_id`
  - `app_name`
  - `transport`
  - `endpoint`
  - `tools`
- tool 级必填：
  - `tool_id`
  - `name`
  - `risk_tags`
  - `operation`
  - `description`
  - `input_schema`
  - `examples`
  - `path_semantics`（可选）
  - `approval_policy`（可选）
- 仅支持 `transport = "uds_rpc"`
- endpoint 必须位于 `/tmp/linux-mcp-apps/`
- `tool_id` 必须全局唯一

语义 hash 当前只由这些字段决定：

- `tool_id`
- `name`
- `app_id`
- `app_name`
- `risk_tags`
- `description`
- `input_schema`
- `examples`
- `path_semantics`
- `approval_policy`

## 与 tool app 的关系

当前只支持 `uds_rpc` transport。

`mcpd` 发给 app 的请求结构：

```json
{
  "req_id": 1,
  "agent_id": "ag_3e8_1234_deadbeef",
  "tool_id": 1,
  "operation": "note_create",
  "payload": {
    "title": "Daily Standup",
    "body": "Blocked on review"
  }
}
```

期望 app 返回：

```json
{
  "req_id": 1,
  "status": "ok",
  "result": {},
  "error": "",
  "t_ms": 201
}
```

## 启动方式

通常从仓库根目录：

```bash
bash scripts/run_mcpd.sh
```

这个脚本会先检查：

- `kernel_mcp` 模块已加载
- `/sys/kernel/mcp/tools` 和 `/sys/kernel/mcp/agents` 存在

然后它会：

- 后台启动 `mcpd`
- 等待 `/tmp/mcpd.sock` ready
- 等待 manifest tools 出现在 `list_tools`
- 调用 [reconcile_kernel.py](/home/lxh/Code/linux-mcp/mcpd/reconcile_kernel.py) 做核对

停止：

```bash
bash scripts/stop_mcpd.sh
```

## 调试与观测

日志默认在：

```bash
cat /tmp/mcpd-$(id -u).log
```

如果只想做基本 RPC 自检，可运行：

```bash
python3 llm-app/rpc.py
```

## 当前限制

- 仅支持 `uds_rpc`
- catalog 只保留语义字段给 `llm-app`
- payload schema 校验是轻量级的，不是完整 JSON Schema 引擎
- 大输出仍走 framed JSON，没有单独数据面
- 没有 async job queue 或长期任务状态查询
