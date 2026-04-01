# linux-mcp

`linux-mcp` 是一个把 Linux 内核治理面、用户态工具网关、demo tool app，以及一个基于 LLM 的客户端串起来的 clean-room 原型。

当前代码已经不是“分阶段草图”，而是一套可以实际跑通的端到端链路：

- 内核模块 `kernel_mcp` 负责 Generic Netlink 仲裁和 sysfs 暴露
- `mcpd` 负责加载 manifest、同步工具注册、转发执行、回报完成状态
- `tool-app` 里的 demo app 通过 Unix Domain Socket RPC 提供真实工具能力
- `llm-app` 通过 DeepSeek 选择 app、tool 和 payload，然后只和 `mcpd` 通信

## 现在这套代码实际做了什么

一次请求的真实路径如下：

```text
llm-app
  -> /tmp/mcpd.sock
  -> mcpd
     -> Generic Netlink: agent register / tool request / tool complete
     -> tool manifest registry
     -> Unix Domain Socket RPC -> demo app
  -> result back to llm-app
```

对应到当前实现：

1. `mcpd` 启动时加载 `tool-app/manifests/*.json`
2. 每个 manifest tool 会被注册到内核，并带上 `tool_id/name/perm/cost/hash`
3. `llm-app` 先调用 `list_apps`
4. `llm-app` 用 DeepSeek 从 app catalog 里选一个 app
5. `llm-app` 再调用 `list_tools(app_id=...)`
6. `llm-app` 用 DeepSeek 从该 app 的 tools 里选一个 tool，并构造 payload
7. `llm-app` 发送 `tool:exec` 给 `mcpd`
8. `mcpd` 先确保 agent 已注册，再向内核发起仲裁
9. 内核返回 `ALLOW` / `DENY` / `DEFER`
10. 若允许，`mcpd` 通过 UDS RPC 调用对应 app 的 `operation`
11. 执行结束后，`mcpd` 再向内核上报 `tool_complete`
12. agent/tool 状态可从 `/sys/kernel/mcp/...` 读取

## 当前仓库结构

- `kernel-mcp/`
  Linux 内核模块。包含 Generic Netlink family、agent/tool 状态、sysfs 生命周期。
- `mcpd/`
  用户态网关。负责 manifest 加载、工具目录暴露、内核仲裁、工具调用。
- `tool-app/`
  demo app 服务和 manifest 定义。
- `llm-app/`
  CLI 和 GUI 客户端，共享同一套路由与 payload 构造逻辑。
- `client/`
  C/Python 侧的 netlink schema 和调试用小工具。
- `scripts/`
  构建、加载、启动、停止、验收脚本。

当前仓库里没有旧文档里提到的 `bench/`、`results/`、`plots/` 主流程实现，根目录 `Makefile` 目前只保留 schema 校验入口。

## 组件说明

### 1. kernel-mcp

内核模块源码在 [kernel-mcp/src/kernel_mcp_main.c](/home/lxh/Code/linux-mcp/kernel-mcp/src/kernel_mcp_main.c)。

当前已实现：

- Generic Netlink family：`KERNEL_MCP`
- 命令常量和属性常量通过 UAPI 与 Python 同步
- tool registry
- agent registry
- sysfs 树：
  - `/sys/kernel/mcp/tools/<tool_id>/`
  - `/sys/kernel/mcp/agents/<agent_id>/`
- `tool_request` 仲裁
- `tool_complete` 完成回报

当前仲裁规则不是通用策略引擎，而是一个很明确的 demo 规则：

- 未注册 agent：`DENY`
- `tool_hash` 不匹配：`DENY`
- 带高风险标签的工具会返回 `DEFER` 并创建 approval ticket
- 其他工具默认 `ALLOW`

内核只负责 control-plane 仲裁、tool registry 对齐和 approval ticket 生命周期；限流、重试和更复杂的执行策略应由 `mcpd` 在用户空间完成。

### 2. mcpd

主入口在 [mcpd/server.py](/home/lxh/Code/linux-mcp/mcpd/server.py)。

它做的事情很具体：

- 加载 manifest
- 校验 manifest 格式和 endpoint 约束
- 生成语义 hash
- 启动时把 manifest tool 注册进内核
- 提供 UDS framed JSON RPC：`/tmp/mcpd.sock`
- 对外暴露：
  - `{"sys":"list_apps"}`
  - `{"sys":"list_tools"}`
  - `{"sys":"list_tools","app_id":"..."}`
  - `{"kind":"tool:exec", ...}`
- 执行前做 payload schema 校验
- 调用具体 app 的 `endpoint + operation`
- 将完成状态回报给内核

manifest 加载逻辑在 [mcpd/manifest_loader.py](/home/lxh/Code/linux-mcp/mcpd/manifest_loader.py)，同步核对工具表的脚本在 [mcpd/reconcile_kernel.py](/home/lxh/Code/linux-mcp/mcpd/reconcile_kernel.py)。

### 3. tool-app

manifest 目录：`tool-app/manifests/*.json`

当前共有 6 个 app、20 个 tool：

- `notes_app`
  - `note_create`
  - `note_list`
  - `note_read`
  - `note_search`
- `workspace_app`
  - `workspace_overview`
  - `read_document`
  - `write_document`
  - `move_document`
- `planner_app`
  - `task_add`
  - `task_list`
  - `task_update`
- `desktop_app`
  - `desktop_snapshot`
  - `open_url`
  - `show_notification`
- `calendar_app`
  - `event_create`
  - `event_list`
  - `event_update`
- `contacts_app`
  - `contact_add`
  - `contact_list`
  - `contact_find`

所有 demo app 都通过 [tool-app/demo_rpc.py](/home/lxh/Code/linux-mcp/tool-app/demo_rpc.py) 提供统一的 framed JSON over UDS 协议。

几个当前实现里的关键边界：

- `workspace_app` 只允许操作仓库根目录下的相对路径
- 禁止绝对路径和 `..`
- `notes_app` 和 `planner_app` 会把 demo 数据写到 `tool-app/demo_data/`
- `calendar_app` 和 `contacts_app` 也会把 demo 数据写到 `tool-app/demo_data/`
- `desktop_app.open_url` 依赖本机 `xdg-open` 或 `gio`
- `desktop_app.show_notification` 依赖本机 `notify-send`

### 4. llm-app

CLI 在 [llm-app/cli.py](/home/lxh/Code/linux-mcp/llm-app/cli.py)，GUI 在 [llm-app/gui_app.py](/home/lxh/Code/linux-mcp/llm-app/gui_app.py)。

当前 `llm-app` 的行为要点：

- 它不会直接访问 tool endpoint
- 它只看 `mcpd` 暴露出来的语义字段：
  - `tool_id`
  - `name`
  - `app_id`
  - `app_name`
  - `description`
  - `input_schema`
  - `examples`
  - `perm`
  - `cost`
  - `hash`
- app 选择、tool 选择、payload 构造都依赖 DeepSeek API

因此，当前 CLI/GUI 不是“无模型规则路由”，而是“模型驱动路由器”。

运行 `llm-app` 需要：

- `mcpd` 已启动
- `DEEPSEEK_API_KEY` 已设置
- GUI 还需要 `PySide6`

## manifest 约定

manifest 是当前系统的单一语义来源。

app 级字段：

- `app_id`
- `app_name`
- `transport`
- `endpoint`
- `demo_entrypoint`（demo 服务启动脚本，可选但当前脚本会使用）

tool 级字段：

- `tool_id`
- `name`
- `perm`
- `cost`
- `operation`
- `timeout_ms`
- `description`
- `input_schema`
- `examples`

当前只支持：

- `transport = "uds_rpc"`
- endpoint 必须位于 `/tmp/linux-mcp-apps/` 下

`manifest_hash` 由以下语义字段计算后截断为 8 位十六进制：

- `tool_id`
- `name`
- `app_id`
- `app_name`
- `perm`
- `cost`
- `description`
- `input_schema`
- `examples`

## 依赖与前提

基础依赖：

- Linux
- `bash`
- `make`
- `gcc`
- `python3`
- 对应内核版本的 headers：`/lib/modules/$(uname -r)/build`

运行时依赖：

- 内核模块加载需要 root
- `mcpd` 依赖已构建的 `client/bin/genl_register_tool` 和 `client/bin/genl_list_tools`
- `llm-app` 依赖 `DEEPSEEK_API_KEY`
- GUI 依赖 `PySide6`
- 部分音量工具依赖 `pactl` 或 `amixer`

可选：

- `pyroute2` 只在部分检查/环境准备里会用到；当前主 netlink client 走的是原生 socket

## 快速开始

建议从仓库根目录运行：

```bash
cd ~/Code/linux-mcp
```

### 1. 环境检查

```bash
bash scripts/bootstrap.sh
bash scripts/run_smoke.sh
```

### 2. 构建与加载内核模块

```bash
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
```

### 3. 构建 client 小工具

```bash
make -C client clean
make -C client
make schema-verify
```

### 4. 启动 demo app 和 mcpd

```bash
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh
```

### 5. 配置 DeepSeek 并执行一次请求

```bash
export DEEPSEEK_API_KEY="your_key"
python3 llm-app/cli.py --once "hello"
python3 llm-app/cli.py --once "burn cpu for 200ms"
python3 llm-app/cli.py --once "show system info"
python3 llm-app/cli.py --once "preview README.md 20 lines"
```

### 6. 停止用户态服务

```bash
bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
```

### 7. 卸载模块

```bash
sudo bash scripts/unload_module.sh
```

## GUI 开发/运行方式

仓库里当前推荐的 GUI 运行方式是：

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

如果没有安装 `PySide6`：

```bash
sudo apt-get install python3-pyside6
```

或者：

```bash
pip install PySide6
```

## 常用脚本

- `bash scripts/bootstrap.sh`
  初始化目录和 Python 环境检查。
- `bash scripts/run_smoke.sh`
  跑基础结构、shell 语法、schema 同步检查。
- `sudo bash scripts/build_kernel.sh`
  编译内核模块。
- `sudo bash scripts/load_module.sh`
  加载模块。
- `sudo bash scripts/unload_module.sh`
  卸载模块。
- `bash scripts/run_tool_services.sh`
  启动所有 demo app。
- `bash scripts/stop_tool_services.sh`
  停止所有 demo app。
- `bash scripts/run_mcpd.sh`
  启动 `mcpd`，等待 socket ready，并自动执行 reconcile。
- `bash scripts/stop_mcpd.sh`
  停止 `mcpd`。
- `sudo bash scripts/reload_10x.sh`
  连续装卸模块 10 次并扫描 `dmesg`。
- `sudo bash scripts/demo_acceptance.sh`
  跑一遍端到端验收。

## 观测点

工具状态：

```bash
ls /sys/kernel/mcp/tools
cat /sys/kernel/mcp/tools/2/name
cat /sys/kernel/mcp/tools/2/hash
```

agent 状态：

```bash
ls /sys/kernel/mcp/agents
cat /sys/kernel/mcp/agents/a1/allow
cat /sys/kernel/mcp/agents/a1/defer
cat /sys/kernel/mcp/agents/a1/completed_ok
cat /sys/kernel/mcp/agents/a1/last_reason
cat /sys/kernel/mcp/agents/a1/last_exec_ms
```

日志：

```bash
cat /tmp/mcpd-$(id -u).log
ls /tmp/linux-mcp-app-*.log
```

## 当前限制

- app/tool/payload 选择完全依赖 DeepSeek API，不提供离线 fallback
- 内核仲裁目前只有 demo 级规则：未注册 agent、hash 校验，以及基于风险标签的 approval gate
- `mcpd` 只支持 `uds_rpc`
- 结果传输仍然是 JSON framed RPC，尚未实现“大输出单独走数据通道”的完整数据面
- 还没有成体系的自动化测试目录；当前主要依赖 smoke、acceptance、手工 sysfs 验证

## 推荐验收流程

如果你想确认当前仓库在本机是通的，最直接的是跑：

```bash
sudo bash scripts/demo_acceptance.sh
```

它会依次执行：

- 构建内核模块
- 加载模块
- 构建 client
- 启动 demo app
- 启动 `mcpd`
- 检查 `DEEPSEEK_API_KEY`
- 跑两次 `llm-app`
- 读取 sysfs agent 计数
- 停止服务
- 卸载模块
- 连续装卸模块 10 次
