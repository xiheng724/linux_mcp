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
2. 每个 manifest tool 会被注册到内核，并带上 `tool_id/name/risk/hash`
3. `llm-app` 先调用 `list_apps`
4. `llm-app` 用 DeepSeek 从 app/tool catalog 里构造执行计划
5. `llm-app` 再按计划查询 `list_tools(app_id=...)` 并补全 step payload
6. `llm-app` 先通过 `open_session` 从 `mcpd` 获取短期 `session_id` 和服务端签发的 `agent_id`
7. `llm-app` 再发送带 `session_id` 的 `tool:exec` 给 `mcpd`
8. `mcpd` 先用 UDS peer credentials 校验 session，派生 `binding_hash / binding_epoch`，再确保对应 agent 已注册，然后向内核发起仲裁
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
- agent 绑定摘要：
  - `binding_hash`
  - `binding_epoch`
- approval ticket 与 agent 绑定摘要做一致性校验

当前仲裁规则不是通用策略引擎，而是一个很明确的 demo 规则：

- 未注册 agent：`DENY`
- `tool_hash` 不匹配：`DENY`
- 带高风险标签的工具会返回 `DEFER` 并创建 approval ticket
- 其他工具默认 `ALLOW`

内核只负责 control-plane 仲裁、tool registry 对齐、agent 绑定摘要校验和 approval ticket 生命周期；session 管理、manifest 解释、限流、重试和更复杂的执行策略应由 `mcpd` 在用户空间完成。

### 2. mcpd

主入口在 [mcpd/server.py](/home/lxh/Code/linux-mcp/mcpd/server.py)。

它做的事情很具体：

- 加载 manifest
- 校验 manifest 格式和 endpoint 约束
- 生成语义 hash
- 启动时把 manifest tool 注册进内核
- 提供 UDS framed JSON RPC：`/tmp/mcpd.sock`
- 从 UDS peer credentials 读取真实客户端 `pid/uid/gid`
- 为客户端签发短期 session，并把 session 绑定到 peer identity
- 从 session 派生 `binding_hash / binding_epoch`
- 对外暴露：
  - `{"sys":"list_apps"}`
  - `{"sys":"list_tools"}`
  - `{"sys":"list_tools","app_id":"..."}`
  - `{"sys":"open_session", ...}`
  - `{"kind":"tool:exec", ...}`
- 执行前做 payload schema 校验
- 调用具体 app 的 `endpoint + operation`
- 将完成状态回报给内核
- 将 approval 与 tool request 绑定到同一 agent binding

manifest 加载逻辑在 [mcpd/manifest_loader.py](/home/lxh/Code/linux-mcp/mcpd/manifest_loader.py)，同步核对工具表的脚本在 [mcpd/reconcile_kernel.py](/home/lxh/Code/linux-mcp/mcpd/reconcile_kernel.py)。

`mcpd` 运行期间会自动检查 `tool-app/manifests/*.json` 是否有新增、删除或修改；一旦发现 catalog 变化，会刷新用户态 registry，并把当前 manifest tools 重新同步到内核 registry。也就是说，更新 tool app 后不需要靠重启 `mcpd` 才能让 `llm-app` 看到新 app/tool。

### 3. tool-app

manifest 目录：`tool-app/manifests/*.json`

当前共有 14 个 app、42 个 tool：

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
- `launcher_app`
  - `list_launchable_apps`
  - `launch_app`
  - `open_with_app`
- `bridge_app`
  - `list_desktop_entries`
  - `launch_desktop_entry`
  - `run_cli_entry`
  - `call_dbus_method`
- `file_manager_app`
  - `open_directory`
  - `reveal_path`
  - `show_item_properties`
- `calendar_desktop_app`
  - `open_calendar`
  - `open_calendar_file`
- `mail_client_app`
  - `open_inbox`
  - `compose_email`
- `document_viewer_app`
  - `open_document`
  - `open_document_page`
- `browser_app`
  - `open_tab`
  - `open_private_window`
  - `search_web`
- `code_editor_app`
  - `open_path`
  - `open_file_at_line`
  - `compare_files`

所有 demo app 都通过 [tool-app/demo_rpc.py](/home/lxh/Code/linux-mcp/tool-app/demo_rpc.py) 提供统一的 framed JSON over UDS 协议。

几个当前实现里的关键边界：

- `workspace_app` 只允许操作仓库根目录下的相对路径
- 禁止绝对路径和 `..`
- `notes_app` 和 `planner_app` 会把 demo 数据写到 `tool-app/demo_data/`
- `calendar_app` 和 `contacts_app` 也会把 demo 数据写到 `tool-app/demo_data/`
- `desktop_app.open_url` 依赖本机 `xdg-open` 或 `gio`
- `desktop_app.show_notification` 依赖本机 `notify-send`
- 新增的真实应用语义 app 会桥接 CLI、`.desktop`、D-Bus / Freedesktop 入口
- 这些桥接型 app 依赖当前会话具备可用的 GUI session

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
  - `risk_tags`
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
- `risk_tags`
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
- `risk_tags`
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
- `llm-app` 依赖 `DEEPSEEK_API_KEY`
- GUI 依赖 `PySide6`
- 部分音量工具依赖 `pactl` 或 `amixer`

可选：

- 当前主 netlink client 走的是原生 socket，不依赖 `pyroute2`

## 快速开始

建议从仓库根目录运行：

```bash
cd ~/Code/linux-mcp
```

### 1. 环境检查

```bash
bash scripts/run_smoke.sh
```

### 2. 构建与加载内核模块

```bash
sudo bash scripts/build_kernel.sh
sudo bash scripts/unload_module.sh || true
sudo bash scripts/load_module.sh
```

### 3. 校验 schema 同步

```bash
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
- `bash scripts/run_experiment_suite.sh`
  跑单轮 benchmark 实验。
- `bash scripts/experiments/run_matrix.sh`
  跑多组负载矩阵 benchmark。
- `bash scripts/run_repeated_suite.sh`
  跑重复 benchmark 并生成聚合统计。
- `bash scripts/run_atc_evaluation.sh`
  跑论文导向的综合评估。

## 测试总览

当前仓库没有 `pytest` 或独立 `tests/` 目录，测试主要由脚本化验证组成，可以分成 4 类：

### 1. 静态与结构检查

- `python3 scripts/verify_schema_sync.py`
  检查内核 UAPI 和 Python schema 常量是否同步。
- `make schema-verify`
  等价于运行 schema 同步检查。
- `bash scripts/run_smoke.sh`
  检查仓库目录结构、关键脚本是否存在、shell 语法是否正确、client Python 导入是否正常、schema 是否同步。

### 2. 构建与生命周期验证

- `sudo bash scripts/build_kernel.sh`
  编译内核模块。
- `sudo bash scripts/load_module.sh`
  加载 `kernel_mcp` 模块。
- `sudo bash scripts/unload_module.sh`
  卸载模块。
- `sudo bash scripts/reload_10x.sh`
  连续装卸模块 10 次，并扫描 `dmesg` 中的 OOPS/WARN，主要验证 sysfs/kobject 生命周期和模块反复装载的稳定性。

### 3. 用户态与端到端验收

- `bash scripts/run_tool_services.sh`
  启动全部 demo tool services。
- `bash scripts/run_mcpd.sh`
  启动 `mcpd`，等待 `/tmp/mcpd.sock` 就绪，并自动执行 kernel reconcile。
- `python3 llm-app/cli.py --once "..."`
  做单次 LLM 驱动请求，验证 catalog -> planning -> tool execution 全链路。
- `sudo bash scripts/demo_acceptance.sh`
  这是最完整的端到端验收脚本，会串起：
  - 编译模块
  - 卸载旧模块
  - 加载新模块
  - 清理旧用户态服务
  - 启动 tool services
  - 启动 `mcpd`
  - 检查 `DEEPSEEK_API_KEY`
  - 跑两次 `llm-app/cli.py --once`
  - 检查 sysfs agent 计数
  - 停止服务
  - 卸载模块
  - 跑 `reload_10x`

### 4. 实验评估

实验脚本集中在 [`scripts/experiments/README.md`](/home/lxh/Code/linux-mcp/scripts/experiments/README.md)。
当前主要有 4 条实验入口：

- `bash scripts/run_experiment_suite.sh`
  单轮 benchmark，对比 `direct` 和 `mcpd`。
- `bash scripts/experiments/run_matrix.sh`
  多组请求规模和并发矩阵。
- `bash scripts/run_repeated_suite.sh`
  重复 benchmark，并自动生成聚合 CSV/markdown 报告。
- `bash scripts/run_atc_evaluation.sh`
  更完整的论文导向评估，包含主实验、ablation、trace、policy mix、restart recovery、manifest scale 等。

## 实验测试方法

### A. 单轮 Benchmark

用途：

- 比较 `direct` 与 `mcpd`
- 观察不同并发下吞吐和 tail latency
- 验证负控路径是否稳定 fast-fail

命令：

```bash
cd ~/Code/linux-mcp
bash scripts/run_experiment_suite.sh
```

默认输出：

- `experiment-results/run-<timestamp>/summary.json`
- `experiment-results/run-<timestamp>/report.md`
- `experiment-results/run-<timestamp>/<scenario>.csv`

可调参数示例：

```bash
bash scripts/run_experiment_suite.sh \
  --requests 12000 \
  --concurrency "1,8,16,32,64" \
  --negative-repeats 1200 \
  --max-tools 24
```

### B. Matrix Benchmark

用途：

- 做更大规模的请求量和并发 sweep
- 看结论是否在多组负载下保持一致

命令：

```bash
cd ~/Code/linux-mcp
bash scripts/experiments/run_matrix.sh
```

输出：

- `experiment-results/matrix/run-<timestamp>/summary.json`
- `experiment-results/matrix/run-<timestamp>/report.md`
- `experiment-results/matrix/run-<timestamp>/<scenario>.csv`

### C. Repeated Benchmark

用途：

- 重复运行 benchmark
- 生成均值、中位数、标准差等统计汇总
- 支撑更稳的性能结论

命令：

```bash
cd ~/Code/linux-mcp
bash scripts/run_repeated_suite.sh
```

输出：

- `experiment-results/repeated-suite/run-<timestamp>/raw/run-<timestamp>/...`
- `experiment-results/repeated-suite/run-<timestamp>/aggregate/detailed_report.md`
- `experiment-results/repeated-suite/run-<timestamp>/aggregate/suite_aggregate.csv`
- `experiment-results/repeated-suite/run-<timestamp>/aggregate/suite_ratio_aggregate.csv`

轻量示例：

```bash
bash scripts/run_repeated_suite.sh \
  --skip-start \
  --repeats 3 \
  --requests 1000 \
  --concurrency "1,4,8,16"
```

### D. ATC-Oriented Evaluation

用途：

- 做论文导向的系统评估
- 同时覆盖性能、控制面、approval、安全、恢复和扩展性

当前主实验组：

- `direct`
- `mcpd`
  也就是当前完整的 `kernel_control_plane`
- `forwarder_only`
  只保留 `mcpd` lookup + relay
- `userspace_semantic_plane`
  保留 session/hash/approval 等语义，但不走 kernel netlink；这是 equivalent userspace baseline

命令：

```bash
cd ~/Code/linux-mcp
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh
bash scripts/run_atc_evaluation.sh
```

默认会测：

- E2E overhead
- `forwarder_only` / `userspace_semantic_plane` ablation
- fixed trace workload
- control-plane RPC latency
- negative controls
- approval path
- policy mix
- restart recovery
- manifest scale
- 可选 `reload_10x`

输出：

- `experiment-results/atc/run-<timestamp>/atc_summary.json`
- `experiment-results/atc/run-<timestamp>/atc_report.md`
- `experiment-results/atc/run-<timestamp>/e2e_summaries.csv`
- `experiment-results/atc/run-<timestamp>/variant_summaries.csv`
- `experiment-results/atc/run-<timestamp>/trace_results.csv`
- `experiment-results/atc/run-<timestamp>/policy_mix.csv`
- `experiment-results/atc/run-<timestamp>/control_plane_rpcs.csv`
- `experiment-results/atc/run-<timestamp>/negative_controls.csv`
- `experiment-results/atc/run-<timestamp>/approval_path.csv`
- `experiment-results/atc/run-<timestamp>/restart_recovery.csv`
- `experiment-results/atc/run-<timestamp>/manifest_scale.csv`
- `experiment-results/atc/run-<timestamp>/derived_metrics.csv`
- `experiment-results/atc/run-<timestamp>/selected_tools.csv`

轻量 smoke：

```bash
bash scripts/run_atc_evaluation.sh \
  --skip-start \
  --skip-reload-10x \
  --requests 200 \
  --trace-requests 50 \
  --policy-requests 50 \
  --restart-requests 50 \
  --restart-after 10 \
  --negative-repeats 20 \
  --approval-repeats 10 \
  --rpc-repeats 20 \
  --scale-repeats 2 \
  --concurrency "1,4" \
  --manifest-scales "1,2" \
  --max-tools 8
```

论文级一轮示例：

```bash
bash scripts/run_atc_evaluation.sh \
  --requests 4000 \
  --trace-requests 1000 \
  --policy-requests 1000 \
  --restart-requests 1000 \
  --restart-after 300 \
  --negative-repeats 500 \
  --approval-repeats 100 \
  --rpc-repeats 300 \
  --scale-repeats 10 \
  --concurrency "1,4,8,16,32" \
  --manifest-scales "1,2,4,8" \
  --max-tools 20
```

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
