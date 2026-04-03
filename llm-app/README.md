# llm-app

`llm-app` 是当前仓库里的 LLM 客户端层，提供 CLI 和 GUI 两种入口。

它的职责不是直接执行工具，而是：

1. 从 `mcpd` 获取 app/tool 语义目录
2. 用 DeepSeek 生成一个最小可执行 plan
3. 按 plan 顺序执行 1 到 N 个 tool step
4. 在 step 间传递上一步结果里的标识符或字段
5. 把每一步 `tool:exec` 请求发给 `mcpd`

## 当前真实链路

```text
llm-app
  -> /tmp/mcpd.sock
  -> mcpd
     -> kernel arbitration
     -> tool app UDS RPC
  -> llm-app
```

`llm-app` 不会：

- 直接访问 tool app 的 socket
- 直接执行工具逻辑
- 直接和 Generic Netlink 打交道

## 当前行为模型

共享逻辑在 [app_logic.py](/home/lxh/Code/linux-mcp/llm-app/app_logic.py)。

当前流程是：

1. 调 `{"sys":"list_apps"}`
2. 调 `{"sys":"list_tools"}`
3. 用 DeepSeek 先从 catalog 里选出一小组候选 tool
4. 再基于候选 tool 生成一个严格 JSON plan
5. 每个 plan step 选择一个 `tool_id`
6. 每个 step 先解析 partial payload，再按 schema 补全最终 payload
7. 如果后一步需要前一步结果，会通过显式 selector 或 `$alias.path` 引用前一步返回值
8. 运行时上下文会显式提供 `context.workspace_root_rel` 之类的环境值
9. 本地按 `input_schema` 校验 step payload
10. 先通过 `open_session` 获取短期 `session_id`
11. 逐步发带 `session_id` 的 `{"kind":"tool:exec", ...}` 给 `mcpd`

这意味着当前 `llm-app` 强依赖：

- `DEEPSEEK_API_KEY`
- `mcpd` 正常返回 catalog
- `mcpd` 能成功签发 session

如果没配置 `DEEPSEEK_API_KEY`，CLI 和 GUI 都会直接失败，不存在本地 fallback 路由。

## 可见字段

`llm-app` 只能看到 `mcpd` 暴露出来的语义字段：

- `tool_id`
- `name`
- `app_id`
- `app_name`
- `description`
- `input_schema`
- `examples`
- `risk_tags`
- `risk_flags`
- `hash`

它看不到：

- app endpoint
- transport runtime 细节
- operation 名称

## CLI

CLI 入口在 [cli.py](/home/lxh/Code/linux-mcp/llm-app/cli.py)。

单次执行：

```bash
python3 llm-app/cli.py --once "hello"
python3 llm-app/cli.py --once "burn cpu for 200ms"
python3 llm-app/cli.py --once "show system info"
python3 llm-app/cli.py --once "calculate (21 + 7) * 3"
python3 llm-app/cli.py --once "preview README.md 20 lines"
python3 llm-app/cli.py --once "hash text hello with sha256"
python3 llm-app/cli.py --once "create file tmp/demo.txt with content hello"
```

REPL：

```bash
python3 llm-app/cli.py --repl
```

REPL 内置命令：

- `/help`
- `/apps`
- `/tools`
- `/mode`
- `/mode user`
- `/mode dev`
- `/exit`

常用参数：

- `--agent-id a1`
- `--sock /tmp/mcpd.sock`
- `--mode user|dev`
- `--show-tools`
- `--show-reasons`
- `--show-payload`
- `--deepseek-model ...`
- `--deepseek-url ...`
- `--deepseek-timeout-sec ...`

## GUI

GUI 入口在 [gui_app.py](/home/lxh/Code/linux-mcp/llm-app/gui_app.py)。

启动方式：

```bash
python3 llm-app/gui_app.py
```

也可以显式指定界面输出模式：

```bash
python3 llm-app/gui_app.py --mode user
python3 llm-app/gui_app.py --mode dev
```

仓库当前推荐的 GUI 开发/运行方式：

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

GUI 和 CLI 使用同一套共享选择逻辑，不是两套不同实现。

- `user` 模式下，CLI/GUI 默认显示简洁的用户结果摘要
- `dev` 模式下，会显示 plan、step route、payload、执行结果等调试细节
- GUI 左侧默认只突出 app 概览，tool catalog 需要手动展开查看

如果某一步被内核仲裁成 `DEFER`，CLI/GUI 会向用户请求确认，再通过带 `session_id` 的 `approval_reply` 链路继续执行或拒绝。

另外，`llm-app` 现在不会靠硬编码工具名来判断这类行为，而是读取 tool catalog 里的 `path_semantics` 和 `approval_policy`。只要新工具在 manifest 里正确声明“这是 repo 内路径还是宿主机路径”“何时要用户确认”，CLI/GUI 就会自动沿用同一套路由和审批行为。

## 运行前提

启动 `llm-app` 之前，通常要先确保：

```bash
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh
export DEEPSEEK_API_KEY="your_key"
```

如果跑 GUI，还需要 `PySide6`：

```bash
sudo apt-get install python3-pyside6
```

或者：

```bash
pip install PySide6
```

## 典型输出

CLI/GUI 在 `user` 模式下，通常会输出：

- 当前 catalog 里的 app/tool 数量
- 简洁的执行摘要
- 更贴近用户任务的结果说明

CLI/GUI 在 `dev` 模式下，通常会额外输出：

- plan 原因
- 每一步的 `app_name/app_id`
- 每一步的 `tool_name/tool_id`
- 每一步的 payload、执行状态和耗时
- 每一步结果，以及最终错误

启用 `--show-payload` 时，会打印每一步真正发送给 `mcpd` 的 payload。

## 当前限制

- plan 生成和 step payload 构造都依赖 DeepSeek
- 没有离线 fallback
- 多步执行质量仍然取决于 manifest 语义和模型规划质量
- `on_empty`、`selector`、`runtime_context` 都是显式执行语义，不会自动推导任意隐含工作流
- 没有对话记忆压缩或 job 模式
- GUI 只是 demo UI，不是完整产品界面
- 真正的仲裁和执行都发生在 `mcpd` 侧，`llm-app` 只负责语义路由
