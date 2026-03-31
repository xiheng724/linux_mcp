# llm-app

`llm-app` 是当前仓库里的 LLM 客户端层，提供 CLI 和 GUI 两种入口。

它的职责不是直接执行工具，而是：

1. 从 `mcpd` 获取 app/tool 语义目录
2. 用 DeepSeek 选择 app
3. 用 DeepSeek 选择 tool
4. 用 DeepSeek 按 `input_schema` 生成 payload
5. 把最终 `tool:exec` 请求发给 `mcpd`

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
2. 用 DeepSeek 从 app 列表里选一个 `app_id`
3. 调 `{"sys":"list_tools","app_id":"..."}`
4. 用 DeepSeek 从 tool 列表里选一个 `tool_id`
5. 用 DeepSeek 生成 payload JSON
6. 本地按 `input_schema` 再校验一次 payload
7. 发 `{"kind":"tool:exec", ...}` 给 `mcpd`

这意味着当前 `llm-app` 强依赖：

- `DEEPSEEK_API_KEY`
- `mcpd` 正常返回 catalog

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
- `perm`
- `cost`
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
- `/exit`

常用参数：

- `--agent-id a1`
- `--sock /tmp/mcpd.sock`
- `--show-tools`
- `--show-reasons`
- `--deepseek-model ...`
- `--deepseek-url ...`
- `--deepseek-timeout-sec ...`

## GUI

GUI 入口在 [gui_app.py](/home/lxh/Code/linux-mcp/llm-app/gui_app.py)。

启动方式：

```bash
python3 llm-app/gui_app.py
```

仓库当前推荐的 GUI 开发/运行方式：

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

GUI 和 CLI 使用同一套共享选择逻辑，不是两套不同实现。

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

CLI 单次执行时，通常会输出：

- 当前 catalog 里的 app/tool 数量
- 选中的 `app_name/app_id`
- 选中的 `tool_name/tool_id/hash`
- 执行状态和耗时
- 最终结果或错误

启用 `--show-reasons` 时，还会输出模型的 app/tool 选择理由。

## 当前限制

- app 选择、tool 选择、payload 构造都依赖 DeepSeek
- 没有离线 fallback
- 没有对话记忆压缩或 job 模式
- GUI 只是 demo UI，不是完整产品界面
- 真正的仲裁和执行都发生在 `mcpd` 侧，`llm-app` 只负责语义路由
