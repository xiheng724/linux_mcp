# linux-mcp Agent Notes

本仓库当前实现的是一套可运行的 Kernel MCP demo，不再按旧的 phase 文档理解代码。

## 先理解当前真实架构

- `kernel-mcp/`: Linux 内核模块，提供 `KERNEL_MCP` Generic Netlink family、tool/agent registry 和 sysfs 状态树
- `mcpd/`: 用户态网关，加载 manifest、同步工具到内核、提供 `/tmp/mcpd.sock` RPC、转发工具执行
- `tool-app/`: demo tool services，按 manifest 通过 Unix Domain Socket RPC 对外提供 operation
- `llm-app/`: CLI/GUI 客户端，使用 DeepSeek 选择 app、tool 和 payload
- `client/`: netlink schema 常量和调试/注册工具用的小程序
- `scripts/`: 构建、装载、启动、停止、验收脚本

不要再假设仓库里有稳定的 `bench/`、`results/`、`plots/` 主流程，也不要把 README 里的旧阶段描述当成事实。

## 当前系统边界

1. Kernel 只做 control plane，不做 JSON 解析，不直接执行工具。
2. `mcpd` 是唯一同时理解“工具语义”和“运行时 endpoint”的进程。
3. `llm-app` 只能看 `list_apps` / `list_tools` 暴露出来的语义字段，不直接连 tool app。
4. 当前只支持 `uds_rpc` tool transport。
5. tool manifest 是语义来源，`tool_hash` 用于和内核注册状态对齐。

## 当前代码里的关键事实

- `mcpd` 启动时会自动加载 `tool-app/manifests/*.json`
- `mcpd` 会在启动时把 manifest tool 注册进内核
- `scripts/run_mcpd.sh` 会等待 socket ready，并调用 `mcpd/reconcile_kernel.py`
- 当前共有 4 个 app、14 个 tool
- `llm-app` 的 app 选择、tool 选择、payload 构造都依赖 `DEEPSEEK_API_KEY`
- 内核仲裁规则目前是 demo 规则，不是通用策略引擎
- `cpu_burn` 是唯一带 token bucket / defer 行为的工具

## Kernel danger zones

- sysfs/kobject 生命周期必须完整：创建什么就释放什么，模块退出必须清理干净
- 重复 `insmod` / `rmmod` 不能泄漏、不能 crash
- 共享计数更新必须受保护；当前 agent token bucket 使用 spinlock
- 不要在 netlink handler 里做阻塞工作
- 不要引入 kernel timer 或 kernel thread 做限流；当前实现要求 lazy refill based on jiffies

## Python / userspace expectations

- 保持 type hints
- 保持错误信息直接、可定位
- 不要引入隐藏的全局状态
- manifest / RPC schema 变更时，要同时检查 C/Python schema 同步
- 如果改了 manifest 语义字段，注意它会影响 `manifest_hash`

## 开发时优先遵循

1. 先看代码，再改文档或实现，不要沿用旧 phase 假设。
2. 修改协议相关内容时，同时检查：
   - `kernel-mcp/include/uapi/linux/kernel_mcp_schema.h`
   - `client/kernel_mcp/schema.py`
   - `scripts/verify_schema_sync.py`
3. 修改 manifest 或 tool registry 行为时，同时检查：
   - `mcpd/manifest_loader.py`
   - `mcpd/server.py`
   - `mcpd/reconcile_kernel.py`
   - `tool-app/manifests/*.json`
4. 修改 GUI/CLI 路由逻辑时，同时检查：
   - `llm-app/app_logic.py`
   - `llm-app/cli.py`
   - `llm-app/gui_app.py`

## 验证要求

任何开发任务完成后，至少跑与改动直接相关的验证命令，并在汇报里贴出关键输出。

常用验证：

```bash
python3 scripts/verify_schema_sync.py
make schema-verify
bash scripts/run_smoke.sh
```

如果改到内核模块、sysfs、netlink、启动流程，优先补充：

```bash
make -C client clean
make -C client
sudo bash scripts/build_kernel.sh
sudo bash scripts/load_module.sh
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh
sudo bash scripts/reload_10x.sh
```

如果本机条件允许，端到端验收用：

```bash
sudo bash scripts/demo_acceptance.sh
```

## 文档更新要求

- `README.md` 必须描述当前实际代码路径、启动顺序、依赖和限制
- 不要把未实现规划写成“已经支持”
- 写架构时要明确区分：
  - manifest 语义层
  - `mcpd` 运行时桥接层
  - kernel 仲裁层

## GUI 运行约定

以后每次开发或运行 GUI，默认使用：

```bash
cd ~/Code/linux-mcp
source .venv/bin/activate
python llm-app/gui_app.py
```

