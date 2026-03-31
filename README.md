# linux-mcp

一个把内核治理和用户态工具执行串起来的 MCP 原型系统。

它的核心目标是：
- 把工具的注册、仲裁、审计、计量放进内核
- 把工具语义、路由和实际执行放在用户态
- 让 `llm-app` 只通过统一网关 `mcpd` 访问工具

当前仓库已经不是“只有概念”的设计稿，而是一个可运行的多组件 demo：
- `kernel-mcp/`：Linux 内核模块，使用 Generic Netlink 暴露注册和仲裁接口，并在 `sysfs` 暴露状态
- `mcpd/`：用户态网关，维护 manifest 注册表，向内核发起仲裁，并把请求转发给 app service
- `tool-app/`：常驻的 app 级工具服务。每个 app 通过一个 Unix socket 对外服务，内部按 `tool_id` 分发 handler
- `llm-app/`：CLI 和 PySide6 GUI 客户端，先选 app，再选 tool，再经 `mcpd` 执行
- `client/`：C 写的 Generic Netlink 调试/校验工具，当前主要被 `mcpd/reconcile_kernel.py` 用于注册表对账
- `bench/`：压测与绘图脚本，不影响主链路

## 这个项目在做什么

可以把它理解成一条“受控工具调用链”：

1. `tool-app` 读取 `tool-app/manifests/*.json`，把 app 和 tool 的语义信息注册给 `mcpd`
2. `mcpd` 校验 manifest，并把 `tool_id/name/perm/cost/hash` 同步到内核
3. `llm-app` 通过 `list_apps` 和 `list_tools` 获取可用工具
4. `llm-app` 发起 `tool:exec`
5. `mcpd` 先向内核发 `tool_request`，由内核返回 `ALLOW` / `DENY` / `DEFER`
6. 只有在 `ALLOW` 后，`mcpd` 才会把请求转发到对应 app 的 Unix socket
7. 执行结束后，`mcpd` 再向内核发 `tool_complete` 回写结果状态和耗时

也就是说，这个项目重点不是“做很多工具”，而是验证一套机制：
- LLM 侧不直连工具
- 用户态负责语义和执行
- 内核负责受控准入、节流和审计

## 当前实现的能力

当前仓库里一共有 4 个 app、14 个工具：

- `utility_app`
  - `echo`
- `settings_app`
  - `cpu_burn`
  - `sys_info`
  - `time_now`
  - `volume_control`
- `calculator_app`
  - `calc`
- `file_manager_app`
  - `text_stats`
  - `file_preview`
  - `hash_text`
  - `file_create`
  - `file_list`
  - `file_delete`
  - `file_copy`
  - `file_rename`

其中 `file_manager_app` 对路径做了安全约束：
- 只允许仓库根目录下的相对路径
- 禁止绝对路径
- 禁止 `..`

## 设计上的关键点

- 内核不解析 JSON，也不承载业务语义
- 工具语义来自 manifest：`description`、`input_schema`、`examples`
- `mcpd` 是唯一执行网关，负责做请求校验、工具路由、内核仲裁和 completion 回写
- 工具按 app 常驻，而不是每次 fork 一个脚本
- 每个工具都有语义哈希，哈希来自：
  - `tool_id`
  - `name`
  - `app_id`
  - `app_name`
  - `perm`
  - `cost`
  - `description`
  - `input_schema`
  - `examples`
- `scripts/run_mcpd.sh` 会等待 manifest 注册完成后执行 reconcile，确保 manifest 与内核注册表严格对齐

## 目录说明

- `kernel-mcp/`：内核模块源码与 UAPI schema
- `mcpd/`：网关、对账脚本、Python netlink client
- `tool-app/`：app service、工具实现、manifest
- `llm-app/`：CLI、GUI、选择器逻辑和 RPC
- `client/`：C 版 netlink 工具
- `scripts/`：构建、加载、启动、停止、验收脚本
- `bench/`：压测脚本

## 快速运行

1. 编译 client 工具：

```bash
make -C client clean
make -C client
```

2. 编译并加载内核模块：

```bash
sudo bash scripts/load_module.sh
```

3. 启动 app 服务：

```bash
bash scripts/run_tool_services.sh
```

4. 启动 `mcpd`：

```bash
bash scripts/run_mcpd.sh
```

5. 发起一次请求：

```bash
python3 llm-app/cli.py --selector heuristic --once "calculate (21+7)*3"
```

6. 停止服务：

```bash
bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
```

如果想跑完整验收流程，可以直接执行：

```bash
bash scripts/demo_acceptance.sh
```

## 新增一个工具

推荐的增量方式是：

1. 在对应 app 模块里实现 handler，并加入 `HANDLERS`
2. 在对应 manifest 的 `tools[]` 里加入：
   - `tool_id`
   - `name`
   - `perm`
   - `cost`
   - `handler`
   - `description`
   - `input_schema`
   - `examples`
3. 重启 app service 和 `mcpd`

涉及的主要文件通常是：
- `tool-app/apps/*.py`
- `tool-app/manifests/*.json`

## 当前代码与旧 README 的主要差异

这次已按代码把根 README 对齐，主要修正了这些点：
- README 之前更像架构概述，缺少当前已经实现的 app 和 tool 清单
- 现在的 `llm-app` 实际是“先选 app，再选 tool”，而不是直接平铺选工具
- `mcpd` 现在既做 manifest 注册表管理，也直接通过 Python netlink client 与内核通信
- `client/` 目前仍然是必需组件，因为 reconcile 依赖 `genl_register_tool` 和 `genl_list_tools`
- 运行链路里包含 app 常驻服务、manifest 注册和 reconcile，不只是单个 daemon

## 清理构建产物

```bash
bash scripts/clean_repo.sh
```
