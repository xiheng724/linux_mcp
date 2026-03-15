# linux-mcp

`linux-mcp` 是一个面向 Linux 本地运行环境的 MCP 原型，实现了明确分层的 capability-driven 执行架构。

系统的 canonical 路径是：

```text
planner-app -> capability intent -> mcpd -> provider/action resolution -> executor -> provider endpoint -> kernel completion
```

这条路径里：

- `planner-app` 只负责把用户输入转换成 capability intent
- `mcpd` 是唯一的执行编排者
- `provider-app` 负责具体工具能力
- `kernel-mcp` 只负责 capability / participant / lease 控制平面

## 项目结构

- `kernel-mcp/`
  Linux 内核模块。负责 capability 注册、participant 注册、request/lease、approval、audit、rate limit。
- `mcpd/`
  用户态 broker。负责 manifest 加载、capability/provider/action 解析、payload 构建、schema 校验、executor 绑定、provider 调用、kernel completion。
- `planner-app/`
  planner/UI。CLI 和 GUI 都在这里，planner 只产生 capability-level intent。
- `provider-app/`
  provider runtime、provider 实现、provider manifests、optional schemas。
- `client/`
  低层 Generic Netlink 调试工具，不属于 canonical runtime 路径。
- `scripts/`
  构建内核模块、加载/卸载模块、启动/停止 provider 服务、启动/停止 broker 的脚本。

## 系统架构

### 1. kernel-mcp

`kernel-mcp` 是控制平面，不知道 provider-specific actions，也不解析业务 payload。

它管理的是：

- capability domains
- participants
- capability request / decision / completion
- leases
- approval state
- audit events
- rate limiting

内核模块构建产物统一放在：

- `kernel-mcp/out/`

### 2. planner-app

`planner-app` 是 planner 层，不负责 provider action payload 构造。

planner canonical 输出形态是：

```json
{
  "capability_domain": "...",
  "intent_text": "...",
  "hints": {}
}
```

planner 不做这些事：

- 不知道 provider action 字段名
- 不直接构造最终执行 payload
- 不直接选择 executor
- 不直接调用 provider endpoint

### 3. mcpd

`mcpd` 是整个系统的执行中枢。

它负责：

- 自动加载 `provider-app/manifests/*.json`
- 构建 provider catalog / capability catalog / broker catalog
- 校验 planner capability request
- 根据 capability intent 解析 provider 和 action
- 根据 manifest + schema 构建结构化 payload
- 做 schema 校验
- 绑定短生命周期 executor
- 请求 kernel lease
- 调用 provider endpoint
- 向 kernel 回报 completion

`mcpd` 的 UDS socket 是：

- `/tmp/mcpd.sock`

### 4. provider-app

`provider-app` 是 provider 层。

一个 provider 由三部分组成：

1. provider endpoint implementation
2. provider manifest
3. optional schema files

在已有 capability domain 下接入新 provider，不需要修改：

- `kernel-mcp`
- `mcpd` 核心路由
- `planner-app`

### 5. executor

executor 是 broker 拉起的短生命周期执行单元。

当前已经实现的最小隔离包括：

- 独立子进程执行
- 限制 `working_directory`
- 最小化继承环境变量
- `RLIMIT_CPU`
- `RLIMIT_AS`
- `RLIMIT_NOFILE`
- `umask 077`
- `no_new_privs`
- 可选 namespace / cgroup / seccomp hook

canonical 路径只允许结构化 payload，不允许 free-form shell payload。

## 当前 capability 覆盖

当前 manifests 实际覆盖这些 capability domains：

- `info.lookup`
- `file.read`
- `file.write`
- `external.write`
- `exec.run`

当前 provider 如下：

- `settings-provider`
- `file-manager-provider`
- `calculator-provider`
- `utility-provider`
- `notes-provider`

其中 `notes-provider` 是 manifest-driven onboarding 的示例 provider。

## Canonical 规则

- planner 只发送：
  - `capability_domain`
  - `intent_text`
  - `hints`
- broker 独占：
  - provider selection
  - action selection
  - payload construction
  - schema validation
  - executor binding
- provider 接收：
  - `action_id`
  - structured `payload`
- kernel 不知道 provider-specific actions

## 运行前准备

需要：

- Linux 环境
- Python 3
- 可用的内核 headers 和模块构建环境
- root 权限用于 `insmod` / `rmmod`

如果你的 provider 依赖本地系统工具，也要确保这些工具存在。比如当前某些 provider 会依赖文件系统访问或音量控制工具。

## 如何运行

### 1. 构建并加载内核模块

只构建：

```bash
bash scripts/build_kernel.sh
```

构建成功后模块文件在：

```bash
kernel-mcp/out/kernel_mcp.ko
```

加载模块：

```bash
sudo bash scripts/load_module.sh
```

卸载模块：

```bash
sudo bash scripts/unload_module.sh
```

### 2. 启动 provider 服务

```bash
bash scripts/run_provider_services.sh
```

这个脚本会：

- 扫描 `provider-app/manifests/*.json`
- 对 `mode=uds_service` 的 provider 拉起 `provider-app/provider_service.py`
- 根据 manifest 中的 `endpoint` 创建 UDS provider 服务

provider 相关运行文件位置：

- provider sockets：manifest 指定的 `endpoint`
- pid files：`/tmp/linux-mcp-provider-<provider_id>.pid`
- logs：`/tmp/linux-mcp-provider-<provider_id>.log`

停止 provider 服务：

```bash
bash scripts/stop_provider_services.sh
```

### 3. 启动 mcpd broker

```bash
bash scripts/run_mcpd.sh
```

这个脚本会：

- 检查 `kernel_mcp` 模块是否已加载
- 检查 provider endpoints 是否都已就绪
- 启动 `mcpd/server.py`
- 等待 `/tmp/mcpd.sock` ready
- 等待 manifest actions 注册到 broker catalog
- 执行 `mcpd/reconcile_kernel.py`，把当前 manifests 对齐到 kernel capability registry

broker 运行文件位置：

- socket：`/tmp/mcpd.sock`
- pid file：`/tmp/mcpd-<uid>.pid`
- log：`/tmp/mcpd-<uid>.log`

停止 broker：

```bash
bash scripts/stop_mcpd.sh
```

### 4. 运行 planner CLI

单次执行：

```bash
python3 planner-app/cli.py --once "what time is it in utc"
```

进入 REPL：

```bash
python3 planner-app/cli.py --repl
```

常用参数：

- `--participant-id`
- `--sock`
- `--show-actions`
- `--deepseek-url`
- `--deepseek-model`
- `--deepseek-api-key`
- `--deepseek-timeout-sec`

CLI 会先从 `mcpd` 拉取：

- providers
- actions
- capabilities

然后基于 capability catalog 选择 capability，再发起 `capability:exec` 请求。

### 5. 运行 planner GUI

```bash
python3 planner-app/gui_app.py
```

常用参数：

- `--sock`
- `--participant-id`
- `--deepseek-url`
- `--deepseek-model`
- `--deepseek-api-key`
- `--deepseek-timeout-sec`

如果当前环境没有 Qt 依赖或图形环境，直接使用 CLI。

## mcpd 对外接口

`mcpd` 支持这些系统查询：

```json
{"sys":"list_providers"}
{"sys":"list_actions"}
{"sys":"list_capabilities"}
{"sys":"list_brokers"}
```

canonical 执行请求形态：

```json
{
  "kind": "capability:exec",
  "req_id": 1,
  "participant_id": "planner-main",
  "capability_domain": "info.lookup",
  "intent_text": "what time is it in utc",
  "hints": {
    "selector_source": "catalog",
    "selector_reason": "catalog_score=42"
  }
}
```

canonical 路径会拒绝这些字段：

- top-level `payload`
- `planner_hints`
- top-level `preferred_provider_id`
- `user_text`
- `hints.payload_slots`

## Provider onboarding

在已有 capability domain 下，新增 provider 的 canonical 步骤是：

1. 实现 provider endpoint
2. 添加 manifest 到 `provider-app/manifests/`
3. 按需添加 schema 到 `provider-app/schemas/`
4. 重启 provider 服务和 `mcpd`

不需要修改：

- planner 路由代码
- broker 核心 dispatch 逻辑
- kernel capability/lease 核心代码

## 当前安全与约束

当前 canonical 路径已经具备：

- manifest-driven provider onboarding
- capability-domain routing
- broker-side schema-driven payload construction
- capability policy gating
- kernel lease / approval / completion 生命周期
- provider/action resolution with policy awareness
- 短生命周期 executor 子进程
- 基础资源限制和最小运行时隔离
- 结构化 timing / audit logs

## 调试和低层工具

`client/` 目录里的工具只用于低层 Generic Netlink 调试，不属于 canonical runtime 路径。

如需构建：

```bash
make -C client
```

构建产物会放到：

```bash
client/bin/
```

## 当前项目状态

当前项目已经是 manifest-driven、capability-driven 的运行结构，主路径是稳定的。

需要注意的是：

- 这是原型系统，不是生产级产品
- provider 能力取决于本地环境和 manifest 当前声明的 action 集
- 内核模块需要与你当前内核 headers / build 环境匹配
- 某些 provider 的实际效果依赖宿主机工具是否存在
