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

- 按配置自动加载 provider manifests
- 构建 provider catalog / capability catalog / broker catalog
- 校验 planner capability request
- 通过独立 policy engine 评估 capability gating 和 executor policy
- 根据 capability intent 解析 provider 和 action
- 根据 manifest + schema 构建结构化 payload
- 做 schema 校验
- 绑定短生命周期 executor
- 请求 kernel lease
- 调用 provider endpoint
- 向 kernel 回报 completion

`mcpd` 的默认 UDS socket 是：

- `/tmp/mcpd.sock`

`mcpd` 的平台配置现在是三层 declarative control plane：

- `mcpd/controlplane/packages/*.yaml`
- `mcpd/controlplane/definitions/brokers/*.yaml`
- `mcpd/controlplane/definitions/executors/*.yaml`
- `mcpd/controlplane/definitions/policies/*.yaml`
- `mcpd/controlplane/platform/server.yaml`
- `mcpd/generated/runtime_registry.json`
- `mcpd/controlplane/INDEX.md`

所有 artifact 都使用统一 envelope：

- `apiVersion`
- `kind`
- `metadata`
- `spec`

其中：

- `packages/` 是 capability 的主要编辑入口
- `definitions/` 是 broker / executor / policy 复用对象
- `generated/runtime_registry.json` 是启动期编译产物，供运行时消费

启动时会按目录扫描、按 kind 校验、做 cross-validation、编译 runtime registry，并在错误时 fail-fast。

`mcpd` 当前还包含一个独立的策略评估层：

- `mcpd/policy_engine.py`
- `mcpd/policy_types.py`
- `mcpd/explain.py`

它负责 capability gating、executor policy 和 dispatch explainability 的解释性判定，不改变 planner/kernel/provider 的边界。

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

broker 返回结果里会附带结构化 explain 信息，覆盖：

- capability request / gating reason
- capability selection source
- action resolution 排序结果
- executor binding reason
- payload construction mode

当前 `explain` 的重点字段包括：

- `capability_request`
- `capability_selection`
- `action_resolution`
- `executor_binding`
- `payload_construction`

## 配置来源

当前系统把平台级可调元数据拆成了三层：

- `CapabilityPackage`
  - `mcpd/controlplane/packages/*.yaml`
  - 定义 capability 语义、`broker_ref`、`policy_ref`、`executor_ref`、provider requirements
- `definitions`
  - `mcpd/controlplane/definitions/brokers/*.yaml`
  - `mcpd/controlplane/definitions/executors/*.yaml`
  - `mcpd/controlplane/definitions/policies/*.yaml`
  - 复用 action selection policy、executor profile 组合、approval/audit/rate limit/enforcement baseline
- `ServerConfig`
  - `mcpd/controlplane/platform/server.yaml`
  - 定义 manifest 目录、planner/broker trust 默认值、socket 默认值、executor workdir root

运行时主要消费：

- `mcpd/generated/runtime_registry.json`
- 其中包含 `capability_registry` / `broker_registry` / `executor_profiles` / `policy_registry` / `server_defaults`

`ServerConfig` 的来源优先级是：

- `ENV`
- `mcpd/controlplane/platform/server.yaml`
- 代码兜底默认值

当前支持的关键环境变量：

- `MCPD_MANIFEST_DIRS`
- `MCPD_SOCKET_PATH`
- `MCPD_EXECUTOR_WORKDIR_ROOT`
- `MCPD_PLANNER_TRUST_LEVEL`

## 新增 capability

推荐路径是：

1. 新增 `mcpd/controlplane/packages/<capability>.yaml`
2. 复用已有 `definitions/brokers` / `definitions/executors` / `definitions/policies`
3. 如确实需要，再新增对应 definition
4. 重启 `mcpd` 或重新编译 control plane，让 `mcpd/generated/runtime_registry.json` 和 `mcpd/controlplane/INDEX.md` 更新

仍然需要改代码的情况：

- 新 executor runtime
- 新 provider transport
- 新 policy semantics
- 新 schema 类型系统
- `MCPD_BROKER_TRUST_LEVEL`

例如，临时改用另一组 manifests 和 socket：

```bash
export MCPD_MANIFEST_DIRS="/abs/path/to/manifests"
export MCPD_SOCKET_PATH="/tmp/mcpd-custom.sock"
```

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

- 扫描配置指定的 manifest 目录
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
- 等待配置中的 broker socket ready
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
2. 添加 manifest 到配置指定的 manifest 目录
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
- 外置 capability / broker / executor / server 配置
- broker-side schema-driven payload construction
- capability policy gating
- kernel lease / approval / completion 生命周期
- provider/action resolution with policy awareness
- 短生命周期 executor 子进程
- 基础资源限制和最小运行时隔离
- 结构化 timing / audit logs
- 独立 policy engine
- 结构化 dispatch explainability

需要注意：

- `executor_runtime` 的隔离 enforcement pipeline 现在已经分层清楚
- `no_new_privs`、workdir isolation、resource limits 是已 enforce 的
- namespace / cgroup / seccomp 仍然有一部分依赖环境能力或属于 hook / placeholder
- 高风险 profile 如果关键隔离要求不满足，会显式失败，不会静默降级

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

当前测试覆盖重点在：

- `tests/test_policy_engine.py`
- `tests/test_registry_consistency.py`
- `tests/test_executor_binding.py`
- `tests/test_resolution_explainability.py`

需要注意的是：

- 这是原型系统，不是生产级产品
- provider 能力取决于本地环境和 manifest 当前声明的 action 集
- 内核模块需要与你当前内核 headers / build 环境匹配
- 某些 provider 的实际效果依赖宿主机工具是否存在
