# linux-mcp

`linux-mcp` 是一个把 MCP 做成“内核控制平面 + 用户态 broker/provider/executor 数据平面”的原型系统。

当前版本的核心目标不是把所有业务都塞进内核，而是把最敏感的治理动作收敛到内核模块里，把语义理解、provider 选择、参数校验和实际执行放到用户态，并且在两者之间建立一条可审计、可限流、可扩展的闭环。

## 1. 当前架构

当前系统已经从“每个 app action 都注册成 kernel tool”的模型，重构成下面的分层：

1. Planner Agent
   - 主要是 `llm-app`
   - 负责把用户输入转成 capability-domain 请求
   - 不直接执行高风险动作

2. Brokers
   - 主要由 `mcpd` 承担 broker 编排职责
   - 按能力域组织，而不是按 app 名组织
   - 当前已经准备好这些 broker 域和接口：
     - `info-broker`
     - `message-broker`
     - `file-broker`
     - `browser-broker`
     - `exec-broker`
     - `external-router-broker`

3. Providers
   - 代表已有 app/service 的实现
   - 当前 provider 信息来自 `tool-app/manifests/*.json`
   - provider 在用户态维护 action -> capability-domain 的映射

4. Executors
   - 目前还是最小可用实现，不是完整沙箱
   - 已经变成短生命周期、结构化 payload、带 executor descriptor 的执行模型
   - 已经预留 sandbox profile / network policy / resource limits 等接口

5. Kernel MCP
   - 只做控制平面
   - 不感知具体 provider action 业务语义
   - 内核里“tool”现在表示 capability domain，而不是具体 app action

## 2. 设计原则

- 内核只管 capability-domain 级别的准入、租约、计量、审计。
- provider-specific action 只存在于 broker/provider 层，不上升为 kernel 一级对象。
- planner 只能请求能力域，例如 `file.write`、`info.lookup`、`external.write`。
- 高风险动作必须走：
  `planner -> kernel MCP -> broker -> executor -> provider`

## 3. 当前已实现的能力域模型

内核注册的顶层对象是 capability domains。当前代码内置了这些稳定能力域：

- `info.lookup`
- `message.read`
- `message.send`
- `file.read`
- `file.write`
- `network.fetch.readonly`
- `browser.automation`
- `external.write`
- `exec.run`

注意：
- 不是所有能力域当前都已有实际 provider manifest。
- 当前 `tool-app/manifests/*.json` 主要覆盖本地 demo provider，因此实际可用能力域取决于已加载的 provider/actions。
- 架构上已经支持未来接入 `wechat-provider`、`github-provider`、`notion-provider`、`browser-provider` 等。

## 4. 当前请求流

### 4.1 标准能力域执行流

1. `llm-app` 接收用户输入。
2. `llm-app` 请求 `mcpd` 执行 `capability:exec`。
3. `mcpd` 根据 capability catalog、broker catalog、provider/action 映射选择 broker、provider、action、executor。
4. `mcpd` 向 kernel MCP 发 `capability_request`。
5. kernel MCP 校验 capability-domain policy，决定 `ALLOW / DENY / DEFER`。
6. 如果 `ALLOW`，kernel 发放单次 lease。
7. `mcpd` 用结构化 payload 调 provider 的常驻 UDS 服务。
8. 执行结束后 `mcpd` 回写 `capability_complete`。
9. kernel MCP 完成 lease 消费、记账和审计。

## 5. 当前安全边界

### 5.1 Kernel 侧

`kernel-mcp` 已经具备这些控制平面能力：

- participant registry
- capability-domain registry
- capability-based authorization
- trust/risk policy
- per-agent-per-capability rate limit
- inflight request tracking
- single-use lease issuance
- lease expiry / timeout GC
- completion validation
- audit event emission

### 5.2 Lease 语义

当前 lease 已经不是普通上下文字符串，而是单次执行授权，绑定到：

- `req_id`
- capability domain
- `broker_id`
- `provider_id`
- `provider_instance_id`
- `executor_id`
- `executor_instance_id`
- `approval_state`
- expiry

lease 只能消费一次；重复 completion、过期 lease、上下文不匹配都会失败。

### 5.3 Runtime identity 绑定

broker 当前不是只靠名字比对。kernel 现在会把 broker 批准时的这些运行时身份一起绑定进请求：

- `broker_pid`
- `broker_uid`
- `broker_epoch`

其中 `broker_epoch` 由 kernel 在 agent register/re-register 时生成。broker 重启或重新注册后 epoch 会变化，之前发出的 lease 自动失效。

### 5.4 Approval lifecycle

每个 capability domain 都有 `approval_mode`，当前支持：

- `AUTO`
- `TRUSTED`
- `ROOT_ONLY`
- `INTERACTIVE`
- `EXPLICIT`

请求会进入明确的 approval state：

- `PENDING`
- `AUTO_APPROVED`
- `APPROVED`
- `REJECTED`

lease 发放时会绑定 approval state，执行完成时必须匹配，不能在执行后再升级审批状态。

## 6. Provider / action / broker 模型

### 6.1 Provider

provider 表示一个现有 app/service 实现。当前 provider 元数据包含：

- `provider_id`
- `instance_id`
- `provider_type`
- `trust_class`
- `auth_mode`
- `broker_domain`
- `endpoint`
- `actions`

### 6.2 ProviderAction

provider action 是 broker 内部对象，不进入 kernel 顶层注册。当前 action 元数据包含：

- `action_id`
- `action_name`
- `capability_domain`
- `risk_level`
- `side_effect`
- `auth_required`
- `data_sensitivity`
- `executor_type`
- `validation_policy`
- `parameter_schema_id`
- `input_schema`

### 6.3 Broker dispatch

`mcpd` 负责：

- 接受 planner 的 capability-domain 请求
- 根据 policy 和 provider/action 映射做选择
- 对 payload 做 schema 校验
- 生成 executor instance id
- 向 kernel 请求单次 lease
- 调用 provider executor
- 回写 completion

高风险能力域下，planner 的 provider preference 不再是强制指令，只能作为偏好；最终 provider/action 选择由 broker policy 控制。

## 7. 当前最小沙箱执行模型

项目现在还没有完整启用 `seccomp`、`namespaces`、`cgroup`、`LSM`，但 executor 接口已经被收窄成沙箱友好的形式。

当前 executor descriptor 已经包含：

- `executor_id`
- `executor_type`
- `parameter_schema_id`
- `sandbox_profile`
- `working_directory`
- `network_policy`
- `resource_limits`
- `inherited_env_keys`
- `command_schema_id`
- `structured_payload_only`
- `short_lived`

当前已经 enforced 的约束：

- executor 使用结构化 payload
- broker 在 dispatch 前做 schema 校验
- `sandboxed-process` executor 不允许通过 payload 传自由格式 shell 命令
- executor 有明确工作目录和最小环境变量继承约束

当前还没有 fully enforced 的部分：

- seccomp 过滤
- mount/user/network namespace
- cgroup 资源控制
- LSM 策略挂接

这些能力在当前架构里已经有明确挂点，后续可以继续增强，而不需要再推翻协议和对象模型。

## 8. 当前审计能力

### 8.1 Kernel 审计

kernel 会输出结构化审计事件，覆盖：

- capability request
- lease issued
- request denied
- lease expired
- execution completed
- duplicate completion attempt
- compatibility path usage

审计字段包括：

- `req_id`
- `capability_domain`
- `planner_participant_id`
- `broker_id`
- `broker_pid`
- `broker_epoch`
- `provider_id`
- `provider_instance_id`
- `executor_id`
- `executor_instance_id`
- `lease_id`
- `approval_mode`
- `approval_state`
- `decision_reason`
- `expiry_time_ms`
- `legacy_path_flag`

### 8.2 Userspace 审计

`mcpd` 也会输出 JSON 形式的结构化审计日志，字段与 kernel 尽量对齐，便于后续做日志关联和分析。

## 9. 当前目录说明

- `kernel-mcp/`
  - Generic Netlink 内核模块
  - 控制平面实现
- `mcpd/`
  - userspace gateway / broker runtime
  - provider catalog、capability catalog、broker dispatch、reconcile、audit
- `tool-app/`
  - provider 侧常驻 UDS 服务与 demo app 实现
- `tool-app/manifests/`
  - provider manifests
- `llm-app/`
  - planner 侧 CLI / GUI
- `client/`
  - C 版 Generic Netlink 调试和验证工具
- `scripts/`
  - 启停脚本和 schema 校验脚本

## 10. 当前主要模块职责

### `kernel-mcp`

负责：

- 注册 capability domains
- 注册 agents
- capability-domain policy enforcement
- rate limiting
- inflight / lease lifecycle
- approval-state binding
- completion validation
- kernel audit

不负责：

- 解析 JSON 业务参数
- 选择 provider
- 选择具体 action
- 具体 app 逻辑

### `mcpd`

负责：

- 接收 planner 请求
- provider manifest 加载与校验
- capability / broker catalog 构建
- provider/action -> capability-domain 映射
- broker dispatch
- 请求 kernel 仲裁
- 调 provider 执行
- userspace audit

### `tool-app`

负责：

- 暴露 provider 侧 UDS 服务
- 按 `action_id` 找到 handler
- 执行本地 demo 功能
- 启动后向 `mcpd` 注册 manifest

### `llm-app`

负责：

- 将用户输入映射到 capability-domain 请求
- 调 `mcpd`
- 显示结果

## 11. 当前状态下的 demo provider

仓库当前自带的本地 provider 主要来自：

- `settings-provider`
- `file-manager-provider`
- `calculator-provider`
- `utility-provider`

它们通过 manifest 暴露 action，再由 `mcpd` 聚合成 capability domains。

## 12. 快速启动

### 12.1 编译 client 工具

```bash
make -C client clean
make -C client
```

### 12.2 编译并加载内核模块

```bash
make -C kernel-mcp
sudo bash scripts/load_module.sh
```

### 12.3 启动 provider 服务和 `mcpd`

```bash
bash scripts/run_tool_services.sh
bash scripts/run_mcpd.sh
```

### 12.4 运行 planner demo

```bash
python3 llm-app/cli.py --selector heuristic --once "what time is it now"
python3 llm-app/cli.py --selector heuristic --once "preview README.md"
python3 llm-app/cli.py --selector heuristic --once "create a file tmp/demo.txt with content hello"
```

### 12.5 停止服务

```bash
bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
```

## 13. 开发者常用入口

- 查看当前 provider / action / capability / broker 对外视图：
  - `mcpd` UDS 的 `list_providers` / `list_actions` / `list_capabilities` / `list_brokers`
- 重建并同步 kernel capability registry：
  - `python3 mcpd/reconcile_kernel.py`
- 校验 Generic Netlink schema 是否同步：
  - `python3 scripts/verify_schema_sync.py`
- 本地快速验证：
  - `python3 -m py_compile mcpd/architecture.py mcpd/server.py mcpd/netlink_client.py`
  - `make -C kernel-mcp`
  - `make -C client clean && make -C client`

## 14. 现阶段边界

当前项目已经完成的重点是“安全架构收口”，不是完整产品化。

已经完成：

- capability-domain 内核注册模型
- provider/action/broker 用户态模型
- planner -> broker -> executor 主链路
- 单次 lease
- broker pid/uid/epoch 绑定
- provider/executor instance id 绑定
- approval lifecycle
- 兼容路径收紧
- 结构化审计
- sandbox-ready executor descriptor

还没完全落地：

- 真正的 seccomp / namespace / cgroup / LSM 沙箱
- 独立 broker 进程拆分
- 外部 SaaS provider 的生产级接入
- 更完整的 approval UI / session 管理

## 15. 为什么这个项目现在值得看

这个仓库当前最有价值的部分，不是 demo 工具本身，而是已经把下面这条边界做清楚了：

- kernel 只看稳定 capability domains
- 用户态 broker 承担 provider/action 解析
- executor 是短生命周期、无策略权的执行体
- request 到 completion 的授权和审计链是闭环的

这意味着后续无论接入本地工具、浏览器自动化、消息发送还是外部 SaaS，扩展的方向都已经被约束在一套更安全、更稳的模型里，而不是继续堆散装 tool 调用。
