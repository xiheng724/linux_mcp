# linux-mcp

一个把内核治理和用户态工具执行串起来的 MCP 原型系统。

当前版本的主链路已经收敛成一套更贴近真实 app 的模型：

- `mcpd` 启动时自动读取 `tool-app/manifests/*.json`
- manifest 描述工具语义和接口契约
- `mcpd` 通过 app 暴露的 UDS RPC 接口执行工具
- `llm-app` 只看语义信息，不接触运行时细节
- demo app 保留为独立服务，便于展示，但不再是系统核心绑定点

## 核心组件

- `kernel-mcp/`
  - Generic Netlink 控制面和 sysfs 状态
- `mcpd/`
  - manifest 注册表
  - kernel 仲裁桥接
  - app 接口调用网关
- `tool-app/`
  - manifest 定义
  - demo app 服务
- `llm-app/`
  - CLI / GUI 客户端
  - app 选择与 tool 选择逻辑
- `client/`
  - C 版 netlink 对账与 ABI 排查工具

## 当前接口模型

manifest 负责声明：
- `app_id`
- `app_name`
- `transport`
- `endpoint`
- `tools[].operation`
- `tools[].description`
- `tools[].input_schema`
- `tools[].examples`

当前只支持一种执行 transport：
- `uds_rpc`

`mcpd` 发给 app 的请求：

```json
{"req_id":1,"agent_id":"a1","tool_id":2,"operation":"cpu_burn","payload":{"ms":200}}
```

app 返回：

```json
{"req_id":1,"status":"ok","result":{"burned_ms":200},"error":"","t_ms":201}
```

## Demo Apps

当前保留 4 个 demo app：

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

这些 demo app 都是独立 UDS 服务，只是为了展示。系统正式依赖的是它们暴露的接口，而不是它们的 Python 源码。

## 运行

1. 编译 client：

```bash
make -C client clean
make -C client
```

2. 加载内核模块：

```bash
sudo bash scripts/load_module.sh
```

3. 启动 demo app 服务：

```bash
bash scripts/run_tool_services.sh
```

4. 启动 `mcpd`：

```bash
bash scripts/run_mcpd.sh
```

5. 发起一次请求：

```bash
python3 llm-app/cli.py --once "calculate (21+7)*3"
```

6. 停止服务：

```bash
bash scripts/stop_mcpd.sh
bash scripts/stop_tool_services.sh
```

完整验收：

```bash
bash scripts/demo_acceptance.sh
```
