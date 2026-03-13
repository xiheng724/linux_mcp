# client

`client/` 提供底层 Generic Netlink 调试/注册工具（C 版本）。

## 是否必要

- 对主链路来说：**当前必要**。  
  `mcpd/reconcile_kernel.py` 现在直接读取 `/sys/kernel/mcp/capabilities`，不再依赖 `genl_list_tools`。
- 这些二进制名因为 wire compatibility 仍然保留旧词，但默认帮助文本已经切到 capability / participant。
- 其他二进制（如 `genl_ping`、`genl_register_agent`、`genl_tool_request`、`genl_tool_complete`）主要用于调试与独立验证。
  其中协议层仍保留旧二进制名，但语义上已经是 capability / participant。

## 编译

```bash
make -C client clean
make -C client
```

## 常用命令

```bash
./client/bin/genl_ping "hello-kernel-mcp"
./client/bin/genl_register_tool --capability-id 1 --capability-name info.lookup --perm 1 --cost 1
./client/bin/genl_register_agent --id planner-main --type planner
./client/bin/genl_tool_request --participant planner-main --capability 2 --n 5
```
