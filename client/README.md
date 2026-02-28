# client

`client/` 提供底层 Generic Netlink 调试/注册工具（C 版本）。

## 是否必要

- 对主链路来说：**当前必要**。  
  `mcpd/reconcile_kernel.py` 会调用：
  - `client/bin/genl_register_tool`
  - `client/bin/genl_list_tools`
- 其他二进制（如 `genl_ping`、`genl_register_agent`、`genl_tool_request`、`genl_tool_complete`）主要用于调试与独立验证。

## 编译

```bash
make -C client clean
make -C client
```

## 常用命令

```bash
./client/bin/genl_ping "hello-kernel-mcp"
./client/bin/genl_register_tool --id 1 --name echo --perm 1 --cost 1
./client/bin/genl_list_tools
./client/bin/genl_register_agent --id a1
./client/bin/genl_tool_request --agent a1 --tool 2 --n 5
```
