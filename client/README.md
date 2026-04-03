# client

`client/` 现在主要保存和内核 UAPI 对齐的 Python schema：

- [kernel_mcp/schema.py](/home/lxh/Code/linux-mcp/client/kernel_mcp/schema.py)

当前主链路里，`mcpd` 和 `mcpd/reconcile_kernel.py` 都直接通过 Python netlink client 与内核通信，不再依赖单独的 C 调试工具。

如果改了协议常量，请同时检查：

- [kernel-mcp/include/uapi/linux/kernel_mcp_schema.h](/home/lxh/Code/linux-mcp/kernel-mcp/include/uapi/linux/kernel_mcp_schema.h)
- [client/kernel_mcp/schema.py](/home/lxh/Code/linux-mcp/client/kernel_mcp/schema.py)
- `python3 scripts/verify_schema_sync.py`
