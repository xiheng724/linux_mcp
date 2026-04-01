# client

`client/` 提供与当前主链路对应的两个底层 Generic Netlink 调试工具：

- `client/bin/genl_register_tool`
- `client/bin/genl_list_tools`

这两个工具主要用于：
- `mcpd/reconcile_kernel.py`
- 独立排查 kernel/user ABI 是否一致

## 构建

```bash
make -C client clean
make -C client
```

## 手动检查

```bash
./client/bin/genl_register_tool --id 1 --name echo --risk-flags 0 --hash 12345678
./client/bin/genl_list_tools
```
