# client

Raw Generic Netlink test clients and Python demo client for linux-mcp.

## Build

Build all C tools:

```bash
make -C client clean
make -C client
```

All binaries are generated in `client/bin/`.

## Tool Registration

1) Ensure the kernel module is loaded:

```bash
sudo bash scripts/load_module.sh
```

2) Register a tool:

```bash
./client/bin/genl_register_tool --id 24 --name clock_tool --perm 1 --cost 1
```

3) Verify registration:

```bash
./client/bin/genl_list_tools
ls -l /sys/kernel/mcp/tools/24
cat /sys/kernel/mcp/tools/24/name
cat /sys/kernel/mcp/tools/24/perm
cat /sys/kernel/mcp/tools/24/cost
cat /sys/kernel/mcp/tools/24/status
```

Notes:
- `id`: unique tool id (`u32`), used as the kernel registry key.
- `name`: human-readable tool name.
- `perm`: policy metadata field (`u32`).
- `cost`: cost metadata field (`u32`).
- Re-registering the same `id` updates metadata in place.

## Common Operations

Ping kernel family:

```bash
./client/bin/genl_ping "hello-kernel-mcp"
```

Register default tools:

```bash
./client/bin/genl_register_tool --id 1 --name echo --perm 1 --cost 1
./client/bin/genl_register_tool --id 2 --name cpu_burn --perm 1 --cost 3
```

Register agent:

```bash
./client/bin/genl_register_agent --id a1
```

Request arbitration decisions:

```bash
./client/bin/genl_tool_request --agent a1 --tool 2 --n 10
```
