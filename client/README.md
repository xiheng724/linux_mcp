# client

`client/` contains shared protocol constants for Kernel MCP.

This directory is not the canonical planner/broker/provider runtime path.

The active component is:

- `kernel_mcp/schema.py` (shared Generic Netlink command/attribute constants)

There are currently no standalone C debug binaries in this directory.

Build:

```bash
make -C client clean
make -C client
```

The Makefile is kept for compatibility and cleanup helpers.
