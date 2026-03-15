# client

`client/` contains low-level Generic Netlink debug utilities.

These tools are not part of the canonical planner/broker/provider runtime path, but they are still useful for:

- kernel protocol debugging
- manual participant/capability registration checks
- direct lease/request experiments

Build:

```bash
make -C client clean
make -C client
```

Compiled binaries are not kept in the repository. They are rebuilt into `client/bin/` when needed.

Current debug utilities:

- `genl_ping`
- `genl_register_participant`
- `genl_register_capability`
- `genl_capability_request`
- `genl_capability_complete`
