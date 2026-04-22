# systemd deployment for mcpd

Reference unit for running mcpd as an unprivileged service with only
the Linux capabilities it actually needs, instead of as root.

## Why capability-based

mcpd needs exactly two privileged operations:

- `CAP_NET_ADMIN` — the kernel_mcp Generic Netlink family tags every
  registry-mutating command with `GENL_ADMIN_PERM`
  (see `kernel-mcp/src/kernel_mcp_main.c`).
- `CAP_SYS_PTRACE` — the backend probe reads `/proc/<pid>/exe` across
  uids when mcpd's service user differs from the tool-app user. Without
  ptrace scope, those reads return `EACCES` on most kernels.

Running the whole Python daemon as uid 0 grants *all* other caps too
(raw sockets, mount, kexec, ...). The unit here drops to a dedicated
`mcpd` user with exactly those two.

## One-time setup

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcpd
sudo install -d -o root -g root -m 0755 /etc/linux-mcp
sudo install -m 0644 config/mcpd.demo.toml /etc/linux-mcp/mcpd.toml
sudo install -d -o mcpd -g mcpd -m 0755 /opt/linux-mcp
sudo rsync -a --delete ./ /opt/linux-mcp/
sudo install -m 0644 deploy/systemd/mcpd.service \
    /etc/systemd/system/mcpd.service
sudo systemctl daemon-reload
```

Edit `/etc/linux-mcp/mcpd.toml` and uncomment/set
`allowed_backend_uids` to list every uid that may serve as a tool
backend. Under systemd there is no `$SUDO_UID` to fall back on, and
`LINUX_MCP_TRUST_SUDO_UID` is intentionally not set in the unit —
trust decisions live in the config, not in launcher heuristics.

## Starting

```bash
sudo systemctl start mcpd
sudo systemctl status mcpd
journalctl -u mcpd -f
```

## Verifying the drop in privileges

```bash
pid=$(systemctl show -p MainPID --value mcpd)
ps -o uid,user,comm -p "$pid"
getpcaps "$pid"
# Expected capabilities: cap_net_admin,cap_sys_ptrace (ambient set)
```
