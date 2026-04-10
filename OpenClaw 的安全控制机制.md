## OpenClaw 的安全控制机制



### 整体安全思路

> LLM → 执行计划 → 安全检查 → 批准 → 不可篡改执行

```
LLM
 ↓
Canonical Execution Plan（结构化）
 ↓
Policy Check（allowlist）
 ↓
User/System Approval
 ↓
Immutable Execution（防篡改）
 ↓
Env Sanitization（防注入）
 ↓
Exec / Node
 ↓
Node-side Validation（第二层防护）
```



#### 1. Host-local

- 本机上的“执行授权记录”（本地持久化 allowlist）
  - 记录哪些命令被运行执行

```
{
  "allowed": [
    "git status",
    "python script.py"
  ]
}
```



#### 2. Per-agent allowlist

- 每个 agent 的权限边界
  - 能力隔离（Capability-based security）

```
Agent A → 可以跑 git
Agent B → 只能读文件
```



#### 3. systemRunPlan

- 标准化的执行计划
  - 防止字符串拼接执行，实现结构化执行

```
{
  "command": "python",
  "args": ["script.py"],
  "cwd": "/app",
  "env": {}
}
```

```
"python script.py && rm -rf /"
```



#### 4. 批准后不可篡改

- 执行计划固定，不可调节参数
  - 本质是防止 TOCTOU（Time-of-check to time-of-use）

```
批准：ls /safe
执行：ls /safe && rm -rf /

监测到变更 --> 拒绝执行
```



#### 5. 拒绝环境变量注入

- 拒绝env.PATH、LD_注入（命令路径挟持、Linux 动态库挟持）
  - 本质是防止 runtime hijacking（运行时挟持）