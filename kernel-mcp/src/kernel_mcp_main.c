#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/timer.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include <linux/kernel_mcp_schema.h>

#define KERNEL_MCP_TOOL_NAME_MAX 128
#define KERNEL_MCP_TOOL_HASH_MAX 65	/* full SHA-256: 64 hex chars + NUL */
#define KERNEL_MCP_AGENT_ID_MAX 64
#define KERNEL_MCP_REASON_MAX 256
#define KERNEL_MCP_APPROVER_MAX 64

#define KERNEL_MCP_TOOL_STATUS_ACTIVE 1U

#define KERNEL_MCP_DECISION_ALLOW 1U
#define KERNEL_MCP_DECISION_DENY 2U
#define KERNEL_MCP_DECISION_DEFER 3U

#define KERNEL_MCP_APPROVAL_APPROVE 1U
#define KERNEL_MCP_APPROVAL_DENY 2U
#define KERNEL_MCP_APPROVAL_REVOKE 3U

#define KERNEL_MCP_COMPLETE_STATUS_OK 0U
#define KERNEL_MCP_COMPLETE_STATUS_ERR 1U

#define KERNEL_MCP_DEFAULT_APPROVAL_TTL_MS 300000U
#define KERNEL_MCP_TICKET_CLEANUP_INTERVAL_MS 300000U

#define KERNEL_MCP_AGENT_HASH_BITS 8
#define KERNEL_MCP_APPROVAL_HASH_BITS 8

#define KERNEL_MCP_HIGH_RISK_FLAGS                                               \
	(KERNEL_MCP_RISK_FILESYSTEM_DELETE | KERNEL_MCP_RISK_DEVICE_CONTROL |     \
	 KERNEL_MCP_RISK_EXTERNAL_NETWORK | KERNEL_MCP_RISK_PRIVILEGED |          \
	 KERNEL_MCP_RISK_IRREVERSIBLE)

/* Keep approval for obviously high-risk categories. More detailed,
 * payload-aware gating should be added in user space later if needed.
 */
#define KERNEL_MCP_APPROVAL_REQUIRED_FLAGS KERNEL_MCP_HIGH_RISK_FLAGS

struct kernel_mcp_tool {
	u32 id;
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	/* TOFU-locked SHA-256 hex of the backend executable; '' until first
	 * TOOL_REQUEST carries a binary_hash, after which any mismatch denies.
	 */
	char binary_hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 risk_flags;
	struct kobject *kobj;
};

struct kernel_mcp_tool_snapshot {
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	char binary_hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 risk_flags;
};

/* Per-call audit record. Layout is ABI — userspace decoders rely on these sizes.
 * Kept intentionally fixed-length and binary so we never parse JSON in the kernel.
 */
struct kernel_mcp_call_record {
	u64 seq;
	u64 timestamp_ns;
	u64 req_id;
	u32 tool_id;
	u32 status;   /* KERNEL_MCP_CALL_STATUS_* */
	u32 exec_ms;
	u32 reserved;
	u8 payload_hash[KERNEL_MCP_CALL_HASH_PREFIX];
	u8 response_hash[KERNEL_MCP_CALL_HASH_PREFIX];
	u8 err_head[KERNEL_MCP_CALL_ERR_HEAD_MAX];
};

struct kernel_mcp_agent {
	char id[KERNEL_MCP_AGENT_ID_MAX];
	u32 pid;
	u32 uid;
	bool uid_set;
	u64 binding_hash;
	u64 binding_epoch;
	/* Rate limiting is handled in mcpd user space, not in the kernel agent state. */
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u32 last_exec_ms;
	u32 last_status;
	char last_reason[KERNEL_MCP_REASON_MAX];
	/* Fixed-size circular log of recent call summaries. Survives mcpd crash;
	 * populated from cmd_tool_complete (ALLOW path) and from cmd_tool_request
	 * (DENY/DEFER paths). Head always points at the next write slot.
	 */
	u64 call_log_seq;
	u32 call_log_head;
	u32 call_log_count;
	struct kernel_mcp_call_record call_log[KERNEL_MCP_CALL_LOG_SIZE];
	struct hlist_node hnode;
	struct kobject *kobj;
};

struct kernel_mcp_agent_snapshot {
	u64 binding_hash;
	u64 binding_epoch;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u32 last_exec_ms;
	u32 last_status;
	u32 call_log_head;
	u32 call_log_count;
	char last_reason[KERNEL_MCP_REASON_MAX];
};

struct kernel_mcp_approval_ticket {
	u64 ticket_id;
	u64 req_id;
	u32 tool_id;
	char agent_id[KERNEL_MCP_AGENT_ID_MAX];
	u64 binding_hash;
	u64 binding_epoch;
	char tool_hash[KERNEL_MCP_TOOL_HASH_MAX];
	bool decided;
	bool approved;
	bool consumed;
	unsigned long expires_jiffies;
	char approver[KERNEL_MCP_APPROVER_MAX];
	char reason[KERNEL_MCP_REASON_MAX];
	struct hlist_node hnode;
};

static DEFINE_XARRAY(kernel_mcp_tools);
static DEFINE_MUTEX(kernel_mcp_tools_lock);

static DEFINE_HASHTABLE(kernel_mcp_agents, KERNEL_MCP_AGENT_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_agents_lock);
static DEFINE_HASHTABLE(kernel_mcp_approval_tickets, KERNEL_MCP_APPROVAL_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_approval_lock);
static u64 kernel_mcp_next_ticket_id;
static struct timer_list kernel_mcp_ticket_cleanup_timer;

static struct kobject *kernel_mcp_sysfs_root;
static struct kobject *kernel_mcp_sysfs_tools;
static struct kobject *kernel_mcp_sysfs_agents;
static struct genl_family kernel_mcp_genl_family;

static const struct nla_policy kernel_mcp_policy[KERNEL_MCP_ATTR_MAX + 1] = {
	[KERNEL_MCP_ATTR_REQ_ID] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TOOL_ID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_NAME] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_TOOL_NAME_MAX - 1,
	},
	[KERNEL_MCP_ATTR_AGENT_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_AGENT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_STATUS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_MESSAGE] = { .type = NLA_NUL_STRING, .len = 256 },
	[KERNEL_MCP_ATTR_PID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_UID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_DECISION] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_HASH] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_TOOL_HASH_MAX - 1,	/* validated against 64-char full SHA-256 */
	},
	[KERNEL_MCP_ATTR_EXEC_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_RISK_FLAGS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TICKET_ID] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_APPROVAL_DECISION] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_APPROVER] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_APPROVER_MAX - 1,
	},
	[KERNEL_MCP_ATTR_APPROVAL_REASON] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_REASON_MAX - 1,
	},
	[KERNEL_MCP_ATTR_APPROVAL_TTL_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_POLICY_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_REASON_MAX - 1,
	},
	[KERNEL_MCP_ATTR_AGENT_BINDING] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_AGENT_EPOCH] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_PAYLOAD_HASH] = {
		.type = NLA_BINARY,
		.len = KERNEL_MCP_CALL_HASH_PREFIX,
	},
	[KERNEL_MCP_ATTR_RESPONSE_HASH] = {
		.type = NLA_BINARY,
		.len = KERNEL_MCP_CALL_HASH_PREFIX,
	},
	[KERNEL_MCP_ATTR_ERR_HEAD] = {
		.type = NLA_BINARY,
		.len = KERNEL_MCP_CALL_ERR_HEAD_MAX,
	},
	[KERNEL_MCP_ATTR_BINARY_HASH] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_TOOL_HASH_MAX - 1,
	},
};

static u32 kernel_mcp_agent_hash_key(const char *agent_id)
{
	return jhash(agent_id, strlen(agent_id), 0);
}

/* Append a fixed-size record to the agent's circular call_log. Caller must hold
 * kernel_mcp_agents_lock. `payload_hash`, `response_hash`, `err_head` may be
 * NULL (fields are zeroed). `err_head_len` is clamped to the record field size.
 */
static void kernel_mcp_agent_call_log_append(struct kernel_mcp_agent *agent,
					     u64 req_id, u32 tool_id, u32 status,
					     u32 exec_ms,
					     const u8 *payload_hash,
					     const u8 *response_hash,
					     const u8 *err_head, size_t err_head_len)
{
	struct kernel_mcp_call_record *rec;
	size_t copy_len;

	rec = &agent->call_log[agent->call_log_head];
	memset(rec, 0, sizeof(*rec));
	rec->seq = ++agent->call_log_seq;
	rec->timestamp_ns = ktime_get_real_ns();
	rec->req_id = req_id;
	rec->tool_id = tool_id;
	rec->status = status;
	rec->exec_ms = exec_ms;
	if (payload_hash)
		memcpy(rec->payload_hash, payload_hash, KERNEL_MCP_CALL_HASH_PREFIX);
	if (response_hash)
		memcpy(rec->response_hash, response_hash, KERNEL_MCP_CALL_HASH_PREFIX);
	if (err_head && err_head_len) {
		copy_len = min_t(size_t, err_head_len, KERNEL_MCP_CALL_ERR_HEAD_MAX);
		memcpy(rec->err_head, err_head, copy_len);
	}

	agent->call_log_head = (agent->call_log_head + 1) % KERNEL_MCP_CALL_LOG_SIZE;
	if (agent->call_log_count < KERNEL_MCP_CALL_LOG_SIZE)
		agent->call_log_count++;
}

static struct kernel_mcp_agent *
kernel_mcp_find_agent_locked(const char *agent_id, u32 key)
{
	struct kernel_mcp_agent *agent;

	hash_for_each_possible(kernel_mcp_agents, agent, hnode, key) {
		if (strcmp(agent->id, agent_id) == 0)
			return agent;
	}
	return NULL;
}

static int
kernel_mcp_lookup_tool_snapshot(struct kobject *kobj,
				struct kernel_mcp_tool_snapshot *out)
{
	unsigned long tool_id;
	const char *id_str;
	struct kernel_mcp_tool *tool;
	int ret;

	id_str = kobject_name(kobj);
	ret = kstrtoul(id_str, 10, &tool_id);
	if (ret)
		return ret;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (!tool) {
		mutex_unlock(&kernel_mcp_tools_lock);
		return -ENOENT;
	}
	strscpy(out->name, tool->name, sizeof(out->name));
	strscpy(out->hash, tool->hash, sizeof(out->hash));
	strscpy(out->binary_hash, tool->binary_hash, sizeof(out->binary_hash));
	out->risk_flags = tool->risk_flags;
	mutex_unlock(&kernel_mcp_tools_lock);
	return 0;
}

static int
kernel_mcp_lookup_agent_snapshot(struct kobject *kobj,
				 struct kernel_mcp_agent_snapshot *out)
{
	const char *agent_id;
	u32 key;
	struct kernel_mcp_agent *agent;

	agent_id = kobject_name(kobj);
	key = kernel_mcp_agent_hash_key(agent_id);

	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOENT;
	}
	out->allow_count = agent->allow_count;
	out->binding_hash = agent->binding_hash;
	out->binding_epoch = agent->binding_epoch;
	out->deny_count = agent->deny_count;
	out->defer_count = agent->defer_count;
	out->completed_ok_count = agent->completed_ok_count;
	out->completed_err_count = agent->completed_err_count;
	out->last_exec_ms = agent->last_exec_ms;
	out->last_status = agent->last_status;
	out->call_log_head = agent->call_log_head;
	out->call_log_count = agent->call_log_count;
	strscpy(out->last_reason, agent->last_reason, sizeof(out->last_reason));
	mutex_unlock(&kernel_mcp_agents_lock);
	return 0;
}

/* Copy the call log into `out` in logical order (oldest first) and return the
 * number of valid records. `out` must have at least KERNEL_MCP_CALL_LOG_SIZE
 * entries. Unused tail slots are zeroed.
 */
static int
kernel_mcp_copy_agent_call_log(struct kobject *kobj,
			       struct kernel_mcp_call_record *out,
			       u32 *out_count)
{
	const char *agent_id;
	struct kernel_mcp_agent *agent;
	u32 key;
	u32 count;
	u32 head;
	u32 start;
	u32 i;

	agent_id = kobject_name(kobj);
	key = kernel_mcp_agent_hash_key(agent_id);

	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOENT;
	}
	count = agent->call_log_count;
	head = agent->call_log_head;
	/* When not yet wrapped, slot 0 is the oldest. After wrap, head is the
	 * next write slot and therefore also the oldest surviving record.
	 */
	start = (count < KERNEL_MCP_CALL_LOG_SIZE) ? 0 : head;
	memset(out, 0,
	       sizeof(struct kernel_mcp_call_record) * KERNEL_MCP_CALL_LOG_SIZE);
	for (i = 0; i < count; i++)
		out[i] = agent->call_log[(start + i) % KERNEL_MCP_CALL_LOG_SIZE];
	mutex_unlock(&kernel_mcp_agents_lock);

	*out_count = count;
	return 0;
}

/* Keep sysfs accessors generated so policy/state fields remain visible
 * without hand-maintaining many near-identical show functions.
 */
#define KERNEL_MCP_DEFINE_TOOL_SHOW_STR(_name, _field)                           \
static ssize_t kernel_mcp_tool_##_name##_show(struct kobject *kobj,              \
					      struct kobj_attribute *attr,       \
					      char *buf)                         \
{                                                                               \
	struct kernel_mcp_tool_snapshot snapshot;                               \
	int ret;                                                                \
	(void)attr;                                                             \
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);                 \
	if (ret)                                                                \
		return ret;                                                     \
	return sysfs_emit(buf, "%s\n", snapshot._field);                       \
}

#define KERNEL_MCP_DEFINE_TOOL_SHOW_U32(_name, _field, _fmt)                     \
static ssize_t kernel_mcp_tool_##_name##_show(struct kobject *kobj,              \
					      struct kobj_attribute *attr,       \
					      char *buf)                         \
{                                                                               \
	struct kernel_mcp_tool_snapshot snapshot;                               \
	int ret;                                                                \
	(void)attr;                                                             \
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);                 \
	if (ret)                                                                \
		return ret;                                                     \
	return sysfs_emit(buf, _fmt "\n", snapshot._field);                    \
}

#define KERNEL_MCP_DEFINE_AGENT_SHOW_U64(_name, _field)                          \
static ssize_t kernel_mcp_agent_##_name##_show(struct kobject *kobj,             \
					       struct kobj_attribute *attr,      \
					       char *buf)                        \
{                                                                               \
	struct kernel_mcp_agent_snapshot snapshot;                              \
	int ret;                                                                \
	(void)attr;                                                             \
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);                \
	if (ret)                                                                \
		return ret;                                                     \
	return sysfs_emit(buf, "%llu\n",                                       \
			  (unsigned long long)snapshot._field);               \
}

#define KERNEL_MCP_DEFINE_AGENT_SHOW_U32(_name, _field)                          \
static ssize_t kernel_mcp_agent_##_name##_show(struct kobject *kobj,             \
					       struct kobj_attribute *attr,      \
					       char *buf)                        \
{                                                                               \
	struct kernel_mcp_agent_snapshot snapshot;                              \
	int ret;                                                                \
	(void)attr;                                                             \
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);                \
	if (ret)                                                                \
		return ret;                                                     \
	return sysfs_emit(buf, "%u\n", snapshot._field);                       \
}

#define KERNEL_MCP_DEFINE_AGENT_SHOW_STR(_name, _field)                          \
static ssize_t kernel_mcp_agent_##_name##_show(struct kobject *kobj,             \
					       struct kobj_attribute *attr,      \
					       char *buf)                        \
{                                                                               \
	struct kernel_mcp_agent_snapshot snapshot;                              \
	int ret;                                                                \
	(void)attr;                                                             \
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);                \
	if (ret)                                                                \
		return ret;                                                     \
	return sysfs_emit(buf, "%s\n", snapshot._field);                       \
}

KERNEL_MCP_DEFINE_TOOL_SHOW_STR(name, name)
KERNEL_MCP_DEFINE_TOOL_SHOW_STR(hash, hash)
KERNEL_MCP_DEFINE_TOOL_SHOW_STR(binary_hash, binary_hash)
KERNEL_MCP_DEFINE_TOOL_SHOW_U32(risk_flags, risk_flags, "0x%08x")

static ssize_t kernel_mcp_tool_status_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	unsigned long tool_id;
	const char *id_str;
	struct kernel_mcp_tool *tool;
	int ret;

	(void)attr;
	id_str = kobject_name(kobj);
	ret = kstrtoul(id_str, 10, &tool_id);
	if (ret)
		return ret;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	mutex_unlock(&kernel_mcp_tools_lock);
	if (!tool)
		return -ENOENT;
	return sysfs_emit(buf, "active\n");
}

KERNEL_MCP_DEFINE_AGENT_SHOW_U64(allow, allow_count)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(binding_hash, binding_hash)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(binding_epoch, binding_epoch)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(deny, deny_count)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(defer, defer_count)
KERNEL_MCP_DEFINE_AGENT_SHOW_STR(last_reason, last_reason)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(completed_ok, completed_ok_count)
KERNEL_MCP_DEFINE_AGENT_SHOW_U64(completed_err, completed_err_count)
KERNEL_MCP_DEFINE_AGENT_SHOW_U32(last_exec_ms, last_exec_ms)
KERNEL_MCP_DEFINE_AGENT_SHOW_U32(last_status, last_status)
KERNEL_MCP_DEFINE_AGENT_SHOW_U32(call_log_head, call_log_head)
KERNEL_MCP_DEFINE_AGENT_SHOW_U32(call_log_count, call_log_count)

static ssize_t kernel_mcp_agent_call_log_read(struct file *filp,
					      struct kobject *kobj,
					      struct bin_attribute *attr,
					      char *buf, loff_t pos, size_t size)
{
	struct kernel_mcp_call_record *snapshot;
	const size_t full_bytes =
		sizeof(struct kernel_mcp_call_record) * KERNEL_MCP_CALL_LOG_SIZE;
	u32 valid_records = 0;
	size_t valid_bytes;
	ssize_t copied;
	int ret;

	(void)filp;
	(void)attr;

	if (pos < 0)
		return -EINVAL;
	if ((size_t)pos >= full_bytes)
		return 0;

	snapshot = kzalloc(full_bytes, GFP_KERNEL);
	if (!snapshot)
		return -ENOMEM;

	ret = kernel_mcp_copy_agent_call_log(kobj, snapshot, &valid_records);
	if (ret) {
		kfree(snapshot);
		return ret;
	}

	valid_bytes = (size_t)valid_records * sizeof(struct kernel_mcp_call_record);
	if ((size_t)pos >= valid_bytes) {
		kfree(snapshot);
		return 0;
	}
	copied = min_t(size_t, size, valid_bytes - (size_t)pos);
	memcpy(buf, ((char *)snapshot) + pos, copied);
	kfree(snapshot);
	return copied;
}
static struct kobj_attribute kernel_mcp_name_attr =
	__ATTR(name, 0444, kernel_mcp_tool_name_show, NULL);
static struct kobj_attribute kernel_mcp_hash_attr =
	__ATTR(hash, 0444, kernel_mcp_tool_hash_show, NULL);
static struct kobj_attribute kernel_mcp_binary_hash_attr =
	__ATTR(binary_hash, 0444, kernel_mcp_tool_binary_hash_show, NULL);
static struct kobj_attribute kernel_mcp_risk_flags_attr =
	__ATTR(risk_flags, 0444, kernel_mcp_tool_risk_flags_show, NULL);
static struct kobj_attribute kernel_mcp_tool_status_attr =
	__ATTR(status, 0444, kernel_mcp_tool_status_show, NULL);

static struct attribute *kernel_mcp_tool_attrs[] = {
	&kernel_mcp_name_attr.attr,
	&kernel_mcp_hash_attr.attr,
	&kernel_mcp_binary_hash_attr.attr,
	&kernel_mcp_risk_flags_attr.attr,
	&kernel_mcp_tool_status_attr.attr,
	NULL,
};

static const struct attribute_group kernel_mcp_tool_attr_group = {
	.attrs = kernel_mcp_tool_attrs,
};

static struct kobj_attribute kernel_mcp_agent_allow_attr =
	__ATTR(allow, 0444, kernel_mcp_agent_allow_show, NULL);
static struct kobj_attribute kernel_mcp_agent_binding_hash_attr =
	__ATTR(binding_hash, 0444, kernel_mcp_agent_binding_hash_show, NULL);
static struct kobj_attribute kernel_mcp_agent_binding_epoch_attr =
	__ATTR(binding_epoch, 0444, kernel_mcp_agent_binding_epoch_show, NULL);
static struct kobj_attribute kernel_mcp_agent_deny_attr =
	__ATTR(deny, 0444, kernel_mcp_agent_deny_show, NULL);
static struct kobj_attribute kernel_mcp_agent_defer_attr =
	__ATTR(defer, 0444, kernel_mcp_agent_defer_show, NULL);
static struct kobj_attribute kernel_mcp_agent_last_reason_attr =
	__ATTR(last_reason, 0444, kernel_mcp_agent_last_reason_show, NULL);
static struct kobj_attribute kernel_mcp_agent_completed_ok_attr =
	__ATTR(completed_ok, 0444, kernel_mcp_agent_completed_ok_show, NULL);
static struct kobj_attribute kernel_mcp_agent_completed_err_attr =
	__ATTR(completed_err, 0444, kernel_mcp_agent_completed_err_show, NULL);
static struct kobj_attribute kernel_mcp_agent_last_exec_ms_attr =
	__ATTR(last_exec_ms, 0444, kernel_mcp_agent_last_exec_ms_show, NULL);
static struct kobj_attribute kernel_mcp_agent_last_status_attr =
	__ATTR(last_status, 0444, kernel_mcp_agent_last_status_show, NULL);
static struct kobj_attribute kernel_mcp_agent_call_log_head_attr =
	__ATTR(call_log_head, 0444, kernel_mcp_agent_call_log_head_show, NULL);
static struct kobj_attribute kernel_mcp_agent_call_log_count_attr =
	__ATTR(call_log_count, 0444, kernel_mcp_agent_call_log_count_show, NULL);

static struct bin_attribute kernel_mcp_agent_call_log_bin_attr = {
	.attr = {
		.name = "call_log",
		.mode = 0444,
	},
	.size = sizeof(struct kernel_mcp_call_record) * KERNEL_MCP_CALL_LOG_SIZE,
	.read = kernel_mcp_agent_call_log_read,
};

static struct attribute *kernel_mcp_agent_attrs[] = {
	&kernel_mcp_agent_allow_attr.attr,
	&kernel_mcp_agent_binding_hash_attr.attr,
	&kernel_mcp_agent_binding_epoch_attr.attr,
	&kernel_mcp_agent_deny_attr.attr,
	&kernel_mcp_agent_defer_attr.attr,
	&kernel_mcp_agent_last_reason_attr.attr,
	&kernel_mcp_agent_completed_ok_attr.attr,
	&kernel_mcp_agent_completed_err_attr.attr,
	&kernel_mcp_agent_last_exec_ms_attr.attr,
	&kernel_mcp_agent_last_status_attr.attr,
	&kernel_mcp_agent_call_log_head_attr.attr,
	&kernel_mcp_agent_call_log_count_attr.attr,
	NULL,
};

static const struct attribute_group kernel_mcp_agent_attr_group = {
	.attrs = kernel_mcp_agent_attrs,
};

static void kernel_mcp_tool_sysfs_remove(struct kernel_mcp_tool *tool)
{
	if (!tool->kobj)
		return;
	sysfs_remove_group(tool->kobj, &kernel_mcp_tool_attr_group);
	kobject_put(tool->kobj);
	tool->kobj = NULL;
}

static int kernel_mcp_tool_sysfs_create(struct kernel_mcp_tool *tool)
{
	char tool_id_dir[16];
	int ret;

	if (!kernel_mcp_sysfs_tools)
		return -ENODEV;

	snprintf(tool_id_dir, sizeof(tool_id_dir), "%u", tool->id);
	tool->kobj = kobject_create_and_add(tool_id_dir, kernel_mcp_sysfs_tools);
	if (!tool->kobj)
		return -ENOMEM;

	ret = sysfs_create_group(tool->kobj, &kernel_mcp_tool_attr_group);
	if (ret) {
		kobject_put(tool->kobj);
		tool->kobj = NULL;
		return ret;
	}
	return 0;
}

static void kernel_mcp_tool_free(struct kernel_mcp_tool *tool)
{
	if (!tool)
		return;
	kernel_mcp_tool_sysfs_remove(tool);
	kfree(tool);
}

static void kernel_mcp_tools_destroy_all(void)
{
	struct kernel_mcp_tool *tool;
	unsigned long index = 0;

	mutex_lock(&kernel_mcp_tools_lock);
	for (;;) {
		tool = xa_find(&kernel_mcp_tools, &index, ULONG_MAX, XA_PRESENT);
		if (!tool)
			break;
		xa_erase(&kernel_mcp_tools, index);
		kernel_mcp_tool_free(tool);
		index++;
	}
	mutex_unlock(&kernel_mcp_tools_lock);
}

static int kernel_mcp_register_tool(u32 tool_id, const char *name,
				    u32 risk_flags, const char *hash,
				    const char *binary_hash)
{
	struct kernel_mcp_tool *tool;
	int ret;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (tool) {
		strscpy(tool->name, name, sizeof(tool->name));
		if (hash)
			strscpy(tool->hash, hash, sizeof(tool->hash));
		/* binary_hash is TOFU: only accept a value if the slot is still
		 * empty. Once pinned by a prior TOOL_REQUEST (or an earlier
		 * register), do not silently overwrite it — mismatches must go
		 * through the deny path on cmd_tool_request.
		 */
		if (binary_hash && binary_hash[0] != '\0' &&
		    tool->binary_hash[0] == '\0')
			strscpy(tool->binary_hash, binary_hash,
				sizeof(tool->binary_hash));
		tool->risk_flags = risk_flags;
		mutex_unlock(&kernel_mcp_tools_lock);
		return 0;
	}

	tool = kzalloc(sizeof(*tool), GFP_KERNEL);
	if (!tool) {
		mutex_unlock(&kernel_mcp_tools_lock);
		return -ENOMEM;
	}

	tool->id = tool_id;
	tool->risk_flags = risk_flags;
	strscpy(tool->name, name, sizeof(tool->name));
	if (hash)
		strscpy(tool->hash, hash, sizeof(tool->hash));
	if (binary_hash && binary_hash[0] != '\0')
		strscpy(tool->binary_hash, binary_hash,
			sizeof(tool->binary_hash));

	ret = xa_err(xa_store(&kernel_mcp_tools, tool_id, tool, GFP_KERNEL));
	if (ret) {
		kfree(tool);
		mutex_unlock(&kernel_mcp_tools_lock);
		return ret;
	}

	ret = kernel_mcp_tool_sysfs_create(tool);
	if (ret) {
		xa_erase(&kernel_mcp_tools, tool_id);
		kfree(tool);
		mutex_unlock(&kernel_mcp_tools_lock);
		return ret;
	}

	mutex_unlock(&kernel_mcp_tools_lock);
	return 0;
}

static void kernel_mcp_agent_sysfs_remove(struct kernel_mcp_agent *agent)
{
	if (!agent->kobj)
		return;
	sysfs_remove_bin_file(agent->kobj, &kernel_mcp_agent_call_log_bin_attr);
	sysfs_remove_group(agent->kobj, &kernel_mcp_agent_attr_group);
	kobject_put(agent->kobj);
	agent->kobj = NULL;
}

static int kernel_mcp_agent_sysfs_create(struct kernel_mcp_agent *agent)
{
	int ret;

	if (!kernel_mcp_sysfs_agents)
		return -ENODEV;

	agent->kobj = kobject_create_and_add(agent->id, kernel_mcp_sysfs_agents);
	if (!agent->kobj)
		return -ENOMEM;

	ret = sysfs_create_group(agent->kobj, &kernel_mcp_agent_attr_group);
	if (ret) {
		kobject_put(agent->kobj);
		agent->kobj = NULL;
		return ret;
	}

	ret = sysfs_create_bin_file(agent->kobj,
				    &kernel_mcp_agent_call_log_bin_attr);
	if (ret) {
		sysfs_remove_group(agent->kobj, &kernel_mcp_agent_attr_group);
		kobject_put(agent->kobj);
		agent->kobj = NULL;
		return ret;
	}
	return 0;
}

static void kernel_mcp_agent_free(struct kernel_mcp_agent *agent)
{
	if (!agent)
		return;
	kernel_mcp_agent_sysfs_remove(agent);
	kfree(agent);
}

static void kernel_mcp_agents_destroy_all(void)
{
	struct kernel_mcp_agent *agent;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_agents_lock);
	hash_for_each_safe(kernel_mcp_agents, bkt, tmp, agent, hnode) {
		hash_del(&agent->hnode);
		kernel_mcp_agent_free(agent);
	}
	mutex_unlock(&kernel_mcp_agents_lock);
}

static int kernel_mcp_register_agent(const char *agent_id, u32 pid, bool uid_set,
				     u32 uid, u64 binding_hash,
				     u64 binding_epoch)
{
	struct kernel_mcp_agent *agent;
	u32 key;
	int ret;

	key = kernel_mcp_agent_hash_key(agent_id);
	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (agent) {
		agent->pid = pid;
		agent->uid_set = uid_set;
		if (uid_set)
			agent->uid = uid;
		agent->binding_hash = binding_hash;
		agent->binding_epoch = binding_epoch;
		mutex_unlock(&kernel_mcp_agents_lock);
		return 0;
	}

	agent = kzalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOMEM;
	}

	strscpy(agent->id, agent_id, sizeof(agent->id));
	agent->pid = pid;
	agent->uid = uid;
	agent->uid_set = uid_set;
	agent->binding_hash = binding_hash;
	agent->binding_epoch = binding_epoch;
	strscpy(agent->last_reason, "registered", sizeof(agent->last_reason));

	ret = kernel_mcp_agent_sysfs_create(agent);
	if (ret) {
		kfree(agent);
		mutex_unlock(&kernel_mcp_agents_lock);
		return ret;
	}

	hash_add(kernel_mcp_agents, &agent->hnode, key);
	mutex_unlock(&kernel_mcp_agents_lock);
	return 0;
}

static void kernel_mcp_approval_ticket_free(struct kernel_mcp_approval_ticket *ticket)
{
	kfree(ticket);
}

static void kernel_mcp_approval_destroy_all(void)
{
	struct kernel_mcp_approval_ticket *ticket;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_approval_lock);
	hash_for_each_safe(kernel_mcp_approval_tickets, bkt, tmp, ticket, hnode) {
		hash_del(&ticket->hnode);
		kernel_mcp_approval_ticket_free(ticket);
	}
	mutex_unlock(&kernel_mcp_approval_lock);
}

static struct kernel_mcp_approval_ticket *
kernel_mcp_find_ticket_locked(u64 ticket_id)
{
	struct kernel_mcp_approval_ticket *ticket;

	hash_for_each_possible(kernel_mcp_approval_tickets, ticket, hnode,
			       ticket_id) {
		if (ticket->ticket_id == ticket_id)
			return ticket;
	}
	return NULL;
}

static void kernel_mcp_purge_expired_tickets_locked(void)
{
	struct kernel_mcp_approval_ticket *ticket;
	struct hlist_node *tmp;
	int bkt;

	hash_for_each_safe(kernel_mcp_approval_tickets, bkt, tmp, ticket, hnode) {
		if (time_after_eq(jiffies, ticket->expires_jiffies)) {
			hash_del(&ticket->hnode);
			kernel_mcp_approval_ticket_free(ticket);
		}
	}
}

static void kernel_mcp_ticket_cleanup_timer_fn(struct timer_list *timer)
{
	(void)timer;

	mutex_lock(&kernel_mcp_approval_lock);
	kernel_mcp_purge_expired_tickets_locked();
	mutex_unlock(&kernel_mcp_approval_lock);

	mod_timer(&kernel_mcp_ticket_cleanup_timer,
		  jiffies +
			  msecs_to_jiffies(KERNEL_MCP_TICKET_CLEANUP_INTERVAL_MS));
}

static int kernel_mcp_issue_approval_ticket(const char *agent_id, u64 binding_hash,
					    u64 binding_epoch, u32 tool_id,
					    u64 req_id, const char *tool_hash,
					    u64 *ticket_id_out)
{
	struct kernel_mcp_approval_ticket *ticket;
	u64 ticket_id;

	ticket = kzalloc(sizeof(*ticket), GFP_KERNEL);
	if (!ticket)
		return -ENOMEM;

	mutex_lock(&kernel_mcp_approval_lock);
	ticket_id = ++kernel_mcp_next_ticket_id;
	if (ticket_id == 0)
		ticket_id = ++kernel_mcp_next_ticket_id;

	ticket->ticket_id = ticket_id;
	ticket->req_id = req_id;
	ticket->tool_id = tool_id;
	strscpy(ticket->agent_id, agent_id, sizeof(ticket->agent_id));
	ticket->binding_hash = binding_hash;
	ticket->binding_epoch = binding_epoch;
	if (tool_hash)
		strscpy(ticket->tool_hash, tool_hash, sizeof(ticket->tool_hash));
	strscpy(ticket->reason, "pending_approval", sizeof(ticket->reason));
	ticket->expires_jiffies =
		jiffies + msecs_to_jiffies(KERNEL_MCP_DEFAULT_APPROVAL_TTL_MS);

	kernel_mcp_purge_expired_tickets_locked();
	hash_add(kernel_mcp_approval_tickets, &ticket->hnode, ticket->ticket_id);
	mutex_unlock(&kernel_mcp_approval_lock);

	*ticket_id_out = ticket_id;
	return 0;
}

static bool kernel_mcp_consume_approval_ticket(u64 ticket_id, const char *agent_id,
						u64 binding_hash, u64 binding_epoch,
						u32 tool_id, u64 req_id,
						const char *tool_hash,
						const char **reason_out)
{
	struct kernel_mcp_approval_ticket *ticket;
	bool allow = false;
	const char *reason = "approval_missing";

	if (ticket_id == 0) {
		*reason_out = reason;
		return false;
	}

	mutex_lock(&kernel_mcp_approval_lock);
	kernel_mcp_purge_expired_tickets_locked();
	ticket = kernel_mcp_find_ticket_locked(ticket_id);
	if (!ticket) {
		reason = "approval_ticket_unknown";
		goto out;
	}
	if (ticket->consumed) {
		reason = "approval_ticket_consumed";
		goto out;
	}
	if (ticket->req_id != req_id || ticket->tool_id != tool_id ||
	    strcmp(ticket->agent_id, agent_id) != 0) {
		reason = "approval_ticket_scope_mismatch";
		goto out;
	}
	if (ticket->binding_hash != binding_hash ||
	    ticket->binding_epoch != binding_epoch) {
		reason = "approval_ticket_binding_mismatch";
		goto out;
	}
	if (tool_hash && ticket->tool_hash[0] != '\0' &&
	    strcmp(ticket->tool_hash, tool_hash) != 0) {
		reason = "approval_ticket_hash_mismatch";
		goto out;
	}
	if (!ticket->decided) {
		reason = "approval_pending";
		goto out;
	}
	if (!ticket->approved) {
		reason = "approval_denied";
		goto out;
	}
	ticket->consumed = true;
	allow = true;
	reason = "approval_ticket_consumed";
out:
	mutex_unlock(&kernel_mcp_approval_lock);
	*reason_out = reason;
	return allow;
}

static int kernel_mcp_reply_tool_decision(struct genl_info *info,
					  const char *agent_id, u32 tool_id,
					  u64 req_id, u32 decision,
					  const char *reason, u64 ticket_id)
{
	struct sk_buff *reply_skb;
	void *reply_hdr;
	int ret;

	reply_skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply_skb)
		return -ENOMEM;

	reply_hdr = genlmsg_put_reply(reply_skb, info, &kernel_mcp_genl_family, 0,
				      KERNEL_MCP_CMD_TOOL_DECISION);
	if (!reply_hdr) {
		nlmsg_free(reply_skb);
		return -EMSGSIZE;
	}

	ret = nla_put_string(reply_skb, KERNEL_MCP_ATTR_AGENT_ID, agent_id);
	if (ret)
		goto nla_fail;
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_TOOL_ID, tool_id);
	if (ret)
		goto nla_fail;
	ret = nla_put_u64_64bit(reply_skb, KERNEL_MCP_ATTR_REQ_ID, req_id,
				KERNEL_MCP_ATTR_UNSPEC);
	if (ret)
		goto nla_fail;
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_DECISION, decision);
	if (ret)
		goto nla_fail;
	ret = nla_put_string(reply_skb, KERNEL_MCP_ATTR_MESSAGE, reason);
	if (ret)
		goto nla_fail;
	if (ticket_id > 0) {
		ret = nla_put_u64_64bit(reply_skb, KERNEL_MCP_ATTR_TICKET_ID,
					ticket_id, KERNEL_MCP_ATTR_UNSPEC);
		if (ret)
			goto nla_fail;
	}

	genlmsg_end(reply_skb, reply_hdr);
	return genlmsg_reply(reply_skb, info);

nla_fail:
	genlmsg_cancel(reply_skb, reply_hdr);
	nlmsg_free(reply_skb);
	return -EMSGSIZE;
}

static int kernel_mcp_cmd_tool_register(struct sk_buff *skb,
					struct genl_info *info)
{
	u32 tool_id;
	u32 risk_flags;
	const char *tool_name;
	const char *tool_hash = NULL;
	const char *binary_hash = NULL;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_TOOL_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_NAME] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_RISK_FLAGS])
		return -EINVAL;

	tool_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_ID]);
	tool_name = nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_NAME]);
	risk_flags = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_RISK_FLAGS]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_HASH])
		tool_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_BINARY_HASH])
		binary_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_BINARY_HASH]);

	return kernel_mcp_register_tool(tool_id, tool_name, risk_flags,
					tool_hash, binary_hash);
}

static int kernel_mcp_cmd_agent_register(struct sk_buff *skb,
					 struct genl_info *info)
{
	const char *agent_id;
	u32 pid;
	u32 uid = 0;
	u64 binding_hash = 0;
	u64 binding_epoch = 0;
	bool uid_set = false;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_AGENT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_PID])
		return -EINVAL;

	agent_id = nla_data(info->attrs[KERNEL_MCP_ATTR_AGENT_ID]);
	pid = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_PID]);
	if (info->attrs[KERNEL_MCP_ATTR_UID]) {
		uid = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_UID]);
		uid_set = true;
	}
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING])
		binding_hash = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH])
		binding_epoch = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH]);

	return kernel_mcp_register_agent(agent_id, pid, uid_set, uid, binding_hash,
					 binding_epoch);
}

static int kernel_mcp_cmd_tool_request(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_agent *agent;
	struct kernel_mcp_tool *tool;
	const char *agent_id;
	const char *requested_tool_hash = NULL;
	const char *requested_binary_hash = NULL;
	const char *reason = "allow";
	const char *ticket_reason = "approval_missing";
	const u8 *payload_hash = NULL;
	size_t payload_hash_len = 0;
	u32 tool_id;
	u64 req_id;
	u64 ticket_id = 0;
	u64 binding_hash = 0;
	u64 binding_epoch = 0;
	u32 decision = KERNEL_MCP_DECISION_ALLOW;
	u32 risk_flags = 0;
	u32 key;
	bool hash_mismatch = false;
	bool binary_mismatch = false;
	bool binary_tofu_locked = false;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_AGENT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_REQ_ID])
		return -EINVAL;

	agent_id = nla_data(info->attrs[KERNEL_MCP_ATTR_AGENT_ID]);
	tool_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_ID]);
	req_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_REQ_ID]);
	key = kernel_mcp_agent_hash_key(agent_id);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_HASH])
		requested_tool_hash =
			nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_TICKET_ID])
		ticket_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_TICKET_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING])
		binding_hash = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH])
		binding_epoch = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH]);
	if (info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH]) {
		payload_hash_len = nla_len(info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH]);
		if (payload_hash_len >= KERNEL_MCP_CALL_HASH_PREFIX)
			payload_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH]);
	}
	if (info->attrs[KERNEL_MCP_ATTR_BINARY_HASH])
		requested_binary_hash =
			nla_data(info->attrs[KERNEL_MCP_ATTR_BINARY_HASH]);

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (!tool) {
		mutex_unlock(&kernel_mcp_tools_lock);
		return -ENOENT;
	}
	risk_flags = tool->risk_flags;
	if (requested_tool_hash && tool->hash[0] != '\0' &&
	    strcmp(tool->hash, requested_tool_hash) != 0)
		hash_mismatch = true;
	/* Binary-hash TOFU: on first non-empty observation lock it in; on any
	 * subsequent request, compare strictly. Missing binary_hash on the
	 * request leaves an already-pinned value unchanged and does NOT deny —
	 * we only enforce when mcpd actually asserts a hash.
	 */
	if (requested_binary_hash && requested_binary_hash[0] != '\0') {
		if (tool->binary_hash[0] == '\0') {
			strscpy(tool->binary_hash, requested_binary_hash,
				sizeof(tool->binary_hash));
			binary_tofu_locked = true;
		} else if (strcmp(tool->binary_hash,
				  requested_binary_hash) != 0) {
			binary_mismatch = true;
		}
	}
	mutex_unlock(&kernel_mcp_tools_lock);

	if (binary_tofu_locked)
		pr_info("kernel_mcp: TOFU-locked tool %u binary_hash\n",
			tool_id);

	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		decision = KERNEL_MCP_DECISION_DENY;
		reason = "deny_unknown_agent";
		mutex_unlock(&kernel_mcp_agents_lock);
		return kernel_mcp_reply_tool_decision(info, agent_id, tool_id, req_id,
						      decision, reason, ticket_id);
	}

	if (hash_mismatch) {
		decision = KERNEL_MCP_DECISION_DENY;
		reason = "hash_mismatch";
		goto out_accounting;
	}
	if (binary_mismatch) {
		decision = KERNEL_MCP_DECISION_DENY;
		reason = "binary_mismatch";
		goto out_accounting;
	}
	if (agent->binding_hash != binding_hash ||
	    agent->binding_epoch != binding_epoch) {
		decision = KERNEL_MCP_DECISION_DENY;
		reason = "binding_mismatch";
		goto out_accounting;
	}

	if (risk_flags & KERNEL_MCP_APPROVAL_REQUIRED_FLAGS) {
		if (kernel_mcp_consume_approval_ticket(ticket_id, agent_id,
						      binding_hash,
						      binding_epoch, tool_id,
						      req_id,
						      requested_tool_hash,
						      &ticket_reason)) {
			decision = KERNEL_MCP_DECISION_ALLOW;
			reason = "allow_approved";
			goto out_accounting;
		}

		decision = KERNEL_MCP_DECISION_DEFER;
		reason = ticket_reason;
		if (ticket_id == 0) {
			if (kernel_mcp_issue_approval_ticket(agent_id, binding_hash,
							     binding_epoch,
							     tool_id,
							     req_id,
							     requested_tool_hash,
							     &ticket_id) == 0)
				reason = "require_approval";
			else
				reason = "approval_unavailable";
		}
		goto out_accounting;
	}

	decision = KERNEL_MCP_DECISION_ALLOW;
	reason = "allow";

out_accounting:
	if (decision == KERNEL_MCP_DECISION_ALLOW) {
		agent->allow_count++;
	} else if (decision == KERNEL_MCP_DECISION_DENY) {
		agent->deny_count++;
	} else {
		agent->defer_count++;
	}
	strscpy(agent->last_reason, reason, sizeof(agent->last_reason));

	/* For DENY/DEFER the tool never ran; record an audit entry here so
	 * rejections remain visible after mcpd dies. ALLOW gets its entry on
	 * tool_complete, which carries the real exec_ms and response summary.
	 */
	if (decision != KERNEL_MCP_DECISION_ALLOW) {
		u32 rec_status = (decision == KERNEL_MCP_DECISION_DENY)
					 ? KERNEL_MCP_CALL_STATUS_DENY
					 : KERNEL_MCP_CALL_STATUS_DEFER;
		kernel_mcp_agent_call_log_append(
			agent, req_id, tool_id, rec_status, 0, payload_hash,
			NULL, (const u8 *)reason,
			reason ? strnlen(reason, KERNEL_MCP_CALL_ERR_HEAD_MAX) : 0);
	}
	mutex_unlock(&kernel_mcp_agents_lock);

	return kernel_mcp_reply_tool_decision(info, agent_id, tool_id, req_id,
					      decision, reason, ticket_id);
}

static int kernel_mcp_cmd_tool_complete(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_agent *agent;
	const char *agent_id;
	const u8 *payload_hash = NULL;
	const u8 *response_hash = NULL;
	const u8 *err_head = NULL;
	size_t err_head_len = 0;
	u32 tool_id;
	u64 req_id;
	u32 status;
	u32 exec_ms;
	u32 key;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_REQ_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_AGENT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_STATUS] ||
	    !info->attrs[KERNEL_MCP_ATTR_EXEC_MS])
		return -EINVAL;

	req_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_REQ_ID]);
	agent_id = nla_data(info->attrs[KERNEL_MCP_ATTR_AGENT_ID]);
	tool_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_ID]);
	status = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_STATUS]);
	exec_ms = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_EXEC_MS]);
	if (info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH] &&
	    nla_len(info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH]) >= KERNEL_MCP_CALL_HASH_PREFIX)
		payload_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_PAYLOAD_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_RESPONSE_HASH] &&
	    nla_len(info->attrs[KERNEL_MCP_ATTR_RESPONSE_HASH]) >= KERNEL_MCP_CALL_HASH_PREFIX)
		response_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_RESPONSE_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_ERR_HEAD]) {
		err_head_len = nla_len(info->attrs[KERNEL_MCP_ATTR_ERR_HEAD]);
		err_head = nla_data(info->attrs[KERNEL_MCP_ATTR_ERR_HEAD]);
	}

	key = kernel_mcp_agent_hash_key(agent_id);
	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOENT;
	}

	if (status == KERNEL_MCP_COMPLETE_STATUS_OK)
		agent->completed_ok_count++;
	else
		agent->completed_err_count++;
	agent->last_exec_ms = exec_ms;
	agent->last_status = status;

	kernel_mcp_agent_call_log_append(
		agent, req_id, tool_id,
		status == KERNEL_MCP_COMPLETE_STATUS_OK
			? KERNEL_MCP_CALL_STATUS_OK
			: KERNEL_MCP_CALL_STATUS_ERR,
		exec_ms, payload_hash, response_hash, err_head, err_head_len);
	mutex_unlock(&kernel_mcp_agents_lock);
	return 0;
}

static int kernel_mcp_cmd_approval_decide(struct sk_buff *skb,
					  struct genl_info *info)
{
	struct kernel_mcp_approval_ticket *ticket;
	u64 ticket_id;
	const char *agent_id;
	u32 decision;
	u32 ttl_ms = KERNEL_MCP_DEFAULT_APPROVAL_TTL_MS;
	u64 binding_hash = 0;
	u64 binding_epoch = 0;
	const char *approver;
	const char *reason;
	bool approved;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_TICKET_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_AGENT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_APPROVAL_DECISION] ||
	    !info->attrs[KERNEL_MCP_ATTR_APPROVER] ||
	    !info->attrs[KERNEL_MCP_ATTR_APPROVAL_REASON])
		return -EINVAL;

	ticket_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_TICKET_ID]);
	agent_id = nla_data(info->attrs[KERNEL_MCP_ATTR_AGENT_ID]);
	decision = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_APPROVAL_DECISION]);
	approver = nla_data(info->attrs[KERNEL_MCP_ATTR_APPROVER]);
	reason = nla_data(info->attrs[KERNEL_MCP_ATTR_APPROVAL_REASON]);
	if (info->attrs[KERNEL_MCP_ATTR_APPROVAL_TTL_MS])
		ttl_ms = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_APPROVAL_TTL_MS]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING])
		binding_hash = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_BINDING]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH])
		binding_epoch = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_EPOCH]);

	mutex_lock(&kernel_mcp_approval_lock);
	kernel_mcp_purge_expired_tickets_locked();
	ticket = kernel_mcp_find_ticket_locked(ticket_id);
	if (!ticket) {
		mutex_unlock(&kernel_mcp_approval_lock);
		return -ENOENT;
	}
	if (ticket->consumed) {
		mutex_unlock(&kernel_mcp_approval_lock);
		return -EPERM;
	}
	if (strcmp(ticket->agent_id, agent_id) != 0 ||
	    ticket->binding_hash != binding_hash ||
	    ticket->binding_epoch != binding_epoch) {
		mutex_unlock(&kernel_mcp_approval_lock);
		return -EPERM;
	}

	strscpy(ticket->approver, approver, sizeof(ticket->approver));
	strscpy(ticket->reason, reason, sizeof(ticket->reason));
	if (decision == KERNEL_MCP_APPROVAL_APPROVE)
		approved = true;
	else if (decision == KERNEL_MCP_APPROVAL_DENY ||
		 decision == KERNEL_MCP_APPROVAL_REVOKE)
		approved = false;
	else {
		mutex_unlock(&kernel_mcp_approval_lock);
		return -EINVAL;
	}

	ticket->decided = true;
	ticket->approved = approved;
	ticket->expires_jiffies = jiffies + msecs_to_jiffies(ttl_ms);
	mutex_unlock(&kernel_mcp_approval_lock);
	return 0;
}

static int kernel_mcp_cmd_reset_tools(struct sk_buff *skb,
				      struct genl_info *info)
{
	(void)skb;
	(void)info;
	kernel_mcp_tools_destroy_all();
	return 0;
}

static int kernel_mcp_cmd_list_tools_dump(struct sk_buff *skb,
					  struct netlink_callback *cb)
{
	struct kernel_mcp_tool *tool;
	unsigned long index = cb->args[0];
	void *msg_hdr;
	int ret = 0;

	mutex_lock(&kernel_mcp_tools_lock);
	for (;;) {
		tool = xa_find(&kernel_mcp_tools, &index, ULONG_MAX, XA_PRESENT);
		if (!tool)
			break;

		msg_hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, &kernel_mcp_genl_family,
				      NLM_F_MULTI, KERNEL_MCP_CMD_LIST_TOOLS);
		if (!msg_hdr) {
			ret = -EMSGSIZE;
			break;
		}

		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_TOOL_ID, tool->id);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_string(skb, KERNEL_MCP_ATTR_TOOL_NAME, tool->name);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_TOOL_RISK_FLAGS,
				  tool->risk_flags);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_STATUS,
				  KERNEL_MCP_TOOL_STATUS_ACTIVE);
		if (ret)
			goto dump_nla_fail;
		if (tool->hash[0] != '\0') {
			ret = nla_put_string(skb, KERNEL_MCP_ATTR_TOOL_HASH,
					     tool->hash);
			if (ret)
				goto dump_nla_fail;
		}
		if (tool->binary_hash[0] != '\0') {
			ret = nla_put_string(skb,
					     KERNEL_MCP_ATTR_BINARY_HASH,
					     tool->binary_hash);
			if (ret)
				goto dump_nla_fail;
		}

		genlmsg_end(skb, msg_hdr);
		cb->args[0] = index + 1;
		index++;
		continue;

dump_nla_fail:
		genlmsg_cancel(skb, msg_hdr);
		ret = -EMSGSIZE;
		break;
	}
	mutex_unlock(&kernel_mcp_tools_lock);

	if (ret == -EMSGSIZE && skb->len > 0)
		return skb->len;
	if (ret)
		return ret;
	return skb->len;
}

static const struct genl_ops kernel_mcp_genl_ops[] = {
	{
		/* Registry mutation: only mcpd (root/CAP_NET_ADMIN) may register tools. */
		.cmd = KERNEL_MCP_CMD_TOOL_REGISTER,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_tool_register,
	},
	{
		/* Catalog read: any process may enumerate registered tools. */
		.cmd = KERNEL_MCP_CMD_LIST_TOOLS,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.dumpit = kernel_mcp_cmd_list_tools_dump,
	},
	{
		/* Registry mutation: only mcpd (root/CAP_NET_ADMIN) may register agents. */
		.cmd = KERNEL_MCP_CMD_AGENT_REGISTER,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_agent_register,
	},
	{
		/* Admission: open to registered callers; binding_hash check enforces identity. */
		.cmd = KERNEL_MCP_CMD_TOOL_REQUEST,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_tool_request,
	},
	{
		/* Lifecycle close: only mcpd (root/CAP_NET_ADMIN) may close an invocation. */
		.cmd = KERNEL_MCP_CMD_TOOL_COMPLETE,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_tool_complete,
	},
	{
		/* Approval resolution: only mcpd (root/CAP_NET_ADMIN) may resolve tickets. */
		.cmd = KERNEL_MCP_CMD_APPROVAL_DECIDE,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_approval_decide,
	},
	{
		/* Registry reset: only mcpd (root/CAP_NET_ADMIN) may clear the tool registry. */
		.cmd = KERNEL_MCP_CMD_RESET_TOOLS,
		.flags = GENL_ADMIN_PERM,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_MAX,
		.doit = kernel_mcp_cmd_reset_tools,
	},
};

static struct genl_family kernel_mcp_genl_family = {
	.name = KERNEL_MCP_GENL_FAMILY_NAME,
	.version = KERNEL_MCP_GENL_FAMILY_VERSION,
	.maxattr = KERNEL_MCP_ATTR_MAX,
	.module = THIS_MODULE,
	.ops = kernel_mcp_genl_ops,
	.n_ops = ARRAY_SIZE(kernel_mcp_genl_ops),
};

static int kernel_mcp_sysfs_init(void)
{
	kernel_mcp_sysfs_root = kobject_create_and_add("mcp", kernel_kobj);
	if (!kernel_mcp_sysfs_root)
		return -ENOMEM;

	kernel_mcp_sysfs_tools = kobject_create_and_add("tools",
							kernel_mcp_sysfs_root);
	if (!kernel_mcp_sysfs_tools)
		goto fail_root;

	kernel_mcp_sysfs_agents = kobject_create_and_add("agents",
							 kernel_mcp_sysfs_root);
	if (!kernel_mcp_sysfs_agents)
		goto fail_tools;

	return 0;

fail_tools:
	kobject_put(kernel_mcp_sysfs_tools);
	kernel_mcp_sysfs_tools = NULL;
fail_root:
	kobject_put(kernel_mcp_sysfs_root);
	kernel_mcp_sysfs_root = NULL;
	return -ENOMEM;
}

static void kernel_mcp_sysfs_exit(void)
{
	if (kernel_mcp_sysfs_agents) {
		kobject_put(kernel_mcp_sysfs_agents);
		kernel_mcp_sysfs_agents = NULL;
	}
	if (kernel_mcp_sysfs_tools) {
		kobject_put(kernel_mcp_sysfs_tools);
		kernel_mcp_sysfs_tools = NULL;
	}
	if (kernel_mcp_sysfs_root) {
		kobject_put(kernel_mcp_sysfs_root);
		kernel_mcp_sysfs_root = NULL;
	}
}

static int __init kernel_mcp_init(void)
{
	int ret;

	timer_setup(&kernel_mcp_ticket_cleanup_timer,
		    kernel_mcp_ticket_cleanup_timer_fn, 0);
	mod_timer(&kernel_mcp_ticket_cleanup_timer,
		  jiffies +
			  msecs_to_jiffies(KERNEL_MCP_TICKET_CLEANUP_INTERVAL_MS));

	ret = kernel_mcp_sysfs_init();
	if (ret) {
		del_timer_sync(&kernel_mcp_ticket_cleanup_timer);
		pr_err("kernel_mcp: sysfs init failed: %d\n", ret);
		return ret;
	}

	ret = genl_register_family(&kernel_mcp_genl_family);
	if (ret) {
		pr_err("kernel_mcp: genl_register_family failed: %d\n", ret);
		kernel_mcp_sysfs_exit();
		del_timer_sync(&kernel_mcp_ticket_cleanup_timer);
		return ret;
	}

	pr_info("kernel_mcp: loaded (family=%s version=%u)\n",
		kernel_mcp_genl_family.name, kernel_mcp_genl_family.version);
	return 0;
}

static void __exit kernel_mcp_exit(void)
{
	int ret;

	del_timer_sync(&kernel_mcp_ticket_cleanup_timer);

	ret = genl_unregister_family(&kernel_mcp_genl_family);
	if (ret)
		pr_err("kernel_mcp: genl_unregister_family failed: %d\n", ret);

	kernel_mcp_approval_destroy_all();
	kernel_mcp_agents_destroy_all();
	kernel_mcp_tools_destroy_all();
	kernel_mcp_sysfs_exit();
	pr_info("kernel_mcp: unloaded\n");
}

module_init(kernel_mcp_init);
module_exit(kernel_mcp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linux-mcp");
MODULE_DESCRIPTION("Kernel MCP control-plane Generic Netlink");
MODULE_VERSION("0.3.0");
