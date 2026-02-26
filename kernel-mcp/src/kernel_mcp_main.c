#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include <linux/kernel_mcp_schema.h>

#define KERNEL_MCP_TOOL_NAME_MAX 128
#define KERNEL_MCP_TOOL_HASH_MAX 17
#define KERNEL_MCP_AGENT_ID_MAX 64
#define KERNEL_MCP_REASON_MAX 64

#define KERNEL_MCP_TOOL_STATUS_ACTIVE 1U

#define KERNEL_MCP_DECISION_ALLOW 1U
#define KERNEL_MCP_DECISION_DENY 2U
#define KERNEL_MCP_DECISION_DEFER 3U

#define KERNEL_MCP_COMPLETE_STATUS_OK 0U
#define KERNEL_MCP_COMPLETE_STATUS_ERR 1U

#define KERNEL_MCP_CPU_BURN_TOOL_ID 2U
#define KERNEL_MCP_BUCKET_MAX_TOKENS 2U
#define KERNEL_MCP_BUCKET_REFILL_JIFFIES (5 * HZ)
#define KERNEL_MCP_DEFER_WAIT_MS 500U

#define KERNEL_MCP_AGENT_HASH_BITS 8

struct kernel_mcp_tool {
	u32 id;
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 perm;
	u32 cost;
	struct kobject *kobj;
};

struct kernel_mcp_tool_snapshot {
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 perm;
	u32 cost;
};

struct kernel_mcp_agent {
	char id[KERNEL_MCP_AGENT_ID_MAX];
	u32 pid;
	u32 uid;
	bool uid_set;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u32 last_exec_ms;
	u32 last_status;
	char last_reason[KERNEL_MCP_REASON_MAX];
	u32 bucket_tokens;
	unsigned long bucket_last_jiffies;
	spinlock_t bucket_lock;
	struct hlist_node hnode;
	struct kobject *kobj;
};

struct kernel_mcp_agent_snapshot {
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u32 last_exec_ms;
	u32 last_status;
	char last_reason[KERNEL_MCP_REASON_MAX];
};

static DEFINE_XARRAY(kernel_mcp_tools);
static DEFINE_MUTEX(kernel_mcp_tools_lock);

static DEFINE_HASHTABLE(kernel_mcp_agents, KERNEL_MCP_AGENT_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_agents_lock);

static struct kobject *kernel_mcp_sysfs_root;
static struct kobject *kernel_mcp_sysfs_tools;
static struct kobject *kernel_mcp_sysfs_agents;
static struct genl_family kernel_mcp_genl_family;

static const struct nla_policy kernel_mcp_policy[KERNEL_MCP_ATTR_EXEC_MS + 1] = {
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
	[KERNEL_MCP_ATTR_TOKEN_COST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOKENS_LEFT] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_STATUS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_MESSAGE] = { .type = NLA_NUL_STRING, .len = 256 },
	[KERNEL_MCP_ATTR_UNIX_SOCK_PATH] = { .type = NLA_NUL_STRING, .len = 108 },
	[KERNEL_MCP_ATTR_PAYLOAD_LEN] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_AUDIT_SEQ] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TS_NS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TOOL_PERM] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_COST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_PID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_UID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_DECISION] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_WAIT_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_HASH] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_TOOL_HASH_MAX - 1,
	},
	[KERNEL_MCP_ATTR_EXEC_MS] = { .type = NLA_U32 },
};

static u32 kernel_mcp_agent_hash_key(const char *agent_id)
{
	return jhash(agent_id, strlen(agent_id), 0);
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
	out->perm = tool->perm;
	out->cost = tool->cost;
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
	out->deny_count = agent->deny_count;
	out->defer_count = agent->defer_count;
	out->completed_ok_count = agent->completed_ok_count;
	out->completed_err_count = agent->completed_err_count;
	out->last_exec_ms = agent->last_exec_ms;
	out->last_status = agent->last_status;
	strscpy(out->last_reason, agent->last_reason, sizeof(out->last_reason));
	mutex_unlock(&kernel_mcp_agents_lock);
	return 0;
}

static ssize_t kernel_mcp_tool_name_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.name);
}

static ssize_t kernel_mcp_tool_perm_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.perm);
}

static ssize_t kernel_mcp_tool_hash_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.hash);
}

static ssize_t kernel_mcp_tool_cost_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.cost);
}

static ssize_t kernel_mcp_tool_status_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "active\n");
}

static ssize_t kernel_mcp_agent_allow_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.allow_count);
}

static ssize_t kernel_mcp_agent_deny_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.deny_count);
}

static ssize_t kernel_mcp_agent_defer_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.defer_count);
}

static ssize_t kernel_mcp_agent_last_reason_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.last_reason);
}

static ssize_t kernel_mcp_agent_completed_ok_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_ok_count);
}

static ssize_t kernel_mcp_agent_completed_err_show(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_err_count);
}

static ssize_t kernel_mcp_agent_last_exec_ms_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.last_exec_ms);
}

static ssize_t kernel_mcp_agent_last_status_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.last_status);
}

static struct kobj_attribute kernel_mcp_name_attr =
	__ATTR(name, 0444, kernel_mcp_tool_name_show, NULL);
static struct kobj_attribute kernel_mcp_perm_attr =
	__ATTR(perm, 0444, kernel_mcp_tool_perm_show, NULL);
static struct kobj_attribute kernel_mcp_hash_attr =
	__ATTR(hash, 0444, kernel_mcp_tool_hash_show, NULL);
static struct kobj_attribute kernel_mcp_cost_attr =
	__ATTR(cost, 0444, kernel_mcp_tool_cost_show, NULL);
static struct kobj_attribute kernel_mcp_tool_status_attr =
	__ATTR(status, 0444, kernel_mcp_tool_status_show, NULL);

static struct attribute *kernel_mcp_tool_attrs[] = {
	&kernel_mcp_name_attr.attr,
	&kernel_mcp_perm_attr.attr,
	&kernel_mcp_hash_attr.attr,
	&kernel_mcp_cost_attr.attr,
	&kernel_mcp_tool_status_attr.attr,
	NULL,
};

static const struct attribute_group kernel_mcp_tool_attr_group = {
	.attrs = kernel_mcp_tool_attrs,
};

static struct kobj_attribute kernel_mcp_agent_allow_attr =
	__ATTR(allow, 0444, kernel_mcp_agent_allow_show, NULL);
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

static struct attribute *kernel_mcp_agent_attrs[] = {
	&kernel_mcp_agent_allow_attr.attr,
	&kernel_mcp_agent_deny_attr.attr,
	&kernel_mcp_agent_defer_attr.attr,
	&kernel_mcp_agent_last_reason_attr.attr,
	&kernel_mcp_agent_completed_ok_attr.attr,
	&kernel_mcp_agent_completed_err_attr.attr,
	&kernel_mcp_agent_last_exec_ms_attr.attr,
	&kernel_mcp_agent_last_status_attr.attr,
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

static int kernel_mcp_register_tool(u32 tool_id, const char *name, u32 perm,
				    u32 cost, const char *hash)
{
	struct kernel_mcp_tool *tool;
	int ret;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (tool) {
		strscpy(tool->name, name, sizeof(tool->name));
		if (hash)
			strscpy(tool->hash, hash, sizeof(tool->hash));
		tool->perm = perm;
		tool->cost = cost;
		mutex_unlock(&kernel_mcp_tools_lock);
		return 0;
	}

	tool = kzalloc(sizeof(*tool), GFP_KERNEL);
	if (!tool) {
		mutex_unlock(&kernel_mcp_tools_lock);
		return -ENOMEM;
	}

	tool->id = tool_id;
	tool->perm = perm;
	tool->cost = cost;
	strscpy(tool->name, name, sizeof(tool->name));
	if (hash)
		strscpy(tool->hash, hash, sizeof(tool->hash));

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
				     u32 uid)
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
	strscpy(agent->last_reason, "registered", sizeof(agent->last_reason));
	agent->bucket_tokens = KERNEL_MCP_BUCKET_MAX_TOKENS;
	agent->bucket_last_jiffies = jiffies;
	spin_lock_init(&agent->bucket_lock);

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

static void kernel_mcp_agent_bucket_refill(struct kernel_mcp_agent *agent)
{
	unsigned long delta;
	unsigned long refill_units;
	u32 new_tokens;

	delta = jiffies - agent->bucket_last_jiffies;
	refill_units = delta / KERNEL_MCP_BUCKET_REFILL_JIFFIES;
	if (refill_units == 0)
		return;

	new_tokens = agent->bucket_tokens + (u32)refill_units;
	if (new_tokens > KERNEL_MCP_BUCKET_MAX_TOKENS)
		new_tokens = KERNEL_MCP_BUCKET_MAX_TOKENS;
	agent->bucket_tokens = new_tokens;
	agent->bucket_last_jiffies +=
		refill_units * KERNEL_MCP_BUCKET_REFILL_JIFFIES;
}

static int kernel_mcp_reply_pong(struct genl_info *info, u64 req_id,
				 const char *payload, u32 payload_len)
{
	struct sk_buff *reply_skb;
	void *reply_hdr;
	int ret;

	reply_skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply_skb)
		return -ENOMEM;

	reply_hdr = genlmsg_put_reply(reply_skb, info, &kernel_mcp_genl_family, 0,
				      KERNEL_MCP_CMD_PONG);
	if (!reply_hdr) {
		nlmsg_free(reply_skb);
		return -EMSGSIZE;
	}

	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_STATUS, 0);
	if (ret)
		goto nla_fail;
	ret = nla_put(reply_skb, KERNEL_MCP_ATTR_MESSAGE, payload_len + 1,
		      payload);
	if (ret)
		goto nla_fail;
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_PAYLOAD_LEN, payload_len);
	if (ret)
		goto nla_fail;
	ret = nla_put_u64_64bit(reply_skb, KERNEL_MCP_ATTR_REQ_ID, req_id,
				KERNEL_MCP_ATTR_UNSPEC);
	if (ret)
		goto nla_fail;

	genlmsg_end(reply_skb, reply_hdr);
	return genlmsg_reply(reply_skb, info);

nla_fail:
	genlmsg_cancel(reply_skb, reply_hdr);
	nlmsg_free(reply_skb);
	return -EMSGSIZE;
}

static int kernel_mcp_reply_tool_decision(struct genl_info *info,
					  const char *agent_id, u32 tool_id,
					  u64 req_id, u32 decision,
					  u32 wait_ms, u32 tokens_left,
					  const char *reason)
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
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_WAIT_MS, wait_ms);
	if (ret)
		goto nla_fail;
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_TOKENS_LEFT, tokens_left);
	if (ret)
		goto nla_fail;
	ret = nla_put_string(reply_skb, KERNEL_MCP_ATTR_MESSAGE, reason);
	if (ret)
		goto nla_fail;

	genlmsg_end(reply_skb, reply_hdr);
	return genlmsg_reply(reply_skb, info);

nla_fail:
	genlmsg_cancel(reply_skb, reply_hdr);
	nlmsg_free(reply_skb);
	return -EMSGSIZE;
}

static int kernel_mcp_cmd_ping(struct sk_buff *skb, struct genl_info *info)
{
	const struct nlattr *payload_attr;
	const char *payload = "ping";
	u32 payload_len = 4;
	u64 req_id = 0;
	int len;

	(void)skb;
	if (!info)
		return -EINVAL;

	if (info->attrs[KERNEL_MCP_ATTR_REQ_ID])
		req_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_REQ_ID]);

	payload_attr = info->attrs[KERNEL_MCP_ATTR_MESSAGE];
	if (payload_attr) {
		payload = nla_data(payload_attr);
		len = nla_len(payload_attr);
		if (len <= 0)
			return -EINVAL;
		payload_len = len - 1;
	}

	return kernel_mcp_reply_pong(info, req_id, payload, payload_len);
}

static int kernel_mcp_cmd_tool_register(struct sk_buff *skb,
					struct genl_info *info)
{
	u32 tool_id;
	u32 perm;
	u32 cost;
	const char *tool_name;
	const char *tool_hash = NULL;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_TOOL_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_NAME] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_PERM] ||
	    !info->attrs[KERNEL_MCP_ATTR_TOOL_COST])
		return -EINVAL;

	tool_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_ID]);
	tool_name = nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_NAME]);
	perm = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_PERM]);
	cost = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_COST]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_HASH])
		tool_hash = nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_HASH]);

	return kernel_mcp_register_tool(tool_id, tool_name, perm, cost, tool_hash);
}

static int kernel_mcp_cmd_agent_register(struct sk_buff *skb,
					 struct genl_info *info)
{
	const char *agent_id;
	u32 pid;
	u32 uid = 0;
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

	return kernel_mcp_register_agent(agent_id, pid, uid_set, uid);
}

static int kernel_mcp_cmd_tool_request(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_agent *agent;
	struct kernel_mcp_tool *tool;
	const char *agent_id;
	const char *requested_tool_hash = NULL;
	const char *reason = "allow";
	u32 tool_id;
	u64 req_id;
	u32 decision = KERNEL_MCP_DECISION_ALLOW;
	u32 wait_ms = 0;
	u32 tokens_left = 0;
	u32 key;
	bool hash_mismatch = false;

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

	if (requested_tool_hash) {
		mutex_lock(&kernel_mcp_tools_lock);
		tool = xa_load(&kernel_mcp_tools, tool_id);
		if (tool && tool->hash[0] != '\0' &&
		    strcmp(tool->hash, requested_tool_hash) != 0)
			hash_mismatch = true;
		mutex_unlock(&kernel_mcp_tools_lock);
	}

	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		decision = KERNEL_MCP_DECISION_DENY;
		wait_ms = 0;
		tokens_left = 0;
		reason = "deny_unknown_agent";
		mutex_unlock(&kernel_mcp_agents_lock);
		return kernel_mcp_reply_tool_decision(info, agent_id, tool_id, req_id,
						      decision, wait_ms,
						      tokens_left, reason);
	}

	if (hash_mismatch) {
		decision = KERNEL_MCP_DECISION_DENY;
		wait_ms = 0;
		tokens_left = 0;
		reason = "hash_mismatch";
		goto out_accounting;
	}

	if (tool_id == KERNEL_MCP_CPU_BURN_TOOL_ID) {
		spin_lock(&agent->bucket_lock);
		kernel_mcp_agent_bucket_refill(agent);
		if (agent->bucket_tokens > 0) {
			agent->bucket_tokens--;
			decision = KERNEL_MCP_DECISION_ALLOW;
			wait_ms = 0;
			reason = "allow_token";
		} else {
			decision = KERNEL_MCP_DECISION_DEFER;
			wait_ms = KERNEL_MCP_DEFER_WAIT_MS;
			reason = "defer_no_token";
		}
		tokens_left = agent->bucket_tokens;
		spin_unlock(&agent->bucket_lock);
	} else {
		decision = KERNEL_MCP_DECISION_ALLOW;
		wait_ms = 0;
		reason = "allow";
		tokens_left = 0;
	}

out_accounting:
	if (decision == KERNEL_MCP_DECISION_ALLOW)
		agent->allow_count++;
	else if (decision == KERNEL_MCP_DECISION_DENY)
		agent->deny_count++;
	else
		agent->defer_count++;
	strscpy(agent->last_reason, reason, sizeof(agent->last_reason));
	mutex_unlock(&kernel_mcp_agents_lock);

	return kernel_mcp_reply_tool_decision(info, agent_id, tool_id, req_id,
					      decision, wait_ms, tokens_left,
					      reason);
}

static int kernel_mcp_cmd_tool_complete(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_agent *agent;
	const char *agent_id;
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

	(void)req_id;
	(void)tool_id;
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
	mutex_unlock(&kernel_mcp_agents_lock);
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
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_TOOL_PERM, tool->perm);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_TOOL_COST, tool->cost);
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
		.cmd = KERNEL_MCP_CMD_PING,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.doit = kernel_mcp_cmd_ping,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.doit = kernel_mcp_cmd_tool_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_LIST_TOOLS,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.dumpit = kernel_mcp_cmd_list_tools_dump,
	},
	{
		.cmd = KERNEL_MCP_CMD_AGENT_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.doit = kernel_mcp_cmd_agent_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_REQUEST,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.doit = kernel_mcp_cmd_tool_request,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_COMPLETE,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
		.doit = kernel_mcp_cmd_tool_complete,
	},
};

static struct genl_family kernel_mcp_genl_family = {
	.name = KERNEL_MCP_GENL_FAMILY_NAME,
	.version = KERNEL_MCP_GENL_FAMILY_VERSION,
	.maxattr = KERNEL_MCP_ATTR_EXEC_MS,
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

	ret = kernel_mcp_sysfs_init();
	if (ret) {
		pr_err("kernel_mcp: sysfs init failed: %d\n", ret);
		return ret;
	}

	ret = genl_register_family(&kernel_mcp_genl_family);
	if (ret) {
		pr_err("kernel_mcp: genl_register_family failed: %d\n", ret);
		kernel_mcp_sysfs_exit();
		return ret;
	}

	pr_info("kernel_mcp: loaded (family=%s version=%u)\n",
		kernel_mcp_genl_family.name, kernel_mcp_genl_family.version);
	return 0;
}

static void __exit kernel_mcp_exit(void)
{
	int ret;

	ret = genl_unregister_family(&kernel_mcp_genl_family);
	if (ret)
		pr_err("kernel_mcp: genl_unregister_family failed: %d\n", ret);

	kernel_mcp_agents_destroy_all();
	kernel_mcp_tools_destroy_all();
	kernel_mcp_sysfs_exit();
	pr_info("kernel_mcp: unloaded\n");
}

module_init(kernel_mcp_init);
module_exit(kernel_mcp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linux-mcp");
MODULE_DESCRIPTION("Kernel MCP control-plane Generic Netlink (phase 3)");
MODULE_VERSION("0.3.0");
