#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/xarray.h>
#include <net/genetlink.h>

#include <linux/kernel_mcp_schema.h>

#define KERNEL_MCP_TOOL_NAME_MAX 128
#define KERNEL_MCP_TOOL_HASH_MAX 17
#define KERNEL_MCP_AGENT_ID_MAX 64
#define KERNEL_MCP_CONTEXT_ID_MAX 64
#define KERNEL_MCP_REASON_MAX 64

#define KERNEL_MCP_TOOL_STATUS_ACTIVE 1U

#define KERNEL_MCP_DECISION_ALLOW 1U
#define KERNEL_MCP_DECISION_DENY 2U
#define KERNEL_MCP_DECISION_DEFER 3U

#define KERNEL_MCP_COMPLETE_STATUS_OK 0U
#define KERNEL_MCP_COMPLETE_STATUS_ERR 1U

#define KERNEL_MCP_AGENT_HASH_BITS 8
#define KERNEL_MCP_REQUEST_HASH_BITS 8
#define KERNEL_MCP_HIGH_RISK_LEVEL 7U
#define KERNEL_MCP_HIGH_TRUST_THRESHOLD 7U
#define KERNEL_MCP_DEFAULT_DEFER_WAIT_MS 500U
#define KERNEL_MCP_REQUEST_TIMEOUT_JIFFIES (30 * HZ)
#define KERNEL_MCP_COMPLETED_RETENTION_JIFFIES (30 * HZ)
#define KERNEL_MCP_LEASE_TTL_JIFFIES (15 * HZ)
#define KERNEL_MCP_AGENT_FLAG_INTERACTIVE_APPROVED 0x1U
#define KERNEL_MCP_REQUEST_FLAG_INTERACTIVE_SESSION 0x1U
#define KERNEL_MCP_REQUEST_FLAG_EXPLICIT_APPROVED 0x2U
#define KERNEL_MCP_REQUEST_FLAG_LEGACY_PATH 0x4U

enum kernel_mcp_approval_mode {
	KERNEL_MCP_APPROVAL_MODE_AUTO = 0,
	KERNEL_MCP_APPROVAL_MODE_TRUSTED,
	KERNEL_MCP_APPROVAL_MODE_ROOT_ONLY,
	KERNEL_MCP_APPROVAL_MODE_INTERACTIVE,
	KERNEL_MCP_APPROVAL_MODE_EXPLICIT,
};

enum kernel_mcp_audit_mode {
	KERNEL_MCP_AUDIT_MODE_BASIC = 0,
	KERNEL_MCP_AUDIT_MODE_DETAILED,
	KERNEL_MCP_AUDIT_MODE_STRICT,
};

enum kernel_mcp_approval_state {
	KERNEL_MCP_APPROVAL_STATE_PENDING = 0,
	KERNEL_MCP_APPROVAL_STATE_AUTO_APPROVED,
	KERNEL_MCP_APPROVAL_STATE_APPROVED,
	KERNEL_MCP_APPROVAL_STATE_REJECTED,
};

/* New enum: centralized reason codes. */
enum kernel_mcp_reason_code {
	KERNEL_MCP_REASON_REGISTERED = 0,
	KERNEL_MCP_REASON_ALLOW,
	KERNEL_MCP_REASON_DENY_UNKNOWN_TOOL,
	KERNEL_MCP_REASON_DENY_UNKNOWN_AGENT,
	KERNEL_MCP_REASON_HASH_MISMATCH,
	KERNEL_MCP_REASON_DENY_UNAUTHORIZED,
	KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED,
	KERNEL_MCP_REASON_DENY_CONTEXT_REQUIRED,
	KERNEL_MCP_REASON_DENY_BROKER_IDENTITY,
	KERNEL_MCP_REASON_DEFER_RATE_LIMIT,
	KERNEL_MCP_REASON_DENY_DUPLICATE_REQUEST,
	KERNEL_MCP_REASON_INVALID_COMPLETE,
	KERNEL_MCP_REASON_DUPLICATE_COMPLETE,
	KERNEL_MCP_REASON_LEASE_EXPIRED,
	KERNEL_MCP_REASON_TIMEOUT,
};

/* New struct: per-tool configurable rate limit state. */
struct kernel_mcp_rate_limit {
	bool enabled;
	u32 burst;
	u32 refill_tokens;
	u32 refill_jiffies;
	u32 default_cost;
	u32 max_inflight_per_agent;
	u32 defer_wait_ms;
};

/* New struct: per-agent-per-tool rate limit/accounting state. */
struct kernel_mcp_agent_tool_state {
	u32 tool_id;
	u32 tokens;
	unsigned long last_refill;
	u32 inflight;
	struct list_head link;
};

struct kernel_mcp_tool {
	u32 id;
	/* Top-level kernel registry entry: stable capability domain. */
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 perm;
	u32 cost;
	u64 required_caps;
	u32 risk_level;
		u32 approval_mode;
		u32 audit_mode;
		u32 max_inflight_per_agent;
	struct kernel_mcp_rate_limit rl;
	u64 request_count;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u64 hash_mismatch_count;
	u64 rate_limit_hit_count;
	struct kobject *kobj;
};

struct kernel_mcp_tool_snapshot {
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 perm;
	u32 cost;
	u64 required_caps;
	u32 risk_level;
	u32 approval_mode;
	u32 audit_mode;
	u32 max_inflight_per_agent;
	u32 rl_enabled;
	u32 rl_burst;
	u32 rl_refill_tokens;
	u32 rl_refill_jiffies;
	u32 rl_default_cost;
	u32 rl_max_inflight_per_agent;
	u32 rl_defer_wait_ms;
	u64 request_count;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u64 hash_mismatch_count;
	u64 rate_limit_hit_count;
};

struct kernel_mcp_agent {
	char id[KERNEL_MCP_AGENT_ID_MAX];
	u32 pid;
	u32 uid;
	bool uid_set;
	u64 registration_epoch;
	u64 caps;
	u32 trust_level;
	u32 flags;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u64 authz_fail_count;
	u64 invalid_complete_count;
	u64 duplicate_complete_count;
	u64 timeout_count;
	u32 last_exec_ms;
	u32 last_status;
	char last_reason[KERNEL_MCP_REASON_MAX];
	struct list_head rl_states;
	struct hlist_node hnode;
	struct kobject *kobj;
};

struct kernel_mcp_agent_snapshot {
	u64 caps;
	u32 trust_level;
	u32 flags;
	u64 allow_count;
	u64 deny_count;
	u64 defer_count;
	u64 completed_ok_count;
	u64 completed_err_count;
	u64 authz_fail_count;
	u64 invalid_complete_count;
	u64 duplicate_complete_count;
	u64 timeout_count;
	u32 last_exec_ms;
	u32 last_status;
	char last_reason[KERNEL_MCP_REASON_MAX];
};

/* New struct: broker/provider/executor context carried with a lease. */
struct kernel_mcp_request_context {
	char broker_id[KERNEL_MCP_CONTEXT_ID_MAX];
	char provider_id[KERNEL_MCP_CONTEXT_ID_MAX];
	char executor_id[KERNEL_MCP_CONTEXT_ID_MAX];
	char provider_instance_id[KERNEL_MCP_CONTEXT_ID_MAX];
	char executor_instance_id[KERNEL_MCP_CONTEXT_ID_MAX];
	u64 lease_id;
	u32 request_flags;
	u32 approval_state;
};

/* New struct: inflight/completed request lifecycle record. */
struct kernel_mcp_request {
	u64 req_id;
	char agent_id[KERNEL_MCP_AGENT_ID_MAX];
	char capability_domain[KERNEL_MCP_TOOL_NAME_MAX];
	u32 tool_id;
	struct kernel_mcp_request_context ctx;
	u32 broker_pid;
	u32 broker_uid;
	bool broker_uid_set;
	u64 broker_epoch;
	unsigned long start_jiffies;
	unsigned long update_jiffies;
	unsigned long lease_expiry_jiffies;
	bool lease_consumed;
	bool completed;
	struct hlist_node hnode;
};

struct kernel_mcp_tool_view {
	char name[KERNEL_MCP_TOOL_NAME_MAX];
	char hash[KERNEL_MCP_TOOL_HASH_MAX];
	u32 cost;
	u64 required_caps;
	u32 risk_level;
	u32 approval_mode;
	u32 audit_mode;
	u32 max_inflight_per_agent;
	struct kernel_mcp_rate_limit rl;
};

struct kernel_mcp_decision_result {
	u32 decision;
	u32 wait_ms;
	u32 tokens_left;
	u32 lease_expires_ms;
	u32 approval_state;
	u64 lease_id;
	enum kernel_mcp_reason_code reason;
};

static DEFINE_XARRAY(kernel_mcp_tools);
static DEFINE_MUTEX(kernel_mcp_tools_lock);

static DEFINE_HASHTABLE(kernel_mcp_agents, KERNEL_MCP_AGENT_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_agents_lock);
static DEFINE_HASHTABLE(kernel_mcp_requests, KERNEL_MCP_REQUEST_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_requests_lock);
static atomic64_t kernel_mcp_broker_epoch_seq = ATOMIC64_INIT(1);
static atomic64_t kernel_mcp_lease_seq = ATOMIC64_INIT(1);
static atomic64_t kernel_mcp_audit_seq = ATOMIC64_INIT(1);

static struct kobject *kernel_mcp_sysfs_root;
static struct kobject *kernel_mcp_sysfs_tools;
static struct kobject *kernel_mcp_sysfs_agents;
static struct genl_family kernel_mcp_genl_family;

static const struct nla_policy kernel_mcp_policy[KERNEL_MCP_ATTR_APPROVAL_STATE + 1] = {
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
	[KERNEL_MCP_ATTR_TOOL_REQUIRED_CAPS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TOOL_RISK_LEVEL] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_AGENT_CAPS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_AGENT_TRUST_LEVEL] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_AGENT_FLAGS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_ENABLED] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_BURST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_REFILL_TOKENS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_REFILL_JIFFIES] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_DEFAULT_COST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_AGENT] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_DEFER_WAIT_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_BROKER_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_PROVIDER_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_EXECUTOR_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_LEASE_ID] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TOOL_APPROVAL_MODE] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_AUDIT_MODE] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOOL_MAX_INFLIGHT_PER_AGENT] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_LEASE_EXPIRES_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_BROKER_EPOCH] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_PROVIDER_INSTANCE_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_EXECUTOR_INSTANCE_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_REQUEST_FLAGS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_APPROVAL_TOKEN] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CONTEXT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_APPROVAL_STATE] = { .type = NLA_U32 },
};

/* New helper: centralized reason string mapping. */
static const char *
kernel_mcp_reason_str(enum kernel_mcp_reason_code code)
{
	switch (code) {
	case KERNEL_MCP_REASON_REGISTERED:
		return "registered";
	case KERNEL_MCP_REASON_ALLOW:
		return "allow";
	case KERNEL_MCP_REASON_DENY_UNKNOWN_TOOL:
		return "deny_unknown_tool";
	case KERNEL_MCP_REASON_DENY_UNKNOWN_AGENT:
		return "deny_unknown_agent";
	case KERNEL_MCP_REASON_HASH_MISMATCH:
		return "hash_mismatch";
	case KERNEL_MCP_REASON_DENY_UNAUTHORIZED:
		return "deny_unauthorized";
	case KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED:
		return "deny_approval_required";
	case KERNEL_MCP_REASON_DENY_CONTEXT_REQUIRED:
		return "deny_context_required";
	case KERNEL_MCP_REASON_DENY_BROKER_IDENTITY:
		return "deny_broker_identity";
	case KERNEL_MCP_REASON_DEFER_RATE_LIMIT:
		return "defer_rate_limit";
	case KERNEL_MCP_REASON_DENY_DUPLICATE_REQUEST:
		return "deny_duplicate_request";
	case KERNEL_MCP_REASON_INVALID_COMPLETE:
		return "invalid_complete";
	case KERNEL_MCP_REASON_DUPLICATE_COMPLETE:
		return "duplicate_complete";
	case KERNEL_MCP_REASON_LEASE_EXPIRED:
		return "lease_expired";
	case KERNEL_MCP_REASON_TIMEOUT:
		return "timeout";
	default:
		return "unknown";
	}
}

static const char *
kernel_mcp_approval_state_str(u32 approval_state)
{
	switch (approval_state) {
	case KERNEL_MCP_APPROVAL_STATE_AUTO_APPROVED:
		return "auto_approved";
	case KERNEL_MCP_APPROVAL_STATE_APPROVED:
		return "approved";
	case KERNEL_MCP_APPROVAL_STATE_REJECTED:
		return "rejected";
	case KERNEL_MCP_APPROVAL_STATE_PENDING:
	default:
		return "pending";
	}
}

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

static struct kernel_mcp_agent_tool_state *
kernel_mcp_find_agent_tool_state_locked(struct kernel_mcp_agent *agent,
					u32 tool_id)
{
	struct kernel_mcp_agent_tool_state *state;

	list_for_each_entry(state, &agent->rl_states, link) {
		if (state->tool_id == tool_id)
			return state;
	}
	return NULL;
}

static struct kernel_mcp_agent_tool_state *
kernel_mcp_get_agent_tool_state_locked(struct kernel_mcp_agent *agent,
				       u32 tool_id)
{
	struct kernel_mcp_agent_tool_state *state;

	state = kernel_mcp_find_agent_tool_state_locked(agent, tool_id);
	if (state)
		return state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	state->tool_id = tool_id;
	list_add_tail(&state->link, &agent->rl_states);
	return state;
}

static u32 kernel_mcp_request_hash_key(u64 req_id, const char *agent_id,
				       u32 tool_id)
{
	u32 parts[2];

	parts[0] = lower_32_bits(req_id) ^ tool_id;
	parts[1] = upper_32_bits(req_id) ^ kernel_mcp_agent_hash_key(agent_id);
	return jhash2(parts, ARRAY_SIZE(parts), 0);
}

static struct kernel_mcp_request *
kernel_mcp_find_request_locked(u64 req_id, const char *agent_id, u32 tool_id)
{
	struct kernel_mcp_request *request;
	u32 key;

	key = kernel_mcp_request_hash_key(req_id, agent_id, tool_id);
	hash_for_each_possible(kernel_mcp_requests, request, hnode, key) {
		if (request->req_id == req_id && request->tool_id == tool_id &&
		    strcmp(request->agent_id, agent_id) == 0)
			return request;
	}
	return NULL;
}

static void
kernel_mcp_copy_request_context(struct kernel_mcp_request_context *out,
				const char *broker_id,
				const char *provider_id,
				const char *executor_id,
				const char *provider_instance_id,
				const char *executor_instance_id,
				u64 lease_id, u32 request_flags,
				u32 approval_state)
{
	memset(out, 0, sizeof(*out));
	if (broker_id)
		strscpy(out->broker_id, broker_id, sizeof(out->broker_id));
	if (provider_id)
			strscpy(out->provider_id, provider_id, sizeof(out->provider_id));
	if (executor_id)
		strscpy(out->executor_id, executor_id, sizeof(out->executor_id));
	if (provider_instance_id)
		strscpy(out->provider_instance_id, provider_instance_id,
			sizeof(out->provider_instance_id));
	if (executor_instance_id)
		strscpy(out->executor_instance_id, executor_instance_id,
			sizeof(out->executor_instance_id));
	out->lease_id = lease_id;
	out->request_flags = request_flags;
	out->approval_state = approval_state;
}

static bool
kernel_mcp_request_context_matches(const struct kernel_mcp_request *request,
				   const char *broker_id,
				   const char *provider_id,
				   const char *executor_id,
				   const char *provider_instance_id,
				   const char *executor_instance_id,
				   u64 lease_id, u32 approval_state)
{
	if (request->ctx.broker_id[0] != '\0') {
		if (!broker_id || strcmp(request->ctx.broker_id, broker_id) != 0)
			return false;
	}
	if (request->ctx.provider_id[0] != '\0') {
		if (!provider_id ||
		    strcmp(request->ctx.provider_id, provider_id) != 0)
			return false;
	}
	if (request->ctx.executor_id[0] != '\0') {
		if (!executor_id ||
		    strcmp(request->ctx.executor_id, executor_id) != 0)
			return false;
	}
	if (request->ctx.provider_instance_id[0] != '\0') {
		if (!provider_instance_id ||
		    strcmp(request->ctx.provider_instance_id,
			   provider_instance_id) != 0)
			return false;
	}
	if (request->ctx.executor_instance_id[0] != '\0') {
		if (!executor_instance_id ||
		    strcmp(request->ctx.executor_instance_id,
			   executor_instance_id) != 0)
			return false;
	}
	if (request->ctx.lease_id != 0 && request->ctx.lease_id != lease_id)
		return false;
	if (request->ctx.approval_state != approval_state)
		return false;
	return true;
}

static void
kernel_mcp_copy_tool_view_locked(const struct kernel_mcp_tool *tool,
				 struct kernel_mcp_tool_view *out)
{
	memset(out, 0, sizeof(*out));
	strscpy(out->name, tool->name, sizeof(out->name));
	strscpy(out->hash, tool->hash, sizeof(out->hash));
	out->cost = tool->cost;
	out->required_caps = tool->required_caps;
	out->risk_level = tool->risk_level;
	out->approval_mode = tool->approval_mode;
	out->audit_mode = tool->audit_mode;
	out->max_inflight_per_agent = tool->max_inflight_per_agent;
	out->rl = tool->rl;
}

static u64 kernel_mcp_expiry_time_ms(unsigned long expiry_jiffies)
{
	u64 now_ms = div_u64(ktime_get_real_ns(), 1000000ULL);

	if (expiry_jiffies == 0)
		return 0;
	if (time_after_eq(jiffies, expiry_jiffies))
		return now_ms;
	return now_ms + jiffies_to_msecs(expiry_jiffies - jiffies);
}

static void
kernel_mcp_audit_event(const char *event_type, const char *capability_domain,
		       const char *planner_agent_id,
		       const struct kernel_mcp_request_context *ctx, u64 req_id,
		       u32 broker_pid, u64 broker_epoch, u64 lease_id,
		       u32 approval_mode, u32 approval_state,
		       enum kernel_mcp_reason_code reason,
		       unsigned long expiry_jiffies)
{
	u64 seq = (u64)atomic64_inc_return(&kernel_mcp_audit_seq);

	pr_info("kernel_mcp_audit {\"seq\":%llu,\"event\":\"%s\",\"req_id\":%llu,\"capability_domain\":\"%s\",\"planner_agent_id\":\"%s\",\"broker_id\":\"%s\",\"broker_pid\":%u,\"broker_epoch\":%llu,\"provider_id\":\"%s\",\"provider_instance_id\":\"%s\",\"executor_id\":\"%s\",\"executor_instance_id\":\"%s\",\"lease_id\":%llu,\"approval_mode\":%u,\"approval_state\":\"%s\",\"decision_reason\":\"%s\",\"expiry_time_ms\":%llu,\"legacy_path_flag\":%u}\n",
		seq, event_type, req_id,
		capability_domain ? capability_domain : "",
		planner_agent_id ? planner_agent_id : "",
		ctx ? ctx->broker_id : "", broker_pid, broker_epoch,
		ctx ? ctx->provider_id : "",
		ctx ? ctx->provider_instance_id : "",
		ctx ? ctx->executor_id : "",
		ctx ? ctx->executor_instance_id : "", lease_id, approval_mode,
		kernel_mcp_approval_state_str(approval_state),
		kernel_mcp_reason_str(reason),
		kernel_mcp_expiry_time_ms(expiry_jiffies),
		(ctx && (ctx->request_flags & KERNEL_MCP_REQUEST_FLAG_LEGACY_PATH)) ? 1U :
										    0U);
}

static void kernel_mcp_copy_tool_snapshot_locked(const struct kernel_mcp_tool *tool,
						 struct kernel_mcp_tool_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	strscpy(out->name, tool->name, sizeof(out->name));
	strscpy(out->hash, tool->hash, sizeof(out->hash));
	out->perm = tool->perm;
	out->cost = tool->cost;
	out->required_caps = tool->required_caps;
	out->risk_level = tool->risk_level;
	out->approval_mode = tool->approval_mode;
	out->audit_mode = tool->audit_mode;
	out->max_inflight_per_agent = tool->max_inflight_per_agent;
	out->rl_enabled = tool->rl.enabled ? 1U : 0U;
	out->rl_burst = tool->rl.burst;
	out->rl_refill_tokens = tool->rl.refill_tokens;
	out->rl_refill_jiffies = tool->rl.refill_jiffies;
	out->rl_default_cost = tool->rl.default_cost;
	out->rl_max_inflight_per_agent = tool->rl.max_inflight_per_agent;
	out->rl_defer_wait_ms = tool->rl.defer_wait_ms;
	out->request_count = tool->request_count;
	out->allow_count = tool->allow_count;
	out->deny_count = tool->deny_count;
	out->defer_count = tool->defer_count;
	out->completed_ok_count = tool->completed_ok_count;
	out->completed_err_count = tool->completed_err_count;
	out->hash_mismatch_count = tool->hash_mismatch_count;
	out->rate_limit_hit_count = tool->rate_limit_hit_count;
}

static void
kernel_mcp_copy_agent_snapshot_locked(const struct kernel_mcp_agent *agent,
				      struct kernel_mcp_agent_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	out->caps = agent->caps;
	out->trust_level = agent->trust_level;
	out->flags = agent->flags;
	out->allow_count = agent->allow_count;
	out->deny_count = agent->deny_count;
	out->defer_count = agent->defer_count;
	out->completed_ok_count = agent->completed_ok_count;
	out->completed_err_count = agent->completed_err_count;
	out->authz_fail_count = agent->authz_fail_count;
	out->invalid_complete_count = agent->invalid_complete_count;
	out->duplicate_complete_count = agent->duplicate_complete_count;
	out->timeout_count = agent->timeout_count;
	out->last_exec_ms = agent->last_exec_ms;
	out->last_status = agent->last_status;
	strscpy(out->last_reason, agent->last_reason, sizeof(out->last_reason));
}

static u32 kernel_mcp_default_approval_mode(u32 risk_level)
{
	if (risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL)
		return KERNEL_MCP_APPROVAL_MODE_TRUSTED;
	return KERNEL_MCP_APPROVAL_MODE_AUTO;
}

static u32 kernel_mcp_default_audit_mode(u32 risk_level)
{
	if (risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL)
		return KERNEL_MCP_AUDIT_MODE_DETAILED;
	return KERNEL_MCP_AUDIT_MODE_BASIC;
}

static u32
kernel_mcp_effective_max_inflight(const struct kernel_mcp_tool_view *tool)
{
	if (tool->max_inflight_per_agent != 0)
		return tool->max_inflight_per_agent;
	return tool->rl.max_inflight_per_agent;
}

static u64 kernel_mcp_issue_lease_id(u64 req_id, u32 tool_id)
{
	u64 seq = (u64)atomic64_inc_return(&kernel_mcp_lease_seq);

	return (seq << 24) ^ ((req_id & 0xFFFFFFFFULL) << 8) ^
		(u64)(tool_id & 0xFFU);
}

static void
kernel_mcp_tool_account_decision(u32 tool_id,
				 const struct kernel_mcp_decision_result *result)
{
	struct kernel_mcp_tool *tool;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (tool) {
		tool->request_count++;
		if (result->decision == KERNEL_MCP_DECISION_ALLOW)
			tool->allow_count++;
		else if (result->decision == KERNEL_MCP_DECISION_DENY)
			tool->deny_count++;
		else
			tool->defer_count++;
		if (result->reason == KERNEL_MCP_REASON_HASH_MISMATCH)
			tool->hash_mismatch_count++;
		if (result->reason == KERNEL_MCP_REASON_DEFER_RATE_LIMIT)
			tool->rate_limit_hit_count++;
	}
	mutex_unlock(&kernel_mcp_tools_lock);
}

static void kernel_mcp_request_free(struct kernel_mcp_request *request)
{
	kfree(request);
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
	kernel_mcp_copy_tool_snapshot_locked(tool, out);
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
	kernel_mcp_copy_agent_snapshot_locked(agent, out);
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

static ssize_t kernel_mcp_tool_required_caps_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.required_caps);
}

static ssize_t kernel_mcp_tool_risk_level_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.risk_level);
}

static ssize_t kernel_mcp_tool_approval_mode_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.approval_mode);
}

static ssize_t kernel_mcp_tool_audit_mode_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.audit_mode);
}

static ssize_t
kernel_mcp_tool_max_inflight_per_agent_show(struct kobject *kobj,
					    struct kobj_attribute *attr,
					    char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.max_inflight_per_agent);
}

static ssize_t kernel_mcp_tool_request_count_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.request_count);
}

static ssize_t kernel_mcp_tool_allow_count_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.allow_count);
}

static ssize_t kernel_mcp_tool_deny_count_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.deny_count);
}

static ssize_t kernel_mcp_tool_defer_count_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.defer_count);
}

static ssize_t kernel_mcp_tool_completed_ok_count_show(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_ok_count);
}

static ssize_t kernel_mcp_tool_completed_err_count_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_err_count);
}

static ssize_t kernel_mcp_tool_hash_mismatch_count_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.hash_mismatch_count);
}

static ssize_t kernel_mcp_tool_rate_limit_hit_count_show(struct kobject *kobj,
							 struct kobj_attribute *attr,
							 char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.rate_limit_hit_count);
}

static ssize_t kernel_mcp_tool_rl_enabled_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_enabled);
}

static ssize_t kernel_mcp_tool_rl_burst_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_burst);
}

static ssize_t kernel_mcp_tool_rl_refill_tokens_show(struct kobject *kobj,
						     struct kobj_attribute *attr,
						     char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_refill_tokens);
}

static ssize_t kernel_mcp_tool_rl_refill_jiffies_show(struct kobject *kobj,
						      struct kobj_attribute *attr,
						      char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_refill_jiffies);
}

static ssize_t kernel_mcp_tool_rl_default_cost_show(struct kobject *kobj,
						    struct kobj_attribute *attr,
						    char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_default_cost);
}

static ssize_t
kernel_mcp_tool_rl_max_inflight_per_agent_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_max_inflight_per_agent);
}

static ssize_t kernel_mcp_tool_rl_defer_wait_ms_show(struct kobject *kobj,
						     struct kobj_attribute *attr,
						     char *buf)
{
	struct kernel_mcp_tool_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_tool_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_defer_wait_ms);
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

static ssize_t kernel_mcp_agent_caps_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.caps);
}

static ssize_t kernel_mcp_agent_trust_level_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.trust_level);
}

static ssize_t kernel_mcp_agent_flags_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.flags);
}

static ssize_t kernel_mcp_agent_authz_fail_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.authz_fail_count);
}

static ssize_t kernel_mcp_agent_invalid_complete_show(struct kobject *kobj,
						      struct kobj_attribute *attr,
						      char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.invalid_complete_count);
}

static ssize_t kernel_mcp_agent_duplicate_complete_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.duplicate_complete_count);
}

static ssize_t kernel_mcp_agent_timeout_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	struct kernel_mcp_agent_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_agent_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.timeout_count);
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
static struct kobj_attribute kernel_mcp_tool_required_caps_attr =
	__ATTR(required_caps, 0444, kernel_mcp_tool_required_caps_show, NULL);
static struct kobj_attribute kernel_mcp_tool_risk_level_attr =
	__ATTR(risk_level, 0444, kernel_mcp_tool_risk_level_show, NULL);
static struct kobj_attribute kernel_mcp_tool_approval_mode_attr =
	__ATTR(approval_mode, 0444, kernel_mcp_tool_approval_mode_show, NULL);
static struct kobj_attribute kernel_mcp_tool_audit_mode_attr =
	__ATTR(audit_mode, 0444, kernel_mcp_tool_audit_mode_show, NULL);
static struct kobj_attribute kernel_mcp_tool_max_inflight_per_agent_attr =
	__ATTR(max_inflight_per_agent, 0444,
	       kernel_mcp_tool_max_inflight_per_agent_show, NULL);
static struct kobj_attribute kernel_mcp_tool_request_count_attr =
	__ATTR(request_count, 0444, kernel_mcp_tool_request_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_allow_count_attr =
	__ATTR(allow_count, 0444, kernel_mcp_tool_allow_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_deny_count_attr =
	__ATTR(deny_count, 0444, kernel_mcp_tool_deny_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_defer_count_attr =
	__ATTR(defer_count, 0444, kernel_mcp_tool_defer_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_completed_ok_count_attr =
	__ATTR(completed_ok_count, 0444,
	       kernel_mcp_tool_completed_ok_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_completed_err_count_attr =
	__ATTR(completed_err_count, 0444,
	       kernel_mcp_tool_completed_err_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_hash_mismatch_count_attr =
	__ATTR(hash_mismatch_count, 0444,
	       kernel_mcp_tool_hash_mismatch_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rate_limit_hit_count_attr =
	__ATTR(rate_limit_hit_count, 0444,
	       kernel_mcp_tool_rate_limit_hit_count_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_enabled_attr =
	__ATTR(rl_enabled, 0444, kernel_mcp_tool_rl_enabled_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_burst_attr =
	__ATTR(rl_burst, 0444, kernel_mcp_tool_rl_burst_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_refill_tokens_attr =
	__ATTR(rl_refill_tokens, 0444,
	       kernel_mcp_tool_rl_refill_tokens_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_refill_jiffies_attr =
	__ATTR(rl_refill_jiffies, 0444,
	       kernel_mcp_tool_rl_refill_jiffies_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_default_cost_attr =
	__ATTR(rl_default_cost, 0444,
	       kernel_mcp_tool_rl_default_cost_show, NULL);
static struct kobj_attribute
kernel_mcp_tool_rl_max_inflight_per_agent_attr =
	__ATTR(rl_max_inflight_per_agent, 0444,
	       kernel_mcp_tool_rl_max_inflight_per_agent_show, NULL);
static struct kobj_attribute kernel_mcp_tool_rl_defer_wait_ms_attr =
	__ATTR(rl_defer_wait_ms, 0444,
	       kernel_mcp_tool_rl_defer_wait_ms_show, NULL);

static struct attribute *kernel_mcp_tool_attrs[] = {
	&kernel_mcp_name_attr.attr,
	&kernel_mcp_perm_attr.attr,
	&kernel_mcp_hash_attr.attr,
	&kernel_mcp_cost_attr.attr,
	&kernel_mcp_tool_status_attr.attr,
	&kernel_mcp_tool_required_caps_attr.attr,
	&kernel_mcp_tool_risk_level_attr.attr,
	&kernel_mcp_tool_approval_mode_attr.attr,
	&kernel_mcp_tool_audit_mode_attr.attr,
	&kernel_mcp_tool_max_inflight_per_agent_attr.attr,
	&kernel_mcp_tool_request_count_attr.attr,
	&kernel_mcp_tool_allow_count_attr.attr,
	&kernel_mcp_tool_deny_count_attr.attr,
	&kernel_mcp_tool_defer_count_attr.attr,
	&kernel_mcp_tool_completed_ok_count_attr.attr,
	&kernel_mcp_tool_completed_err_count_attr.attr,
	&kernel_mcp_tool_hash_mismatch_count_attr.attr,
	&kernel_mcp_tool_rate_limit_hit_count_attr.attr,
	&kernel_mcp_tool_rl_enabled_attr.attr,
	&kernel_mcp_tool_rl_burst_attr.attr,
	&kernel_mcp_tool_rl_refill_tokens_attr.attr,
	&kernel_mcp_tool_rl_refill_jiffies_attr.attr,
	&kernel_mcp_tool_rl_default_cost_attr.attr,
	&kernel_mcp_tool_rl_max_inflight_per_agent_attr.attr,
	&kernel_mcp_tool_rl_defer_wait_ms_attr.attr,
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
static struct kobj_attribute kernel_mcp_agent_caps_attr =
	__ATTR(caps, 0444, kernel_mcp_agent_caps_show, NULL);
static struct kobj_attribute kernel_mcp_agent_trust_level_attr =
	__ATTR(trust_level, 0444, kernel_mcp_agent_trust_level_show, NULL);
static struct kobj_attribute kernel_mcp_agent_flags_attr =
	__ATTR(flags, 0444, kernel_mcp_agent_flags_show, NULL);
static struct kobj_attribute kernel_mcp_agent_authz_fail_attr =
	__ATTR(authz_fail, 0444, kernel_mcp_agent_authz_fail_show, NULL);
static struct kobj_attribute kernel_mcp_agent_invalid_complete_attr =
	__ATTR(invalid_complete, 0444,
	       kernel_mcp_agent_invalid_complete_show, NULL);
static struct kobj_attribute kernel_mcp_agent_duplicate_complete_attr =
	__ATTR(duplicate_complete, 0444,
	       kernel_mcp_agent_duplicate_complete_show, NULL);
static struct kobj_attribute kernel_mcp_agent_timeout_attr =
	__ATTR(timeout, 0444, kernel_mcp_agent_timeout_show, NULL);

static struct attribute *kernel_mcp_agent_attrs[] = {
	&kernel_mcp_agent_caps_attr.attr,
	&kernel_mcp_agent_trust_level_attr.attr,
	&kernel_mcp_agent_flags_attr.attr,
	&kernel_mcp_agent_allow_attr.attr,
	&kernel_mcp_agent_deny_attr.attr,
	&kernel_mcp_agent_defer_attr.attr,
	&kernel_mcp_agent_last_reason_attr.attr,
	&kernel_mcp_agent_completed_ok_attr.attr,
	&kernel_mcp_agent_completed_err_attr.attr,
	&kernel_mcp_agent_authz_fail_attr.attr,
	&kernel_mcp_agent_invalid_complete_attr.attr,
	&kernel_mcp_agent_duplicate_complete_attr.attr,
	&kernel_mcp_agent_timeout_attr.attr,
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
				    u32 cost, const char *hash,
				    u64 required_caps, u32 risk_level,
				    u32 approval_mode, u32 audit_mode,
				    u32 max_inflight_per_agent,
				    const struct kernel_mcp_rate_limit *rl)
{
	struct kernel_mcp_tool *tool;
	struct kernel_mcp_rate_limit rl_cfg = { 0 };
	int ret;

	if (rl)
		rl_cfg = *rl;
	if (approval_mode == KERNEL_MCP_APPROVAL_MODE_AUTO &&
	    risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL)
		approval_mode = kernel_mcp_default_approval_mode(risk_level);
	if (audit_mode == KERNEL_MCP_AUDIT_MODE_BASIC &&
	    risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL)
		audit_mode = kernel_mcp_default_audit_mode(risk_level);
	if (max_inflight_per_agent == 0)
		max_inflight_per_agent = rl_cfg.max_inflight_per_agent;
	if (rl_cfg.enabled) {
		if (rl_cfg.burst == 0)
			rl_cfg.burst = 1;
		if (rl_cfg.refill_tokens == 0)
			rl_cfg.refill_tokens = 1;
		if (rl_cfg.refill_jiffies == 0)
			rl_cfg.refill_jiffies = HZ;
		if (rl_cfg.defer_wait_ms == 0)
			rl_cfg.defer_wait_ms = KERNEL_MCP_DEFAULT_DEFER_WAIT_MS;
	}

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (tool) {
		strscpy(tool->name, name, sizeof(tool->name));
		if (hash)
			strscpy(tool->hash, hash, sizeof(tool->hash));
		tool->perm = perm;
		tool->cost = cost;
		tool->required_caps = required_caps;
		tool->risk_level = risk_level;
		tool->approval_mode = approval_mode;
		tool->audit_mode = audit_mode;
		tool->max_inflight_per_agent = max_inflight_per_agent;
		tool->rl = rl_cfg;
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
	tool->required_caps = required_caps;
	tool->risk_level = risk_level;
	tool->approval_mode = approval_mode;
	tool->audit_mode = audit_mode;
	tool->max_inflight_per_agent = max_inflight_per_agent;
	strscpy(tool->name, name, sizeof(tool->name));
	if (hash)
		strscpy(tool->hash, hash, sizeof(tool->hash));
	tool->rl = rl_cfg;

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
	struct kernel_mcp_agent_tool_state *state;
	struct kernel_mcp_agent_tool_state *tmp;

	if (!agent)
		return;
	list_for_each_entry_safe(state, tmp, &agent->rl_states, link) {
		list_del(&state->link);
		kfree(state);
	}
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
				     u32 uid, u64 caps, u32 trust_level,
				     u32 flags)
{
	struct kernel_mcp_agent *agent;
	u32 key;
	int ret;

	key = kernel_mcp_agent_hash_key(agent_id);
	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (agent) {
		agent->registration_epoch =
			(u64)atomic64_inc_return(&kernel_mcp_broker_epoch_seq);
		agent->pid = pid;
		agent->uid_set = uid_set;
		if (uid_set)
			agent->uid = uid;
		agent->caps = caps;
		agent->trust_level = trust_level;
		agent->flags = flags;
		mutex_unlock(&kernel_mcp_agents_lock);
		return 0;
	}

	agent = kzalloc(sizeof(*agent), GFP_KERNEL);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOMEM;
	}

	strscpy(agent->id, agent_id, sizeof(agent->id));
	agent->registration_epoch =
		(u64)atomic64_inc_return(&kernel_mcp_broker_epoch_seq);
	agent->pid = pid;
	agent->uid = uid;
	agent->uid_set = uid_set;
	agent->caps = caps;
	agent->trust_level = trust_level;
	agent->flags = flags;
	INIT_LIST_HEAD(&agent->rl_states);
	strscpy(agent->last_reason,
		kernel_mcp_reason_str(KERNEL_MCP_REASON_REGISTERED),
		sizeof(agent->last_reason));

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

/* New helper: capability/trust based authorization. */
static bool
kernel_mcp_authorize(const struct kernel_mcp_agent *agent,
		     const struct kernel_mcp_tool_view *tool,
		     u32 request_flags, const char *approval_token,
		     u32 *approval_state,
		     enum kernel_mcp_reason_code *reason)
{
	if (approval_state)
		*approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
	if ((agent->caps & tool->required_caps) != tool->required_caps) {
		*reason = KERNEL_MCP_REASON_DENY_UNAUTHORIZED;
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		return false;
	}

	switch (tool->approval_mode) {
	case KERNEL_MCP_APPROVAL_MODE_ROOT_ONLY:
		if (!agent->uid_set || agent->uid != 0) {
			*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
			if (approval_state)
				*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
			return false;
		}
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_APPROVED;
		break;
	case KERNEL_MCP_APPROVAL_MODE_INTERACTIVE:
		if ((request_flags & KERNEL_MCP_REQUEST_FLAG_INTERACTIVE_SESSION) == 0 &&
		    (agent->flags & KERNEL_MCP_AGENT_FLAG_INTERACTIVE_APPROVED) == 0 &&
		    (!agent->uid_set || agent->uid != 0)) {
			*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
			if (approval_state)
				*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
			return false;
		}
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_APPROVED;
		break;
	case KERNEL_MCP_APPROVAL_MODE_EXPLICIT:
		if ((request_flags & KERNEL_MCP_REQUEST_FLAG_EXPLICIT_APPROVED) == 0 &&
		    (!approval_token || approval_token[0] == '\0') &&
		    (!agent->uid_set || agent->uid != 0)) {
			*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
			if (approval_state)
				*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
			return false;
		}
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_APPROVED;
		break;
	case KERNEL_MCP_APPROVAL_MODE_TRUSTED:
		if ((!agent->uid_set || agent->uid != 0) &&
		    agent->trust_level < KERNEL_MCP_HIGH_TRUST_THRESHOLD) {
			*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
			if (approval_state)
				*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
			return false;
		}
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_APPROVED;
		break;
	default:
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_AUTO_APPROVED;
		break;
	}

	if (tool->risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL &&
	    (!agent->uid_set || agent->uid != 0) &&
	    agent->trust_level < KERNEL_MCP_HIGH_TRUST_THRESHOLD) {
		*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		return false;
	}

	return true;
}

static bool
kernel_mcp_validate_request_context_locked(const char *agent_id,
					   const struct kernel_mcp_tool_view *tool,
					   const char *broker_id,
					   const char *provider_id,
					   const char *executor_id,
					   const char *provider_instance_id,
					   const char *executor_instance_id,
					   u32 request_flags,
					   struct kernel_mcp_agent **broker_agent_out,
					   enum kernel_mcp_reason_code *reason)
{
	struct kernel_mcp_agent *broker_agent;
	u32 broker_key;
	bool broker_required;

	(void)provider_instance_id;
	if (broker_agent_out)
		*broker_agent_out = NULL;
	broker_required = tool->risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL ||
		tool->approval_mode != KERNEL_MCP_APPROVAL_MODE_AUTO;
	if (broker_required) {
		if (!broker_id || broker_id[0] == '\0' ||
		    !provider_id || provider_id[0] == '\0' ||
		    !executor_id || executor_id[0] == '\0' ||
		    !executor_instance_id || executor_instance_id[0] == '\0') {
			*reason = KERNEL_MCP_REASON_DENY_CONTEXT_REQUIRED;
			return false;
		}
		if (strcmp(agent_id, broker_id) == 0) {
			*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
			return false;
		}
	}
	if ((request_flags & KERNEL_MCP_REQUEST_FLAG_LEGACY_PATH) != 0 &&
	    tool->risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL)
		pr_warn("kernel_mcp legacy-path request for high-risk capability=%s\n",
			tool->name);

	if (!broker_id || broker_id[0] == '\0')
		return true;

	broker_key = kernel_mcp_agent_hash_key(broker_id);
	broker_agent = kernel_mcp_find_agent_locked(broker_id, broker_key);
	if (!broker_agent) {
		*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
		return false;
	}

	if (!kernel_mcp_authorize(broker_agent, tool, request_flags,
				  NULL, NULL, reason)) {
		*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
		return false;
	}
	if (broker_agent_out)
		*broker_agent_out = broker_agent;

	return true;
}

static void
kernel_mcp_rate_limit_refill_locked(struct kernel_mcp_agent_tool_state *state,
				    const struct kernel_mcp_rate_limit *rl)
{
	unsigned long delta;
	unsigned long refill_units;
	u32 tokens;

	if (!rl->enabled || rl->refill_jiffies == 0 || rl->refill_tokens == 0)
		return;

	if (state->last_refill == 0) {
		state->last_refill = jiffies;
		if (state->tokens == 0)
			state->tokens = rl->burst;
		return;
	}

	delta = jiffies - state->last_refill;
	refill_units = delta / rl->refill_jiffies;
	if (refill_units == 0)
		return;

	tokens = state->tokens + (u32)refill_units * rl->refill_tokens;
	if (tokens > rl->burst)
		tokens = rl->burst;
	state->tokens = tokens;
	state->last_refill += refill_units * rl->refill_jiffies;
}

static u32
kernel_mcp_rate_limit_cost(const struct kernel_mcp_tool_view *tool)
{
	if (tool->rl.default_cost != 0)
		return tool->rl.default_cost;
	return max(tool->cost, 1U);
}

static int
kernel_mcp_insert_request_locked(u64 req_id, const char *agent_id,
				 const char *capability_domain, u32 tool_id,
				 const char *broker_id,
				 const char *provider_id,
				 const char *executor_id,
				 const char *provider_instance_id,
				 const char *executor_instance_id,
				 const struct kernel_mcp_agent *broker_agent,
				 u64 lease_id, u32 request_flags,
				 u32 approval_state,
				 unsigned long lease_expiry_jiffies)
{
	struct kernel_mcp_request *request;
	u32 key;

	if (kernel_mcp_find_request_locked(req_id, agent_id, tool_id))
		return -EEXIST;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;

	request->req_id = req_id;
	request->tool_id = tool_id;
	request->start_jiffies = jiffies;
	request->update_jiffies = request->start_jiffies;
	request->lease_expiry_jiffies = lease_expiry_jiffies;
	strscpy(request->agent_id, agent_id, sizeof(request->agent_id));
	strscpy(request->capability_domain, capability_domain,
		sizeof(request->capability_domain));
	kernel_mcp_copy_request_context(&request->ctx, broker_id, provider_id,
					executor_id, provider_instance_id,
					executor_instance_id, lease_id,
					request_flags, approval_state);
	if (broker_agent) {
		request->broker_pid = broker_agent->pid;
		request->broker_uid = broker_agent->uid;
		request->broker_uid_set = broker_agent->uid_set;
		request->broker_epoch = broker_agent->registration_epoch;
	}

	key = kernel_mcp_request_hash_key(req_id, agent_id, tool_id);
	hash_add(kernel_mcp_requests, &request->hnode, key);
	return 0;
}

static void
kernel_mcp_request_remove_locked(struct kernel_mcp_request *request)
{
	hash_del(&request->hnode);
	kernel_mcp_request_free(request);
}

static void kernel_mcp_requests_destroy_all(void)
{
	struct kernel_mcp_request *request;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_requests_lock);
	hash_for_each_safe(kernel_mcp_requests, bkt, tmp, request, hnode) {
		hash_del(&request->hnode);
		kernel_mcp_request_free(request);
	}
	mutex_unlock(&kernel_mcp_requests_lock);
}

static void kernel_mcp_requests_gc(void)
{
	struct kernel_mcp_request *request;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_agents_lock);
	mutex_lock(&kernel_mcp_requests_lock);
	hash_for_each_safe(kernel_mcp_requests, bkt, tmp, request, hnode) {
		struct kernel_mcp_agent *agent;
		struct kernel_mcp_agent_tool_state *state;
		unsigned long age;
		bool expired = false;
		bool lease_expired = false;
		u32 key;

		age = jiffies - request->update_jiffies;
		if (!request->completed && age >= KERNEL_MCP_REQUEST_TIMEOUT_JIFFIES)
			expired = true;
		if (!request->completed &&
		    time_after_eq(jiffies, request->lease_expiry_jiffies)) {
			expired = true;
			lease_expired = true;
		}
		if (request->completed &&
		    age >= KERNEL_MCP_COMPLETED_RETENTION_JIFFIES)
			expired = true;
		if (!expired)
			continue;

		key = kernel_mcp_agent_hash_key(request->agent_id);
		agent = kernel_mcp_find_agent_locked(request->agent_id, key);
		if (agent) {
			state = kernel_mcp_find_agent_tool_state_locked(agent,
							request->tool_id);
			if (!request->completed) {
				if (state && state->inflight > 0)
					state->inflight--;
				agent->timeout_count++;
				strscpy(agent->last_reason,
					kernel_mcp_reason_str(lease_expired ?
						KERNEL_MCP_REASON_LEASE_EXPIRED :
						KERNEL_MCP_REASON_TIMEOUT),
					sizeof(agent->last_reason));
				kernel_mcp_audit_event(lease_expired ?
						      "lease_expired" :
						      "request_timeout",
						      request->capability_domain,
						      request->agent_id,
						      &request->ctx,
						      request->req_id,
						      request->broker_pid,
						      request->broker_epoch,
						      request->ctx.lease_id,
						      0,
						      request->ctx.approval_state,
						      lease_expired ?
						      KERNEL_MCP_REASON_LEASE_EXPIRED :
						      KERNEL_MCP_REASON_TIMEOUT,
						      request->lease_expiry_jiffies);
			}
		}

		kernel_mcp_request_remove_locked(request);
	}
	mutex_unlock(&kernel_mcp_requests_lock);
	mutex_unlock(&kernel_mcp_agents_lock);
}

/* New helper: centralized request decision flow. */
static int
kernel_mcp_decide_request(const char *agent_id, u32 tool_id, u64 req_id,
			  const char *requested_tool_hash,
			  const char *broker_id,
			  const char *provider_id,
			  const char *provider_instance_id,
			  const char *executor_id,
			  const char *executor_instance_id,
			  u32 request_flags,
			  const char *approval_token,
			  struct kernel_mcp_decision_result *result)
{
	struct kernel_mcp_agent *agent;
	struct kernel_mcp_agent *broker_agent = NULL;
	struct kernel_mcp_agent_tool_state *state = NULL;
	struct kernel_mcp_tool *tool;
	struct kernel_mcp_tool_view tool_view;
	struct kernel_mcp_request_context audit_ctx;
	unsigned long lease_expiry_jiffies;
	u32 max_inflight;
	u32 agent_key;
	int ret = 0;

	memset(result, 0, sizeof(*result));
	result->decision = KERNEL_MCP_DECISION_DENY;
	result->reason = KERNEL_MCP_REASON_DENY_UNKNOWN_TOOL;
	result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (!tool) {
		mutex_unlock(&kernel_mcp_tools_lock);
		return 0;
	}
	kernel_mcp_copy_tool_view_locked(tool, &tool_view);
	mutex_unlock(&kernel_mcp_tools_lock);
	kernel_mcp_copy_request_context(&audit_ctx, broker_id, provider_id,
					executor_id, provider_instance_id,
					executor_instance_id, 0, request_flags,
					KERNEL_MCP_APPROVAL_STATE_PENDING);
	kernel_mcp_audit_event("capability_request", tool_view.name, agent_id,
			       &audit_ctx, req_id, 0, 0, 0,
			       tool_view.approval_mode,
			       KERNEL_MCP_APPROVAL_STATE_PENDING,
			       KERNEL_MCP_REASON_ALLOW, 0);
	if ((request_flags & KERNEL_MCP_REQUEST_FLAG_LEGACY_PATH) != 0)
		kernel_mcp_audit_event("compatibility_path_usage",
				       tool_view.name, agent_id, &audit_ctx,
				       req_id, 0, 0, 0,
				       tool_view.approval_mode,
				       KERNEL_MCP_APPROVAL_STATE_PENDING,
				       KERNEL_MCP_REASON_ALLOW, 0);

	result->reason = KERNEL_MCP_REASON_DENY_UNKNOWN_AGENT;
	result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
	agent_key = kernel_mcp_agent_hash_key(agent_id);
	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, agent_key);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		kernel_mcp_audit_event("request_denied", tool_view.name, agent_id,
				       &audit_ctx, req_id, 0, 0, 0,
				       tool_view.approval_mode,
				       result->approval_state, result->reason, 0);
		kernel_mcp_tool_account_decision(tool_id, result);
		return 0;
	}

	if (requested_tool_hash && tool_view.hash[0] != '\0' &&
	    strcmp(tool_view.hash, requested_tool_hash) != 0) {
		result->reason = KERNEL_MCP_REASON_HASH_MISMATCH;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		goto account_agent_only;
	}

	if (!kernel_mcp_authorize(agent, &tool_view, request_flags,
				  approval_token, &result->approval_state,
				  &result->reason)) {
		agent->authz_fail_count++;
		goto account_agent_only;
	}
	if (!kernel_mcp_validate_request_context_locked(agent_id, &tool_view,
							broker_id,
							provider_id,
							executor_id,
							provider_instance_id,
							executor_instance_id,
							request_flags,
							&broker_agent,
							&result->reason)) {
		agent->authz_fail_count++;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		goto account_agent_only;
	}

	state = kernel_mcp_get_agent_tool_state_locked(agent, tool_id);
	if (!state) {
		ret = -ENOMEM;
		goto out_unlock_agent;
	}

	mutex_lock(&kernel_mcp_requests_lock);
	if (kernel_mcp_find_request_locked(req_id, agent_id, tool_id)) {
		result->reason = KERNEL_MCP_REASON_DENY_DUPLICATE_REQUEST;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		mutex_unlock(&kernel_mcp_requests_lock);
		goto account_agent_only;
	}

	max_inflight = kernel_mcp_effective_max_inflight(&tool_view);
	if (max_inflight > 0 && state->inflight >= max_inflight) {
		result->decision = KERNEL_MCP_DECISION_DEFER;
		result->wait_ms = tool_view.rl.defer_wait_ms ?
			tool_view.rl.defer_wait_ms :
			KERNEL_MCP_DEFAULT_DEFER_WAIT_MS;
		result->tokens_left = state->tokens;
		result->reason = KERNEL_MCP_REASON_DEFER_RATE_LIMIT;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
		mutex_unlock(&kernel_mcp_requests_lock);
		goto account_agent_only;
	}

	if (tool_view.rl.enabled) {
		kernel_mcp_rate_limit_refill_locked(state, &tool_view.rl);
		if (state->last_refill == 0) {
			state->last_refill = jiffies;
			state->tokens = tool_view.rl.burst;
		}
		if (state->tokens < kernel_mcp_rate_limit_cost(&tool_view)) {
			result->decision = KERNEL_MCP_DECISION_DEFER;
			result->wait_ms = tool_view.rl.defer_wait_ms ?
				tool_view.rl.defer_wait_ms :
				KERNEL_MCP_DEFAULT_DEFER_WAIT_MS;
			result->tokens_left = state->tokens;
			result->reason = KERNEL_MCP_REASON_DEFER_RATE_LIMIT;
			result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
			mutex_unlock(&kernel_mcp_requests_lock);
			goto account_agent_only;
		}
		state->tokens -= kernel_mcp_rate_limit_cost(&tool_view);
		result->tokens_left = state->tokens;
	}

	result->lease_id = kernel_mcp_issue_lease_id(req_id, tool_id);
	result->lease_expires_ms = jiffies_to_msecs(KERNEL_MCP_LEASE_TTL_JIFFIES);
	lease_expiry_jiffies = jiffies + KERNEL_MCP_LEASE_TTL_JIFFIES;
	audit_ctx.lease_id = result->lease_id;
	audit_ctx.approval_state = result->approval_state;
	ret = kernel_mcp_insert_request_locked(req_id, agent_id, tool_view.name,
					       tool_id,
					       broker_id, provider_id,
					       executor_id,
					       provider_instance_id,
					       executor_instance_id,
					       broker_agent, result->lease_id,
					       request_flags,
					       result->approval_state,
					       lease_expiry_jiffies);
	if (ret == -EEXIST) {
		result->lease_id = 0;
		result->lease_expires_ms = 0;
		result->reason = KERNEL_MCP_REASON_DENY_DUPLICATE_REQUEST;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		mutex_unlock(&kernel_mcp_requests_lock);
		ret = 0;
		goto account_agent_only;
	}
	if (ret) {
		mutex_unlock(&kernel_mcp_requests_lock);
		goto out_unlock_agent;
	}

	state->inflight++;
	mutex_unlock(&kernel_mcp_requests_lock);

	result->decision = KERNEL_MCP_DECISION_ALLOW;
	result->reason = KERNEL_MCP_REASON_ALLOW;
	kernel_mcp_audit_event("lease_issued", tool_view.name, agent_id, &audit_ctx,
			       req_id,
			       broker_agent ? broker_agent->pid : 0,
			       broker_agent ? broker_agent->registration_epoch : 0,
			       result->lease_id, tool_view.approval_mode,
			       result->approval_state, result->reason,
			       lease_expiry_jiffies);

account_agent_only:
	if (result->decision == KERNEL_MCP_DECISION_DENY)
		kernel_mcp_audit_event("request_denied", tool_view.name, agent_id,
				       &audit_ctx, req_id,
				       broker_agent ? broker_agent->pid : 0,
				       broker_agent ? broker_agent->registration_epoch : 0,
				       result->lease_id, tool_view.approval_mode,
				       result->approval_state, result->reason,
				       lease_expiry_jiffies);
	if (result->decision == KERNEL_MCP_DECISION_ALLOW)
		agent->allow_count++;
	else if (result->decision == KERNEL_MCP_DECISION_DENY)
		agent->deny_count++;
	else
		agent->defer_count++;
	strscpy(agent->last_reason, kernel_mcp_reason_str(result->reason),
		sizeof(agent->last_reason));
	mutex_unlock(&kernel_mcp_agents_lock);
	kernel_mcp_tool_account_decision(tool_id, result);
	return 0;

out_unlock_agent:
	mutex_unlock(&kernel_mcp_agents_lock);
	return ret;
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
					  const struct kernel_mcp_decision_result *result,
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
	if (result->lease_id != 0) {
		ret = nla_put_u64_64bit(reply_skb, KERNEL_MCP_ATTR_LEASE_ID,
					result->lease_id,
					KERNEL_MCP_ATTR_UNSPEC);
		if (ret)
			goto nla_fail;
	}
	if (result->lease_expires_ms != 0) {
		ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_LEASE_EXPIRES_MS,
				  result->lease_expires_ms);
		if (ret)
			goto nla_fail;
	}
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_APPROVAL_STATE,
			  result->approval_state);
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
	u32 risk_level = 0;
	u32 approval_mode = 0;
	u32 audit_mode = 0;
	u32 max_inflight_per_agent = 0;
	struct kernel_mcp_rate_limit rl = { 0 };
	u64 required_caps = 0;
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
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_REQUIRED_CAPS])
		required_caps =
			nla_get_u64(info->attrs[KERNEL_MCP_ATTR_TOOL_REQUIRED_CAPS]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_RISK_LEVEL])
		risk_level =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_RISK_LEVEL]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_APPROVAL_MODE])
		approval_mode =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_APPROVAL_MODE]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_AUDIT_MODE])
		audit_mode =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_TOOL_AUDIT_MODE]);
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_MAX_INFLIGHT_PER_AGENT])
		max_inflight_per_agent = nla_get_u32(
			info->attrs[KERNEL_MCP_ATTR_TOOL_MAX_INFLIGHT_PER_AGENT]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_ENABLED])
		rl.enabled =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_ENABLED]) != 0;
	if (info->attrs[KERNEL_MCP_ATTR_RL_BURST])
		rl.burst = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_BURST]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_REFILL_TOKENS])
		rl.refill_tokens =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_REFILL_TOKENS]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_REFILL_JIFFIES])
		rl.refill_jiffies =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_REFILL_JIFFIES]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_DEFAULT_COST])
		rl.default_cost =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_DEFAULT_COST]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_AGENT])
		rl.max_inflight_per_agent =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_AGENT]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_DEFER_WAIT_MS])
		rl.defer_wait_ms =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_DEFER_WAIT_MS]);

	return kernel_mcp_register_tool(tool_id, tool_name, perm, cost, tool_hash,
					required_caps, risk_level,
					approval_mode, audit_mode,
					max_inflight_per_agent, &rl);
}

static int kernel_mcp_cmd_agent_register(struct sk_buff *skb,
					 struct genl_info *info)
{
	const char *agent_id;
	u32 pid;
	u32 uid = 0;
	u32 trust_level = 0;
	u32 flags = 0;
	bool uid_set = false;
	u64 caps = 0;

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
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_CAPS])
		caps = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_AGENT_CAPS]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_TRUST_LEVEL])
		trust_level =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_AGENT_TRUST_LEVEL]);
	if (info->attrs[KERNEL_MCP_ATTR_AGENT_FLAGS])
		flags = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_AGENT_FLAGS]);

	return kernel_mcp_register_agent(agent_id, pid, uid_set, uid, caps,
					 trust_level, flags);
}

static int kernel_mcp_cmd_tool_request(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_decision_result result;
	const char *agent_id;
	const char *broker_id = NULL;
	const char *provider_id = NULL;
	const char *provider_instance_id = NULL;
	const char *executor_id = NULL;
	const char *executor_instance_id = NULL;
	const char *requested_tool_hash = NULL;
	const char *approval_token = NULL;
	u32 tool_id;
	u32 request_flags = 0;
	u64 req_id;
	int ret;

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
	if (info->attrs[KERNEL_MCP_ATTR_TOOL_HASH])
		requested_tool_hash =
			nla_data(info->attrs[KERNEL_MCP_ATTR_TOOL_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_BROKER_ID])
		broker_id = nla_data(info->attrs[KERNEL_MCP_ATTR_BROKER_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_PROVIDER_ID])
		provider_id = nla_data(info->attrs[KERNEL_MCP_ATTR_PROVIDER_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_PROVIDER_INSTANCE_ID])
		provider_instance_id =
			nla_data(info->attrs[KERNEL_MCP_ATTR_PROVIDER_INSTANCE_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_EXECUTOR_ID])
		executor_id = nla_data(info->attrs[KERNEL_MCP_ATTR_EXECUTOR_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_EXECUTOR_INSTANCE_ID])
		executor_instance_id =
			nla_data(info->attrs[KERNEL_MCP_ATTR_EXECUTOR_INSTANCE_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_REQUEST_FLAGS])
		request_flags = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_REQUEST_FLAGS]);
	if (info->attrs[KERNEL_MCP_ATTR_APPROVAL_TOKEN])
		approval_token = nla_data(info->attrs[KERNEL_MCP_ATTR_APPROVAL_TOKEN]);
	kernel_mcp_requests_gc();
	ret = kernel_mcp_decide_request(agent_id, tool_id, req_id,
						requested_tool_hash, broker_id,
						provider_id, provider_instance_id,
						executor_id, executor_instance_id,
						request_flags, approval_token,
						&result);
	if (ret)
		return ret;

	return kernel_mcp_reply_tool_decision(info, agent_id, tool_id, req_id,
					      result.decision, result.wait_ms,
					      result.tokens_left,
					      &result,
					      kernel_mcp_reason_str(result.reason));
}

static int kernel_mcp_cmd_tool_complete(struct sk_buff *skb, struct genl_info *info)
{
	struct kernel_mcp_agent *agent;
	struct kernel_mcp_agent_tool_state *state;
	struct kernel_mcp_request *request;
	struct kernel_mcp_tool *tool;
	const char *agent_id;
	const char *broker_id = NULL;
	const char *provider_id = NULL;
	const char *provider_instance_id = NULL;
	const char *executor_id = NULL;
	const char *executor_instance_id = NULL;
	u32 tool_id;
	u64 req_id;
	u64 lease_id = 0;
	u32 approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
	u32 status;
	u32 exec_ms;
	u32 key;
	int ret = 0;

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
	if (info->attrs[KERNEL_MCP_ATTR_BROKER_ID])
		broker_id = nla_data(info->attrs[KERNEL_MCP_ATTR_BROKER_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_PROVIDER_ID])
		provider_id = nla_data(info->attrs[KERNEL_MCP_ATTR_PROVIDER_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_PROVIDER_INSTANCE_ID])
		provider_instance_id =
			nla_data(info->attrs[KERNEL_MCP_ATTR_PROVIDER_INSTANCE_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_EXECUTOR_ID])
		executor_id = nla_data(info->attrs[KERNEL_MCP_ATTR_EXECUTOR_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_EXECUTOR_INSTANCE_ID])
		executor_instance_id =
			nla_data(info->attrs[KERNEL_MCP_ATTR_EXECUTOR_INSTANCE_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_LEASE_ID])
		lease_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_LEASE_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_APPROVAL_STATE])
		approval_state =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_APPROVAL_STATE]);

	kernel_mcp_requests_gc();
	key = kernel_mcp_agent_hash_key(agent_id);
	mutex_lock(&kernel_mcp_agents_lock);
	agent = kernel_mcp_find_agent_locked(agent_id, key);
	if (!agent) {
		mutex_unlock(&kernel_mcp_agents_lock);
		return -ENOENT;
	}

	mutex_lock(&kernel_mcp_requests_lock);
	request = kernel_mcp_find_request_locked(req_id, agent_id, tool_id);
	if (!request) {
		agent->invalid_complete_count++;
		strscpy(agent->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_INVALID_COMPLETE),
			sizeof(agent->last_reason));
		ret = -ENOENT;
		goto out_unlock;
	}

	if (request->completed) {
		agent->duplicate_complete_count++;
		strscpy(agent->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_DUPLICATE_COMPLETE),
			sizeof(agent->last_reason));
		ret = -EALREADY;
		kernel_mcp_audit_event("duplicate_completion_attempt",
				       request->capability_domain, agent_id,
				       &request->ctx, req_id, request->broker_pid,
				       request->broker_epoch, request->ctx.lease_id, 0,
				       request->ctx.approval_state,
				       KERNEL_MCP_REASON_DUPLICATE_COMPLETE,
				       request->lease_expiry_jiffies);
		goto out_unlock;
	}
	if (!kernel_mcp_request_context_matches(request, broker_id, provider_id,
							executor_id,
							provider_instance_id,
							executor_instance_id,
							lease_id, approval_state)) {
		agent->invalid_complete_count++;
		strscpy(agent->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_INVALID_COMPLETE),
			sizeof(agent->last_reason));
		ret = -EPERM;
		goto out_unlock;
	}
	if (request->ctx.broker_id[0] != '\0') {
		struct kernel_mcp_agent *broker_agent;
		u32 broker_key;

		broker_key = kernel_mcp_agent_hash_key(request->ctx.broker_id);
		broker_agent = kernel_mcp_find_agent_locked(request->ctx.broker_id,
							    broker_key);
		if (!broker_agent ||
		    broker_agent->pid != request->broker_pid ||
		    broker_agent->registration_epoch != request->broker_epoch ||
		    broker_agent->uid_set != request->broker_uid_set ||
		    (broker_agent->uid_set &&
		     broker_agent->uid != request->broker_uid)) {
			agent->invalid_complete_count++;
			strscpy(agent->last_reason,
				kernel_mcp_reason_str(
					KERNEL_MCP_REASON_DENY_BROKER_IDENTITY),
				sizeof(agent->last_reason));
			ret = -EPERM;
			goto out_unlock;
		}
	}
	if (request->lease_consumed) {
		agent->duplicate_complete_count++;
		strscpy(agent->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_DUPLICATE_COMPLETE),
			sizeof(agent->last_reason));
		ret = -EALREADY;
		kernel_mcp_audit_event("duplicate_completion_attempt",
				       request->capability_domain, agent_id,
				       &request->ctx, req_id, request->broker_pid,
				       request->broker_epoch, request->ctx.lease_id, 0,
				       request->ctx.approval_state,
				       KERNEL_MCP_REASON_DUPLICATE_COMPLETE,
				       request->lease_expiry_jiffies);
		goto out_unlock;
	}
	if (time_after_eq(jiffies, request->lease_expiry_jiffies)) {
		state = kernel_mcp_find_agent_tool_state_locked(agent, tool_id);
		if (state && state->inflight > 0)
			state->inflight--;
		agent->timeout_count++;
		strscpy(agent->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_LEASE_EXPIRED),
			sizeof(agent->last_reason));
		kernel_mcp_audit_event("lease_expired", request->capability_domain,
				       agent_id, &request->ctx, req_id,
				       request->broker_pid, request->broker_epoch,
				       request->ctx.lease_id, 0,
				       request->ctx.approval_state,
				       KERNEL_MCP_REASON_LEASE_EXPIRED,
				       request->lease_expiry_jiffies);
		kernel_mcp_request_remove_locked(request);
		ret = -ETIME;
		goto out_unlock;
	}

	request->lease_consumed = true;
	request->completed = true;
	request->update_jiffies = jiffies;
	state = kernel_mcp_find_agent_tool_state_locked(agent, tool_id);
	if (state && state->inflight > 0)
		state->inflight--;

	if (status == KERNEL_MCP_COMPLETE_STATUS_OK)
		agent->completed_ok_count++;
	else
		agent->completed_err_count++;
	agent->last_exec_ms = exec_ms;
	agent->last_status = status;
	mutex_unlock(&kernel_mcp_requests_lock);
	mutex_unlock(&kernel_mcp_agents_lock);
	kernel_mcp_audit_event("execution_completed", request->capability_domain,
			       agent_id, &request->ctx, req_id, request->broker_pid,
			       request->broker_epoch, request->ctx.lease_id, 0,
			       request->ctx.approval_state, KERNEL_MCP_REASON_ALLOW,
			       request->lease_expiry_jiffies);

	mutex_lock(&kernel_mcp_tools_lock);
	tool = xa_load(&kernel_mcp_tools, tool_id);
	if (tool) {
		if (status == KERNEL_MCP_COMPLETE_STATUS_OK)
			tool->completed_ok_count++;
		else
			tool->completed_err_count++;
	}
	mutex_unlock(&kernel_mcp_tools_lock);
	return 0;

out_unlock:
	mutex_unlock(&kernel_mcp_requests_lock);
	mutex_unlock(&kernel_mcp_agents_lock);
	return ret;
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
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.doit = kernel_mcp_cmd_ping,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.doit = kernel_mcp_cmd_tool_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_LIST_TOOLS,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.dumpit = kernel_mcp_cmd_list_tools_dump,
	},
	{
		.cmd = KERNEL_MCP_CMD_AGENT_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.doit = kernel_mcp_cmd_agent_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_REQUEST,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.doit = kernel_mcp_cmd_tool_request,
	},
	{
		.cmd = KERNEL_MCP_CMD_TOOL_COMPLETE,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
		.doit = kernel_mcp_cmd_tool_complete,
	},
};

static struct genl_family kernel_mcp_genl_family = {
	.name = KERNEL_MCP_GENL_FAMILY_NAME,
	.version = KERNEL_MCP_GENL_FAMILY_VERSION,
	.maxattr = KERNEL_MCP_ATTR_APPROVAL_STATE,
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

	kernel_mcp_requests_destroy_all();
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
