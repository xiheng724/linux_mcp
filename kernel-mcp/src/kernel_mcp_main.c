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

#define KERNEL_MCP_CAPABILITY_NAME_MAX 128
#define KERNEL_MCP_CAPABILITY_HASH_MAX 17
#define KERNEL_MCP_PARTICIPANT_ID_MAX 64
#define KERNEL_MCP_CONTEXT_ID_MAX 64
#define KERNEL_MCP_REASON_MAX 64

#define KERNEL_MCP_CAPABILITY_STATUS_ACTIVE 1U

#define KERNEL_MCP_DECISION_ALLOW 1U
#define KERNEL_MCP_DECISION_DENY 2U
#define KERNEL_MCP_DECISION_DEFER 3U

#define KERNEL_MCP_COMPLETE_STATUS_OK 0U
#define KERNEL_MCP_COMPLETE_STATUS_ERR 1U

#define KERNEL_MCP_PARTICIPANT_HASH_BITS 8
#define KERNEL_MCP_REQUEST_HASH_BITS 8
#define KERNEL_MCP_HIGH_RISK_LEVEL 7U
#define KERNEL_MCP_HIGH_TRUST_THRESHOLD 7U
#define KERNEL_MCP_DEFAULT_DEFER_WAIT_MS 500U
#define KERNEL_MCP_REQUEST_TIMEOUT_JIFFIES (30 * HZ)
#define KERNEL_MCP_COMPLETED_RETENTION_JIFFIES (30 * HZ)
#define KERNEL_MCP_LEASE_TTL_JIFFIES (15 * HZ)
#define KERNEL_MCP_PARTICIPANT_FLAG_INTERACTIVE_APPROVED 0x1U
#define KERNEL_MCP_REQUEST_FLAG_INTERACTIVE_SESSION 0x1U
#define KERNEL_MCP_REQUEST_FLAG_EXPLICIT_APPROVED 0x2U

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

enum kernel_mcp_participant_type {
	KERNEL_MCP_PARTICIPANT_TYPE_VALUE_UNSPEC = 0,
	KERNEL_MCP_PARTICIPANT_TYPE_VALUE_PLANNER = 1,
	KERNEL_MCP_PARTICIPANT_TYPE_VALUE_BROKER = 2,
};

/* New enum: centralized reason codes. */
enum kernel_mcp_reason_code {
	KERNEL_MCP_REASON_REGISTERED = 0,
	KERNEL_MCP_REASON_ALLOW,
	KERNEL_MCP_REASON_DENY_UNKNOWN_CAPABILITY,
	KERNEL_MCP_REASON_DENY_UNKNOWN_PARTICIPANT,
	KERNEL_MCP_REASON_DENY_PARTICIPANT_TYPE,
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

/* Per-capability configurable rate-limit policy. */
struct kernel_mcp_rate_limit {
	bool enabled;
	u32 burst;
	u32 refill_tokens;
	u32 refill_jiffies;
	u32 default_cost;
	u32 max_inflight_per_participant;
	u32 defer_wait_ms;
};

/* Per-participant-per-capability rate/accounting state. */
struct kernel_mcp_participant_capability_state {
	u32 capability_id;
	u32 tokens;
	unsigned long last_refill;
	u32 inflight;
	struct list_head link;
};

struct kernel_mcp_capability {
	u32 id;
	/* Top-level kernel registry entry: stable capability domain. */
	char name[KERNEL_MCP_CAPABILITY_NAME_MAX];
	char hash[KERNEL_MCP_CAPABILITY_HASH_MAX];
	u32 cost;
	u64 required_caps;
	u32 risk_level;
	u32 approval_mode;
	u32 audit_mode;
	u32 max_inflight_per_participant;
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

struct kernel_mcp_capability_snapshot {
	char name[KERNEL_MCP_CAPABILITY_NAME_MAX];
	char hash[KERNEL_MCP_CAPABILITY_HASH_MAX];
	u32 cost;
	u64 required_caps;
	u32 risk_level;
	u32 approval_mode;
	u32 audit_mode;
	u32 max_inflight_per_participant;
	u32 rl_enabled;
	u32 rl_burst;
	u32 rl_refill_tokens;
	u32 rl_refill_jiffies;
	u32 rl_default_cost;
	u32 rl_max_inflight_per_participant;
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

struct kernel_mcp_participant {
	char id[KERNEL_MCP_PARTICIPANT_ID_MAX];
	u32 participant_type;
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

struct kernel_mcp_participant_snapshot {
	char id[KERNEL_MCP_PARTICIPANT_ID_MAX];
	u32 participant_type;
	u32 pid;
	u32 uid;
	u32 uid_set;
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
	char planner_participant_id[KERNEL_MCP_PARTICIPANT_ID_MAX];
	char capability_domain[KERNEL_MCP_CAPABILITY_NAME_MAX];
	u32 capability_id;
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

struct kernel_mcp_capability_view {
	char name[KERNEL_MCP_CAPABILITY_NAME_MAX];
	char hash[KERNEL_MCP_CAPABILITY_HASH_MAX];
	u32 cost;
	u64 required_caps;
	u32 risk_level;
	u32 approval_mode;
	u32 audit_mode;
	u32 max_inflight_per_participant;
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

static DEFINE_XARRAY(kernel_mcp_capabilities);
static DEFINE_MUTEX(kernel_mcp_capabilities_lock);

static DEFINE_HASHTABLE(kernel_mcp_participants, KERNEL_MCP_PARTICIPANT_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_participants_lock);
static DEFINE_HASHTABLE(kernel_mcp_requests, KERNEL_MCP_REQUEST_HASH_BITS);
static DEFINE_MUTEX(kernel_mcp_requests_lock);
static DEFINE_MUTEX(kernel_mcp_seq_lock);
static u64 kernel_mcp_broker_epoch_seq = 1;
static u64 kernel_mcp_lease_seq = 1;
static u64 kernel_mcp_audit_seq = 1;

static struct kobject *kernel_mcp_sysfs_root;
static struct kobject *kernel_mcp_sysfs_capabilities;
static struct kobject *kernel_mcp_sysfs_participants;
static struct genl_family kernel_mcp_genl_family;

static const struct nla_policy kernel_mcp_policy[KERNEL_MCP_ATTR_TOKENS_LEFT + 1] = {
	[KERNEL_MCP_ATTR_REQ_ID] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_CAPABILITY_ID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_CAPABILITY_NAME] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CAPABILITY_NAME_MAX - 1,
	},
	[KERNEL_MCP_ATTR_PARTICIPANT_ID] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_PARTICIPANT_ID_MAX - 1,
	},
	[KERNEL_MCP_ATTR_STATUS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_MESSAGE] = { .type = NLA_NUL_STRING, .len = 256 },
	[KERNEL_MCP_ATTR_UNIX_SOCK_PATH] = { .type = NLA_NUL_STRING, .len = 108 },
	[KERNEL_MCP_ATTR_PAYLOAD_LEN] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_AUDIT_SEQ] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_TS_NS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_CAPABILITY_COST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_PID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_UID] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_DECISION] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_WAIT_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_CAPABILITY_HASH] = {
		.type = NLA_NUL_STRING,
		.len = KERNEL_MCP_CAPABILITY_HASH_MAX - 1,
	},
	[KERNEL_MCP_ATTR_EXEC_MS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_CAPABILITY_REQUIRED_CAPS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_CAPABILITY_RISK_LEVEL] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_PARTICIPANT_CAPS] = { .type = NLA_U64 },
	[KERNEL_MCP_ATTR_PARTICIPANT_TRUST_LEVEL] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_PARTICIPANT_FLAGS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_ENABLED] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_BURST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_REFILL_TOKENS] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_REFILL_JIFFIES] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_DEFAULT_COST] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_PARTICIPANT] = { .type = NLA_U32 },
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
	[KERNEL_MCP_ATTR_CAPABILITY_APPROVAL_MODE] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_CAPABILITY_AUDIT_MODE] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_CAPABILITY_MAX_INFLIGHT_PER_PARTICIPANT] = { .type = NLA_U32 },
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
	[KERNEL_MCP_ATTR_PARTICIPANT_TYPE] = { .type = NLA_U32 },
	[KERNEL_MCP_ATTR_TOKENS_LEFT] = { .type = NLA_U32 },
};

/* Centralized reason string mapping for canonical capability/participant paths. */
static const char *
kernel_mcp_reason_str(enum kernel_mcp_reason_code code)
{
	switch (code) {
	case KERNEL_MCP_REASON_REGISTERED:
		return "registered";
	case KERNEL_MCP_REASON_ALLOW:
		return "allow";
	case KERNEL_MCP_REASON_DENY_UNKNOWN_CAPABILITY:
		return "deny_unknown_capability";
	case KERNEL_MCP_REASON_DENY_UNKNOWN_PARTICIPANT:
		return "deny_unknown_participant";
	case KERNEL_MCP_REASON_DENY_PARTICIPANT_TYPE:
		return "deny_participant_type";
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
kernel_mcp_participant_type_str(u32 participant_type)
{
	switch (participant_type) {
	case KERNEL_MCP_PARTICIPANT_TYPE_VALUE_BROKER:
		return "broker";
	case KERNEL_MCP_PARTICIPANT_TYPE_VALUE_PLANNER:
		return "planner";
	case KERNEL_MCP_PARTICIPANT_TYPE_VALUE_UNSPEC:
	default:
		return "unspecified";
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

static u32 kernel_mcp_participant_hash_key(const char *participant_id)
{
	return jhash(participant_id, strlen(participant_id), 0);
}

static struct kernel_mcp_participant *
kernel_mcp_find_participant_locked(const char *participant_id, u32 key)
{
	struct kernel_mcp_participant *participant;

	hash_for_each_possible(kernel_mcp_participants, participant, hnode, key) {
		if (strcmp(participant->id, participant_id) == 0)
			return participant;
	}
	return NULL;
}

static struct kernel_mcp_participant_capability_state *
kernel_mcp_find_participant_capability_state_locked(struct kernel_mcp_participant *participant,
						    u32 capability_id)
{
	struct kernel_mcp_participant_capability_state *state;

	list_for_each_entry(state, &participant->rl_states, link) {
		if (state->capability_id == capability_id)
			return state;
	}
	return NULL;
}

static struct kernel_mcp_participant_capability_state *
kernel_mcp_get_participant_capability_state_locked(struct kernel_mcp_participant *participant,
						   u32 capability_id)
{
	struct kernel_mcp_participant_capability_state *state;

	state = kernel_mcp_find_participant_capability_state_locked(participant,
							 capability_id);
	if (state)
		return state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	state->capability_id = capability_id;
	list_add_tail(&state->link, &participant->rl_states);
	return state;
}

static u32 kernel_mcp_request_hash_key(u64 req_id, const char *planner_participant_id,
				       u32 capability_id)
{
	u32 parts[2];

	parts[0] = lower_32_bits(req_id) ^ capability_id;
	parts[1] = upper_32_bits(req_id) ^
		kernel_mcp_participant_hash_key(planner_participant_id);
	return jhash2(parts, ARRAY_SIZE(parts), 0);
}

static struct kernel_mcp_request *
kernel_mcp_find_request_locked(u64 req_id, const char *planner_participant_id,
			       u32 capability_id)
{
	struct kernel_mcp_request *request;
	u32 key;

	key = kernel_mcp_request_hash_key(req_id, planner_participant_id,
					  capability_id);
	hash_for_each_possible(kernel_mcp_requests, request, hnode, key) {
		if (request->req_id == req_id &&
		    request->capability_id == capability_id &&
		    strcmp(request->planner_participant_id,
			   planner_participant_id) == 0)
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

static u64 kernel_mcp_next_seq(u64 *seq)
{
	u64 value;

	mutex_lock(&kernel_mcp_seq_lock);
	value = (*seq)++;
	mutex_unlock(&kernel_mcp_seq_lock);
	return value;
}

static void
kernel_mcp_copy_capability_view_locked(
	const struct kernel_mcp_capability *capability,
	struct kernel_mcp_capability_view *out)
{
	memset(out, 0, sizeof(*out));
	strscpy(out->name, capability->name, sizeof(out->name));
	strscpy(out->hash, capability->hash, sizeof(out->hash));
	out->cost = capability->cost;
	out->required_caps = capability->required_caps;
	out->risk_level = capability->risk_level;
	out->approval_mode = capability->approval_mode;
	out->audit_mode = capability->audit_mode;
	out->max_inflight_per_participant =
		capability->max_inflight_per_participant;
	out->rl = capability->rl;
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
		       const char *planner_participant_id,
		       const struct kernel_mcp_request_context *ctx, u64 req_id,
		       u32 broker_pid, u64 broker_epoch, u64 lease_id,
		       u32 approval_mode, u32 approval_state,
		       enum kernel_mcp_reason_code reason,
		       unsigned long expiry_jiffies)
{
	u64 seq = kernel_mcp_next_seq(&kernel_mcp_audit_seq);

	pr_info("kernel_mcp_audit {\"seq\":%llu,\"event\":\"%s\",\"req_id\":%llu,\"capability_domain\":\"%s\",\"planner_participant_id\":\"%s\",\"broker_id\":\"%s\",\"broker_pid\":%u,\"broker_epoch\":%llu,\"provider_id\":\"%s\",\"provider_instance_id\":\"%s\",\"executor_id\":\"%s\",\"executor_instance_id\":\"%s\",\"lease_id\":%llu,\"approval_mode\":%u,\"approval_state\":\"%s\",\"decision_reason\":\"%s\",\"expiry_time_ms\":%llu}\n",
			seq, event_type, req_id,
			capability_domain ? capability_domain : "",
			planner_participant_id ? planner_participant_id : "",
		ctx ? ctx->broker_id : "", broker_pid, broker_epoch,
		ctx ? ctx->provider_id : "",
		ctx ? ctx->provider_instance_id : "",
		ctx ? ctx->executor_id : "",
		ctx ? ctx->executor_instance_id : "", lease_id, approval_mode,
			kernel_mcp_approval_state_str(approval_state),
			kernel_mcp_reason_str(reason),
			kernel_mcp_expiry_time_ms(expiry_jiffies));
}

static void
kernel_mcp_copy_capability_snapshot_locked(
	const struct kernel_mcp_capability *capability,
	struct kernel_mcp_capability_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	strscpy(out->name, capability->name, sizeof(out->name));
	strscpy(out->hash, capability->hash, sizeof(out->hash));
	out->cost = capability->cost;
	out->required_caps = capability->required_caps;
	out->risk_level = capability->risk_level;
	out->approval_mode = capability->approval_mode;
	out->audit_mode = capability->audit_mode;
	out->max_inflight_per_participant =
		capability->max_inflight_per_participant;
	out->rl_enabled = capability->rl.enabled ? 1U : 0U;
	out->rl_burst = capability->rl.burst;
	out->rl_refill_tokens = capability->rl.refill_tokens;
	out->rl_refill_jiffies = capability->rl.refill_jiffies;
	out->rl_default_cost = capability->rl.default_cost;
	out->rl_max_inflight_per_participant =
		capability->rl.max_inflight_per_participant;
	out->rl_defer_wait_ms = capability->rl.defer_wait_ms;
	out->request_count = capability->request_count;
	out->allow_count = capability->allow_count;
	out->deny_count = capability->deny_count;
	out->defer_count = capability->defer_count;
	out->completed_ok_count = capability->completed_ok_count;
	out->completed_err_count = capability->completed_err_count;
	out->hash_mismatch_count = capability->hash_mismatch_count;
	out->rate_limit_hit_count = capability->rate_limit_hit_count;
}

static void
kernel_mcp_copy_participant_snapshot_locked(const struct kernel_mcp_participant *participant,
					    struct kernel_mcp_participant_snapshot *out)
{
	memset(out, 0, sizeof(*out));
	strscpy(out->id, participant->id, sizeof(out->id));
	out->participant_type = participant->participant_type;
	out->pid = participant->pid;
	out->uid = participant->uid;
	out->uid_set = participant->uid_set ? 1U : 0U;
	out->registration_epoch = participant->registration_epoch;
	out->caps = participant->caps;
	out->trust_level = participant->trust_level;
	out->flags = participant->flags;
	out->allow_count = participant->allow_count;
	out->deny_count = participant->deny_count;
	out->defer_count = participant->defer_count;
	out->completed_ok_count = participant->completed_ok_count;
	out->completed_err_count = participant->completed_err_count;
	out->authz_fail_count = participant->authz_fail_count;
	out->invalid_complete_count = participant->invalid_complete_count;
	out->duplicate_complete_count = participant->duplicate_complete_count;
	out->timeout_count = participant->timeout_count;
	out->last_exec_ms = participant->last_exec_ms;
	out->last_status = participant->last_status;
	strscpy(out->last_reason, participant->last_reason,
		sizeof(out->last_reason));
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
kernel_mcp_effective_max_inflight(
	const struct kernel_mcp_capability_view *capability)
{
	if (capability->max_inflight_per_participant != 0)
		return capability->max_inflight_per_participant;
	return capability->rl.max_inflight_per_participant;
}

static u64 kernel_mcp_issue_lease_id(u64 req_id, u32 capability_id)
{
	u64 seq = kernel_mcp_next_seq(&kernel_mcp_lease_seq);

	return (seq << 24) ^ ((req_id & 0xFFFFFFFFULL) << 8) ^
		(u64)(capability_id & 0xFFU);
}

static void
kernel_mcp_capability_account_decision(
	u32 capability_id, const struct kernel_mcp_decision_result *result)
{
	struct kernel_mcp_capability *capability;

	mutex_lock(&kernel_mcp_capabilities_lock);
	capability = xa_load(&kernel_mcp_capabilities, capability_id);
	if (capability) {
		capability->request_count++;
		if (result->decision == KERNEL_MCP_DECISION_ALLOW)
			capability->allow_count++;
		else if (result->decision == KERNEL_MCP_DECISION_DENY)
			capability->deny_count++;
		else
			capability->defer_count++;
		if (result->reason == KERNEL_MCP_REASON_HASH_MISMATCH)
			capability->hash_mismatch_count++;
		if (result->reason == KERNEL_MCP_REASON_DEFER_RATE_LIMIT)
			capability->rate_limit_hit_count++;
	}
	mutex_unlock(&kernel_mcp_capabilities_lock);
}

static int
kernel_mcp_lookup_capability_snapshot(struct kobject *kobj,
				struct kernel_mcp_capability_snapshot *out)
{
	unsigned long capability_id;
	const char *id_str;
	struct kernel_mcp_capability *capability;
	int ret;

	id_str = kobject_name(kobj);
	ret = kstrtoul(id_str, 10, &capability_id);
	if (ret)
		return ret;

	mutex_lock(&kernel_mcp_capabilities_lock);
	capability = xa_load(&kernel_mcp_capabilities, capability_id);
	if (!capability) {
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return -ENOENT;
	}
	kernel_mcp_copy_capability_snapshot_locked(capability, out);
	mutex_unlock(&kernel_mcp_capabilities_lock);
	return 0;
}

static int
kernel_mcp_lookup_participant_snapshot(struct kobject *kobj,
				       struct kernel_mcp_participant_snapshot *out)
{
	const char *participant_id;
	u32 key;
	struct kernel_mcp_participant *participant;

	participant_id = kobject_name(kobj);
	key = kernel_mcp_participant_hash_key(participant_id);

	mutex_lock(&kernel_mcp_participants_lock);
	participant = kernel_mcp_find_participant_locked(participant_id, key);
	if (!participant) {
		mutex_unlock(&kernel_mcp_participants_lock);
		return -ENOENT;
	}
	kernel_mcp_copy_participant_snapshot_locked(participant, out);
	mutex_unlock(&kernel_mcp_participants_lock);
	return 0;
}

static ssize_t kernel_mcp_capability_name_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.name);
}



static ssize_t kernel_mcp_capability_hash_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.hash);
}

static ssize_t kernel_mcp_capability_cost_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.cost);
}

static ssize_t kernel_mcp_capability_status_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "active\n");
}

static ssize_t kernel_mcp_capability_required_caps_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.required_caps);
}

static ssize_t kernel_mcp_capability_risk_level_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.risk_level);
}

static ssize_t kernel_mcp_capability_approval_mode_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.approval_mode);
}

static ssize_t kernel_mcp_capability_audit_mode_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.audit_mode);
}

static ssize_t
kernel_mcp_capability_max_inflight_per_participant_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n",
			  snapshot.max_inflight_per_participant);
}

static ssize_t kernel_mcp_capability_request_count_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.request_count);
}

static ssize_t kernel_mcp_capability_allow_count_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.allow_count);
}

static ssize_t kernel_mcp_capability_deny_count_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.deny_count);
}

static ssize_t kernel_mcp_capability_defer_count_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.defer_count);
}

static ssize_t kernel_mcp_capability_completed_ok_count_show(struct kobject *kobj,
						       struct kobj_attribute *attr,
						       char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_ok_count);
}

static ssize_t kernel_mcp_capability_completed_err_count_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_err_count);
}

static ssize_t kernel_mcp_capability_hash_mismatch_count_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.hash_mismatch_count);
}

static ssize_t kernel_mcp_capability_rate_limit_hit_count_show(struct kobject *kobj,
							 struct kobj_attribute *attr,
							 char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.rate_limit_hit_count);
}

static ssize_t kernel_mcp_capability_rl_enabled_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_enabled);
}

static ssize_t kernel_mcp_capability_rl_burst_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_burst);
}

static ssize_t kernel_mcp_capability_rl_refill_tokens_show(struct kobject *kobj,
						     struct kobj_attribute *attr,
						     char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_refill_tokens);
}

static ssize_t kernel_mcp_capability_rl_refill_jiffies_show(struct kobject *kobj,
						      struct kobj_attribute *attr,
						      char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_refill_jiffies);
}

static ssize_t kernel_mcp_capability_rl_default_cost_show(struct kobject *kobj,
						    struct kobj_attribute *attr,
						    char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_default_cost);
}

static ssize_t
kernel_mcp_capability_rl_max_inflight_per_participant_show(
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n",
			  snapshot.rl_max_inflight_per_participant);
}

static ssize_t kernel_mcp_capability_rl_defer_wait_ms_show(struct kobject *kobj,
						     struct kobj_attribute *attr,
						     char *buf)
{
	struct kernel_mcp_capability_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_capability_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.rl_defer_wait_ms);
}

static ssize_t kernel_mcp_participant_allow_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.allow_count);
}

static ssize_t kernel_mcp_participant_id_show(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.id);
}

static ssize_t kernel_mcp_participant_type_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n",
			  kernel_mcp_participant_type_str(snapshot.participant_type));
}

static ssize_t kernel_mcp_participant_pid_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.pid);
}

static ssize_t kernel_mcp_participant_uid_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.uid);
}

static ssize_t kernel_mcp_participant_uid_set_show(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.uid_set);
}

static ssize_t
kernel_mcp_participant_registration_epoch_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.registration_epoch);
}

static ssize_t kernel_mcp_participant_deny_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.deny_count);
}

static ssize_t kernel_mcp_participant_defer_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.defer_count);
}

static ssize_t kernel_mcp_participant_last_reason_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%s\n", snapshot.last_reason);
}

static ssize_t kernel_mcp_participant_completed_ok_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_ok_count);
}

static ssize_t kernel_mcp_participant_completed_err_show(struct kobject *kobj,
						   struct kobj_attribute *attr,
						   char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.completed_err_count);
}

static ssize_t kernel_mcp_participant_last_exec_ms_show(struct kobject *kobj,
						  struct kobj_attribute *attr,
						  char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.last_exec_ms);
}

static ssize_t kernel_mcp_participant_last_status_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.last_status);
}

static ssize_t kernel_mcp_participant_caps_show(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.caps);
}

static ssize_t kernel_mcp_participant_trust_level_show(struct kobject *kobj,
						 struct kobj_attribute *attr,
						 char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.trust_level);
}

static ssize_t kernel_mcp_participant_flags_show(struct kobject *kobj,
					   struct kobj_attribute *attr,
					   char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%u\n", snapshot.flags);
}

static ssize_t kernel_mcp_participant_authz_fail_show(struct kobject *kobj,
						struct kobj_attribute *attr,
						char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.authz_fail_count);
}

static ssize_t kernel_mcp_participant_invalid_complete_show(struct kobject *kobj,
						      struct kobj_attribute *attr,
						      char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.invalid_complete_count);
}

static ssize_t kernel_mcp_participant_duplicate_complete_show(struct kobject *kobj,
							struct kobj_attribute *attr,
							char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.duplicate_complete_count);
}

static ssize_t kernel_mcp_participant_timeout_show(struct kobject *kobj,
					     struct kobj_attribute *attr,
					     char *buf)
{
	struct kernel_mcp_participant_snapshot snapshot;
	int ret;

	(void)attr;
	ret = kernel_mcp_lookup_participant_snapshot(kobj, &snapshot);
	if (ret)
		return ret;
	return sysfs_emit(buf, "%llu\n", snapshot.timeout_count);
}

static struct kobj_attribute kernel_mcp_name_attr =
	__ATTR(name, 0444, kernel_mcp_capability_name_show, NULL);

static struct kobj_attribute kernel_mcp_hash_attr =
	__ATTR(hash, 0444, kernel_mcp_capability_hash_show, NULL);
static struct kobj_attribute kernel_mcp_cost_attr =
	__ATTR(cost, 0444, kernel_mcp_capability_cost_show, NULL);
static struct kobj_attribute kernel_mcp_capability_status_attr =
	__ATTR(status, 0444, kernel_mcp_capability_status_show, NULL);
static struct kobj_attribute kernel_mcp_capability_required_caps_attr =
	__ATTR(required_caps, 0444, kernel_mcp_capability_required_caps_show, NULL);
static struct kobj_attribute kernel_mcp_capability_risk_level_attr =
	__ATTR(risk_level, 0444, kernel_mcp_capability_risk_level_show, NULL);
static struct kobj_attribute kernel_mcp_capability_approval_mode_attr =
	__ATTR(approval_mode, 0444, kernel_mcp_capability_approval_mode_show, NULL);
static struct kobj_attribute kernel_mcp_capability_audit_mode_attr =
	__ATTR(audit_mode, 0444, kernel_mcp_capability_audit_mode_show, NULL);
static struct kobj_attribute
kernel_mcp_capability_max_inflight_per_participant_attr =
	__ATTR(max_inflight_per_participant, 0444,
	       kernel_mcp_capability_max_inflight_per_participant_show, NULL);
static struct kobj_attribute kernel_mcp_capability_request_count_attr =
	__ATTR(request_count, 0444, kernel_mcp_capability_request_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_allow_count_attr =
	__ATTR(allow_count, 0444, kernel_mcp_capability_allow_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_deny_count_attr =
	__ATTR(deny_count, 0444, kernel_mcp_capability_deny_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_defer_count_attr =
	__ATTR(defer_count, 0444, kernel_mcp_capability_defer_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_completed_ok_count_attr =
	__ATTR(completed_ok_count, 0444,
	       kernel_mcp_capability_completed_ok_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_completed_err_count_attr =
	__ATTR(completed_err_count, 0444,
	       kernel_mcp_capability_completed_err_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_hash_mismatch_count_attr =
	__ATTR(hash_mismatch_count, 0444,
	       kernel_mcp_capability_hash_mismatch_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rate_limit_hit_count_attr =
	__ATTR(rate_limit_hit_count, 0444,
	       kernel_mcp_capability_rate_limit_hit_count_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rl_enabled_attr =
	__ATTR(rl_enabled, 0444, kernel_mcp_capability_rl_enabled_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rl_burst_attr =
	__ATTR(rl_burst, 0444, kernel_mcp_capability_rl_burst_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rl_refill_tokens_attr =
	__ATTR(rl_refill_tokens, 0444,
	       kernel_mcp_capability_rl_refill_tokens_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rl_refill_jiffies_attr =
	__ATTR(rl_refill_jiffies, 0444,
	       kernel_mcp_capability_rl_refill_jiffies_show, NULL);
static struct kobj_attribute kernel_mcp_capability_rl_default_cost_attr =
	__ATTR(rl_default_cost, 0444,
	       kernel_mcp_capability_rl_default_cost_show, NULL);
static struct kobj_attribute
kernel_mcp_capability_rl_max_inflight_per_participant_attr =
	__ATTR(rl_max_inflight_per_participant, 0444,
	       kernel_mcp_capability_rl_max_inflight_per_participant_show,
	       NULL);
static struct kobj_attribute kernel_mcp_capability_rl_defer_wait_ms_attr =
	__ATTR(rl_defer_wait_ms, 0444,
	       kernel_mcp_capability_rl_defer_wait_ms_show, NULL);

static struct attribute *kernel_mcp_capability_attrs[] = {
	&kernel_mcp_name_attr.attr,
	&kernel_mcp_hash_attr.attr,
	&kernel_mcp_cost_attr.attr,
	&kernel_mcp_capability_status_attr.attr,
	&kernel_mcp_capability_required_caps_attr.attr,
	&kernel_mcp_capability_risk_level_attr.attr,
	&kernel_mcp_capability_approval_mode_attr.attr,
	&kernel_mcp_capability_audit_mode_attr.attr,
	&kernel_mcp_capability_max_inflight_per_participant_attr.attr,
	&kernel_mcp_capability_request_count_attr.attr,
	&kernel_mcp_capability_allow_count_attr.attr,
	&kernel_mcp_capability_deny_count_attr.attr,
	&kernel_mcp_capability_defer_count_attr.attr,
	&kernel_mcp_capability_completed_ok_count_attr.attr,
	&kernel_mcp_capability_completed_err_count_attr.attr,
	&kernel_mcp_capability_hash_mismatch_count_attr.attr,
	&kernel_mcp_capability_rate_limit_hit_count_attr.attr,
	&kernel_mcp_capability_rl_enabled_attr.attr,
	&kernel_mcp_capability_rl_burst_attr.attr,
	&kernel_mcp_capability_rl_refill_tokens_attr.attr,
	&kernel_mcp_capability_rl_refill_jiffies_attr.attr,
	&kernel_mcp_capability_rl_default_cost_attr.attr,
	&kernel_mcp_capability_rl_max_inflight_per_participant_attr.attr,
	&kernel_mcp_capability_rl_defer_wait_ms_attr.attr,
	NULL,
};

static const struct attribute_group kernel_mcp_capability_attr_group = {
	.attrs = kernel_mcp_capability_attrs,
};

static struct kobj_attribute kernel_mcp_participant_allow_attr =
	__ATTR(allow, 0444, kernel_mcp_participant_allow_show, NULL);
static struct kobj_attribute kernel_mcp_participant_id_attr =
	__ATTR(id, 0444, kernel_mcp_participant_id_show, NULL);
static struct kobj_attribute kernel_mcp_participant_type_attr =
	__ATTR(participant_type, 0444, kernel_mcp_participant_type_show, NULL);
static struct kobj_attribute kernel_mcp_participant_pid_attr =
	__ATTR(pid, 0444, kernel_mcp_participant_pid_show, NULL);
static struct kobj_attribute kernel_mcp_participant_uid_attr =
	__ATTR(uid, 0444, kernel_mcp_participant_uid_show, NULL);
static struct kobj_attribute kernel_mcp_participant_uid_set_attr =
	__ATTR(uid_set, 0444, kernel_mcp_participant_uid_set_show, NULL);
static struct kobj_attribute kernel_mcp_participant_registration_epoch_attr =
	__ATTR(registration_epoch, 0444,
	       kernel_mcp_participant_registration_epoch_show, NULL);
static struct kobj_attribute kernel_mcp_participant_deny_attr =
	__ATTR(deny, 0444, kernel_mcp_participant_deny_show, NULL);
static struct kobj_attribute kernel_mcp_participant_defer_attr =
	__ATTR(defer, 0444, kernel_mcp_participant_defer_show, NULL);
static struct kobj_attribute kernel_mcp_participant_last_reason_attr =
	__ATTR(last_reason, 0444, kernel_mcp_participant_last_reason_show, NULL);
static struct kobj_attribute kernel_mcp_participant_completed_ok_attr =
	__ATTR(completed_ok, 0444, kernel_mcp_participant_completed_ok_show, NULL);
static struct kobj_attribute kernel_mcp_participant_completed_err_attr =
	__ATTR(completed_err, 0444, kernel_mcp_participant_completed_err_show, NULL);
static struct kobj_attribute kernel_mcp_participant_last_exec_ms_attr =
	__ATTR(last_exec_ms, 0444, kernel_mcp_participant_last_exec_ms_show, NULL);
static struct kobj_attribute kernel_mcp_participant_last_status_attr =
	__ATTR(last_status, 0444, kernel_mcp_participant_last_status_show, NULL);
static struct kobj_attribute kernel_mcp_participant_caps_attr =
	__ATTR(caps, 0444, kernel_mcp_participant_caps_show, NULL);
static struct kobj_attribute kernel_mcp_participant_trust_level_attr =
	__ATTR(trust_level, 0444, kernel_mcp_participant_trust_level_show, NULL);
static struct kobj_attribute kernel_mcp_participant_flags_attr =
	__ATTR(flags, 0444, kernel_mcp_participant_flags_show, NULL);
static struct kobj_attribute kernel_mcp_participant_authz_fail_attr =
	__ATTR(authz_fail, 0444, kernel_mcp_participant_authz_fail_show, NULL);
static struct kobj_attribute kernel_mcp_participant_invalid_complete_attr =
	__ATTR(invalid_complete, 0444,
	       kernel_mcp_participant_invalid_complete_show, NULL);
static struct kobj_attribute kernel_mcp_participant_duplicate_complete_attr =
	__ATTR(duplicate_complete, 0444,
	       kernel_mcp_participant_duplicate_complete_show, NULL);
static struct kobj_attribute kernel_mcp_participant_timeout_attr =
	__ATTR(timeout, 0444, kernel_mcp_participant_timeout_show, NULL);

static struct attribute *kernel_mcp_participant_attrs[] = {
	&kernel_mcp_participant_id_attr.attr,
	&kernel_mcp_participant_type_attr.attr,
	&kernel_mcp_participant_pid_attr.attr,
	&kernel_mcp_participant_uid_attr.attr,
	&kernel_mcp_participant_uid_set_attr.attr,
	&kernel_mcp_participant_registration_epoch_attr.attr,
	&kernel_mcp_participant_caps_attr.attr,
	&kernel_mcp_participant_trust_level_attr.attr,
	&kernel_mcp_participant_flags_attr.attr,
	&kernel_mcp_participant_allow_attr.attr,
	&kernel_mcp_participant_deny_attr.attr,
	&kernel_mcp_participant_defer_attr.attr,
	&kernel_mcp_participant_last_reason_attr.attr,
	&kernel_mcp_participant_completed_ok_attr.attr,
	&kernel_mcp_participant_completed_err_attr.attr,
	&kernel_mcp_participant_authz_fail_attr.attr,
	&kernel_mcp_participant_invalid_complete_attr.attr,
	&kernel_mcp_participant_duplicate_complete_attr.attr,
	&kernel_mcp_participant_timeout_attr.attr,
	&kernel_mcp_participant_last_exec_ms_attr.attr,
	&kernel_mcp_participant_last_status_attr.attr,
	NULL,
};

static const struct attribute_group kernel_mcp_participant_attr_group = {
	.attrs = kernel_mcp_participant_attrs,
};

static void
kernel_mcp_capability_sysfs_remove(struct kernel_mcp_capability *capability)
{
	if (!capability->kobj)
		return;
	sysfs_remove_group(capability->kobj, &kernel_mcp_capability_attr_group);
	kobject_put(capability->kobj);
	capability->kobj = NULL;
}

static int
kernel_mcp_capability_sysfs_create(struct kernel_mcp_capability *capability)
{
	char capability_id_dir[16];
	int ret;

	if (!kernel_mcp_sysfs_capabilities)
		return -ENODEV;

	snprintf(capability_id_dir, sizeof(capability_id_dir), "%u",
		 capability->id);
	capability->kobj = kobject_create_and_add(capability_id_dir,
						  kernel_mcp_sysfs_capabilities);
	if (!capability->kobj)
		return -ENOMEM;

	ret = sysfs_create_group(capability->kobj,
				 &kernel_mcp_capability_attr_group);
	if (ret) {
		kobject_put(capability->kobj);
		capability->kobj = NULL;
		return ret;
	}
	return 0;
}

static void kernel_mcp_capability_free(struct kernel_mcp_capability *capability)
{
	if (!capability)
		return;
	kernel_mcp_capability_sysfs_remove(capability);
	kfree(capability);
}

static void kernel_mcp_capabilities_destroy_all(void)
{
	struct kernel_mcp_capability *capability;
	unsigned long index = 0;

	mutex_lock(&kernel_mcp_capabilities_lock);
	for (;;) {
		capability = xa_find(&kernel_mcp_capabilities, &index, ULONG_MAX,
				     XA_PRESENT);
		if (!capability)
			break;
		xa_erase(&kernel_mcp_capabilities, index);
		kernel_mcp_capability_free(capability);
		index++;
	}
	mutex_unlock(&kernel_mcp_capabilities_lock);
}

static int kernel_mcp_register_capability(u32 capability_id, const char *name,
					  u32 cost, const char *hash,
					  u64 required_caps, u32 risk_level,
					  u32 approval_mode, u32 audit_mode,
					  u32 max_inflight_per_participant,
					  const struct kernel_mcp_rate_limit *rl)
{
	struct kernel_mcp_capability *capability;
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
	if (max_inflight_per_participant == 0)
		max_inflight_per_participant =
			rl_cfg.max_inflight_per_participant;
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

	mutex_lock(&kernel_mcp_capabilities_lock);
	capability = xa_load(&kernel_mcp_capabilities, capability_id);
	if (capability) {
		strscpy(capability->name, name, sizeof(capability->name));
		if (hash)
			strscpy(capability->hash, hash, sizeof(capability->hash));
		capability->cost = cost;
		capability->required_caps = required_caps;
		capability->risk_level = risk_level;
		capability->approval_mode = approval_mode;
		capability->audit_mode = audit_mode;
		capability->max_inflight_per_participant =
			max_inflight_per_participant;
		capability->rl = rl_cfg;
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return 0;
	}

	capability = kzalloc(sizeof(*capability), GFP_KERNEL);
	if (!capability) {
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return -ENOMEM;
	}

	capability->id = capability_id;
	capability->cost = cost;
	capability->required_caps = required_caps;
	capability->risk_level = risk_level;
	capability->approval_mode = approval_mode;
	capability->audit_mode = audit_mode;
	capability->max_inflight_per_participant =
		max_inflight_per_participant;
	strscpy(capability->name, name, sizeof(capability->name));
	if (hash)
		strscpy(capability->hash, hash, sizeof(capability->hash));
	capability->rl = rl_cfg;

	ret = xa_err(xa_store(&kernel_mcp_capabilities, capability_id, capability,
			      GFP_KERNEL));
	if (ret) {
		kfree(capability);
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return ret;
	}

	ret = kernel_mcp_capability_sysfs_create(capability);
	if (ret) {
		xa_erase(&kernel_mcp_capabilities, capability_id);
		kfree(capability);
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return ret;
	}

	mutex_unlock(&kernel_mcp_capabilities_lock);
	return 0;
}

static void
kernel_mcp_participant_sysfs_remove(struct kernel_mcp_participant *participant)
{
	if (!participant->kobj)
		return;
	sysfs_remove_group(participant->kobj, &kernel_mcp_participant_attr_group);
	kobject_put(participant->kobj);
	participant->kobj = NULL;
}

static int
kernel_mcp_participant_sysfs_create(struct kernel_mcp_participant *participant)
{
	int ret;

	if (!kernel_mcp_sysfs_participants)
		return -ENODEV;

	participant->kobj = kobject_create_and_add(participant->id,
						   kernel_mcp_sysfs_participants);
	if (!participant->kobj)
		return -ENOMEM;

	ret = sysfs_create_group(participant->kobj,
				 &kernel_mcp_participant_attr_group);
	if (ret) {
		kobject_put(participant->kobj);
		participant->kobj = NULL;
		return ret;
	}
	return 0;
}

static void
kernel_mcp_participant_free(struct kernel_mcp_participant *participant)
{
	struct kernel_mcp_participant_capability_state *state;
	struct kernel_mcp_participant_capability_state *tmp;

	if (!participant)
		return;
	list_for_each_entry_safe(state, tmp, &participant->rl_states, link) {
		list_del(&state->link);
		kfree(state);
	}
	kernel_mcp_participant_sysfs_remove(participant);
	kfree(participant);
}

static void kernel_mcp_participants_destroy_all(void)
{
	struct kernel_mcp_participant *participant;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_participants_lock);
	hash_for_each_safe(kernel_mcp_participants, bkt, tmp, participant,
			   hnode) {
		hash_del(&participant->hnode);
		kernel_mcp_participant_free(participant);
	}
	mutex_unlock(&kernel_mcp_participants_lock);
}

static int kernel_mcp_register_participant(const char *participant_id,
					   u32 pid, bool uid_set, u32 uid,
					   u64 caps, u32 trust_level,
					   u32 flags, u32 participant_type)
{
	struct kernel_mcp_participant *participant;
	u32 key;
	int ret;

	if (participant_type == KERNEL_MCP_PARTICIPANT_TYPE_UNSPEC)
		participant_type = KERNEL_MCP_PARTICIPANT_TYPE_PLANNER;

	key = kernel_mcp_participant_hash_key(participant_id);
	mutex_lock(&kernel_mcp_participants_lock);
	participant = kernel_mcp_find_participant_locked(participant_id, key);
	if (participant) {
		participant->registration_epoch =
			kernel_mcp_next_seq(&kernel_mcp_broker_epoch_seq);
		participant->participant_type = participant_type;
		participant->pid = pid;
		participant->uid_set = uid_set;
		if (uid_set)
			participant->uid = uid;
		participant->caps = caps;
		participant->trust_level = trust_level;
		participant->flags = flags;
		mutex_unlock(&kernel_mcp_participants_lock);
		return 0;
	}

	participant = kzalloc(sizeof(*participant), GFP_KERNEL);
	if (!participant) {
		mutex_unlock(&kernel_mcp_participants_lock);
		return -ENOMEM;
	}

	strscpy(participant->id, participant_id, sizeof(participant->id));
	participant->participant_type = participant_type;
	participant->registration_epoch =
		kernel_mcp_next_seq(&kernel_mcp_broker_epoch_seq);
	participant->pid = pid;
	participant->uid = uid;
	participant->uid_set = uid_set;
	participant->caps = caps;
	participant->trust_level = trust_level;
	participant->flags = flags;
	INIT_LIST_HEAD(&participant->rl_states);
	strscpy(participant->last_reason,
		kernel_mcp_reason_str(KERNEL_MCP_REASON_REGISTERED),
		sizeof(participant->last_reason));

	ret = kernel_mcp_participant_sysfs_create(participant);
	if (ret) {
		kfree(participant);
		mutex_unlock(&kernel_mcp_participants_lock);
		return ret;
	}

	hash_add(kernel_mcp_participants, &participant->hnode, key);
	mutex_unlock(&kernel_mcp_participants_lock);
	return 0;
}

/* New helper: capability/trust based authorization. */
static bool
kernel_mcp_authorize(const struct kernel_mcp_participant *participant,
		     const struct kernel_mcp_capability_view *capability,
		     u32 request_flags, const char *approval_token,
		     u32 *approval_state,
		     enum kernel_mcp_reason_code *reason)
{
	if (approval_state)
		*approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
	if ((participant->caps & capability->required_caps) !=
	    capability->required_caps) {
		*reason = KERNEL_MCP_REASON_DENY_UNAUTHORIZED;
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		return false;
	}

	switch (capability->approval_mode) {
	case KERNEL_MCP_APPROVAL_MODE_ROOT_ONLY:
		if (!participant->uid_set || participant->uid != 0) {
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
		    (participant->flags & KERNEL_MCP_PARTICIPANT_FLAG_INTERACTIVE_APPROVED) == 0 &&
		    (!participant->uid_set || participant->uid != 0)) {
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
		    (!participant->uid_set || participant->uid != 0)) {
			*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
			if (approval_state)
				*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
			return false;
		}
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_APPROVED;
		break;
	case KERNEL_MCP_APPROVAL_MODE_TRUSTED:
		if ((!participant->uid_set || participant->uid != 0) &&
		    participant->trust_level < KERNEL_MCP_HIGH_TRUST_THRESHOLD) {
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

	if (capability->risk_level >= KERNEL_MCP_HIGH_RISK_LEVEL &&
	    (!participant->uid_set || participant->uid != 0) &&
	    participant->trust_level < KERNEL_MCP_HIGH_TRUST_THRESHOLD) {
		*reason = KERNEL_MCP_REASON_DENY_APPROVAL_REQUIRED;
		if (approval_state)
			*approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		return false;
	}

	return true;
}

static bool
kernel_mcp_validate_request_context_locked(const char *planner_participant_id,
					   const struct kernel_mcp_capability_view *capability,
					   const char *broker_id,
					   const char *provider_id,
					   const char *executor_id,
					   const char *executor_instance_id,
					   u32 request_flags,
					   struct kernel_mcp_participant **broker_participant_out,
					   enum kernel_mcp_reason_code *reason)
{
	struct kernel_mcp_participant *broker_participant;
	u32 broker_key;

	if (broker_participant_out)
		*broker_participant_out = NULL;
	if (!broker_id || broker_id[0] == '\0' || !provider_id ||
	    provider_id[0] == '\0' || !executor_id || executor_id[0] == '\0' ||
	    !executor_instance_id || executor_instance_id[0] == '\0') {
		*reason = KERNEL_MCP_REASON_DENY_CONTEXT_REQUIRED;
		return false;
	}
	if (strcmp(planner_participant_id, broker_id) == 0) {
		*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
		return false;
	}
	broker_key = kernel_mcp_participant_hash_key(broker_id);
	broker_participant = kernel_mcp_find_participant_locked(broker_id,
							      broker_key);
	if (!broker_participant) {
		*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
		return false;
	}
	if (broker_participant->participant_type !=
	    KERNEL_MCP_PARTICIPANT_TYPE_BROKER) {
		*reason = KERNEL_MCP_REASON_DENY_PARTICIPANT_TYPE;
		return false;
	}

	if (!kernel_mcp_authorize(broker_participant, capability, request_flags,
				  NULL, NULL, reason)) {
		*reason = KERNEL_MCP_REASON_DENY_BROKER_IDENTITY;
		return false;
	}
	if (broker_participant_out)
		*broker_participant_out = broker_participant;

	return true;
}

static void
kernel_mcp_rate_limit_refill_locked(struct kernel_mcp_participant_capability_state *state,
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
kernel_mcp_rate_limit_cost(const struct kernel_mcp_capability_view *capability)
{
	if (capability->rl.default_cost != 0)
		return capability->rl.default_cost;
	return max(capability->cost, 1U);
}

static int
kernel_mcp_insert_request_locked(u64 req_id,
				 const char *planner_participant_id,
				 const char *capability_domain,
				 u32 capability_id,
				 const char *broker_id,
				 const char *provider_id,
				 const char *executor_id,
				 const char *provider_instance_id,
				 const char *executor_instance_id,
				 const struct kernel_mcp_participant *broker_participant,
				 u64 lease_id, u32 request_flags,
				 u32 approval_state,
				 unsigned long lease_expiry_jiffies)
{
	struct kernel_mcp_request *request;
	u32 key;

	if (kernel_mcp_find_request_locked(req_id, planner_participant_id,
					   capability_id))
		return -EEXIST;

	request = kzalloc(sizeof(*request), GFP_KERNEL);
	if (!request)
		return -ENOMEM;

	request->req_id = req_id;
	request->capability_id = capability_id;
	request->start_jiffies = jiffies;
	request->update_jiffies = request->start_jiffies;
	request->lease_expiry_jiffies = lease_expiry_jiffies;
	strscpy(request->planner_participant_id, planner_participant_id,
		sizeof(request->planner_participant_id));
	strscpy(request->capability_domain, capability_domain,
		sizeof(request->capability_domain));
	kernel_mcp_copy_request_context(&request->ctx, broker_id, provider_id,
					executor_id, provider_instance_id,
					executor_instance_id, lease_id,
					request_flags, approval_state);
	if (broker_participant) {
		request->broker_pid = broker_participant->pid;
		request->broker_uid = broker_participant->uid;
		request->broker_uid_set = broker_participant->uid_set;
		request->broker_epoch = broker_participant->registration_epoch;
	}

	key = kernel_mcp_request_hash_key(req_id, planner_participant_id,
					  capability_id);
	hash_add(kernel_mcp_requests, &request->hnode, key);
	return 0;
}

static void
kernel_mcp_request_remove_locked(struct kernel_mcp_request *request)
{
	hash_del(&request->hnode);
	kfree(request);
}

static void kernel_mcp_requests_destroy_all(void)
{
	struct kernel_mcp_request *request;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_requests_lock);
	hash_for_each_safe(kernel_mcp_requests, bkt, tmp, request, hnode) {
		hash_del(&request->hnode);
		kfree(request);
	}
	mutex_unlock(&kernel_mcp_requests_lock);
}

static void kernel_mcp_requests_gc(void)
{
	struct kernel_mcp_request *request;
	struct hlist_node *tmp;
	int bkt;

	mutex_lock(&kernel_mcp_participants_lock);
	mutex_lock(&kernel_mcp_requests_lock);
	hash_for_each_safe(kernel_mcp_requests, bkt, tmp, request, hnode) {
		struct kernel_mcp_participant *planner_participant;
		struct kernel_mcp_participant_capability_state *state;
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

		key = kernel_mcp_participant_hash_key(request->planner_participant_id);
		planner_participant = kernel_mcp_find_participant_locked(
			request->planner_participant_id, key);
		if (planner_participant) {
			state = kernel_mcp_find_participant_capability_state_locked(
				planner_participant, request->capability_id);
			if (!request->completed) {
				if (state && state->inflight > 0)
					state->inflight--;
				planner_participant->timeout_count++;
				strscpy(planner_participant->last_reason,
					kernel_mcp_reason_str(lease_expired ?
						KERNEL_MCP_REASON_LEASE_EXPIRED :
						KERNEL_MCP_REASON_TIMEOUT),
					sizeof(planner_participant->last_reason));
				kernel_mcp_audit_event(lease_expired ?
						      "lease_expired" :
						      "request_timeout",
						      request->capability_domain,
						      request->planner_participant_id,
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
	mutex_unlock(&kernel_mcp_participants_lock);
}

/* New helper: centralized request decision flow. */
static int
kernel_mcp_decide_request(const char *planner_participant_id, u32 capability_id,
			  u64 req_id, const char *requested_capability_hash,
			  const char *broker_id,
			  const char *provider_id,
			  const char *provider_instance_id,
			  const char *executor_id,
			  const char *executor_instance_id,
			  u32 request_flags,
			  const char *approval_token,
			  struct kernel_mcp_decision_result *result)
{
	struct kernel_mcp_participant *planner_participant;
	struct kernel_mcp_participant *broker_participant = NULL;
	struct kernel_mcp_participant_capability_state *state = NULL;
	struct kernel_mcp_capability *capability;
	struct kernel_mcp_capability_view capability_view;
	struct kernel_mcp_request_context audit_ctx;
	unsigned long lease_expiry_jiffies;
	u32 max_inflight;
	u32 participant_key;
	int ret = 0;

	memset(result, 0, sizeof(*result));
	result->decision = KERNEL_MCP_DECISION_DENY;
	result->reason = KERNEL_MCP_REASON_DENY_UNKNOWN_CAPABILITY;
	result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;

	mutex_lock(&kernel_mcp_capabilities_lock);
	capability = xa_load(&kernel_mcp_capabilities, capability_id);
	if (!capability) {
		mutex_unlock(&kernel_mcp_capabilities_lock);
		return 0;
	}
	kernel_mcp_copy_capability_view_locked(capability, &capability_view);
	mutex_unlock(&kernel_mcp_capabilities_lock);
	kernel_mcp_copy_request_context(&audit_ctx, broker_id, provider_id,
					executor_id, provider_instance_id,
					executor_instance_id, 0, request_flags,
					KERNEL_MCP_APPROVAL_STATE_PENDING);
	kernel_mcp_audit_event("capability_request", capability_view.name,
			       planner_participant_id,
			       &audit_ctx, req_id, 0, 0, 0,
			       capability_view.approval_mode,
			       KERNEL_MCP_APPROVAL_STATE_PENDING,
			       KERNEL_MCP_REASON_ALLOW, 0);
	result->reason = KERNEL_MCP_REASON_DENY_UNKNOWN_PARTICIPANT;
	result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
	participant_key =
		kernel_mcp_participant_hash_key(planner_participant_id);
	mutex_lock(&kernel_mcp_participants_lock);
	planner_participant = kernel_mcp_find_participant_locked(
		planner_participant_id, participant_key);
	if (!planner_participant) {
		mutex_unlock(&kernel_mcp_participants_lock);
		kernel_mcp_audit_event("request_denied", capability_view.name,
				       planner_participant_id,
				       &audit_ctx, req_id, 0, 0, 0,
				       capability_view.approval_mode,
				       result->approval_state, result->reason, 0);
		kernel_mcp_capability_account_decision(capability_id, result);
		return 0;
	}
	if (planner_participant->participant_type !=
	    KERNEL_MCP_PARTICIPANT_TYPE_PLANNER) {
		result->reason = KERNEL_MCP_REASON_DENY_PARTICIPANT_TYPE;
		goto account_participant_only;
	}

	if (requested_capability_hash && capability_view.hash[0] != '\0' &&
	    strcmp(capability_view.hash, requested_capability_hash) != 0) {
		result->reason = KERNEL_MCP_REASON_HASH_MISMATCH;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		goto account_participant_only;
	}

	if (!kernel_mcp_authorize(planner_participant, &capability_view,
				  request_flags,
				  approval_token, &result->approval_state,
				  &result->reason)) {
		planner_participant->authz_fail_count++;
		goto account_participant_only;
	}
	if (!kernel_mcp_validate_request_context_locked(planner_participant_id,
							&capability_view,
							broker_id,
							provider_id,
							executor_id,
							executor_instance_id,
							request_flags,
							&broker_participant,
							&result->reason)) {
		planner_participant->authz_fail_count++;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		goto account_participant_only;
	}

	state = kernel_mcp_get_participant_capability_state_locked(
		planner_participant, capability_id);
	if (!state) {
		ret = -ENOMEM;
		goto out_unlock_participant;
	}

	mutex_lock(&kernel_mcp_requests_lock);
	if (kernel_mcp_find_request_locked(req_id, planner_participant_id,
					   capability_id)) {
		result->reason = KERNEL_MCP_REASON_DENY_DUPLICATE_REQUEST;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_REJECTED;
		mutex_unlock(&kernel_mcp_requests_lock);
		goto account_participant_only;
	}

	max_inflight = kernel_mcp_effective_max_inflight(&capability_view);
	if (max_inflight > 0 && state->inflight >= max_inflight) {
		result->decision = KERNEL_MCP_DECISION_DEFER;
		result->wait_ms = capability_view.rl.defer_wait_ms ?
			capability_view.rl.defer_wait_ms :
			KERNEL_MCP_DEFAULT_DEFER_WAIT_MS;
		result->tokens_left = state->tokens;
		result->reason = KERNEL_MCP_REASON_DEFER_RATE_LIMIT;
		result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
		mutex_unlock(&kernel_mcp_requests_lock);
		goto account_participant_only;
	}

	if (capability_view.rl.enabled) {
		kernel_mcp_rate_limit_refill_locked(state, &capability_view.rl);
		if (state->last_refill == 0) {
			state->last_refill = jiffies;
			state->tokens = capability_view.rl.burst;
		}
		if (state->tokens < kernel_mcp_rate_limit_cost(&capability_view)) {
			result->decision = KERNEL_MCP_DECISION_DEFER;
			result->wait_ms = capability_view.rl.defer_wait_ms ?
				capability_view.rl.defer_wait_ms :
				KERNEL_MCP_DEFAULT_DEFER_WAIT_MS;
			result->tokens_left = state->tokens;
			result->reason = KERNEL_MCP_REASON_DEFER_RATE_LIMIT;
			result->approval_state = KERNEL_MCP_APPROVAL_STATE_PENDING;
			mutex_unlock(&kernel_mcp_requests_lock);
			goto account_participant_only;
		}
		state->tokens -= kernel_mcp_rate_limit_cost(&capability_view);
		result->tokens_left = state->tokens;
	}

	result->lease_id = kernel_mcp_issue_lease_id(req_id, capability_id);
	result->lease_expires_ms = jiffies_to_msecs(KERNEL_MCP_LEASE_TTL_JIFFIES);
	lease_expiry_jiffies = jiffies + KERNEL_MCP_LEASE_TTL_JIFFIES;
	audit_ctx.lease_id = result->lease_id;
	audit_ctx.approval_state = result->approval_state;
	ret = kernel_mcp_insert_request_locked(req_id,
					       planner_participant_id,
					       capability_view.name,
					       capability_id,
					       broker_id, provider_id,
					       executor_id,
					       provider_instance_id,
					       executor_instance_id,
					       broker_participant,
					       result->lease_id,
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
		goto account_participant_only;
	}
	if (ret) {
		mutex_unlock(&kernel_mcp_requests_lock);
		goto out_unlock_participant;
	}

	state->inflight++;
	mutex_unlock(&kernel_mcp_requests_lock);

	result->decision = KERNEL_MCP_DECISION_ALLOW;
	result->reason = KERNEL_MCP_REASON_ALLOW;
	kernel_mcp_audit_event("lease_issued", capability_view.name,
			       planner_participant_id, &audit_ctx,
			       req_id,
			       broker_participant ? broker_participant->pid : 0,
			       broker_participant ?
				       broker_participant->registration_epoch :
				       0,
			       result->lease_id,
			       capability_view.approval_mode,
			       result->approval_state, result->reason,
			       lease_expiry_jiffies);

account_participant_only:
	if (result->decision == KERNEL_MCP_DECISION_DENY)
		kernel_mcp_audit_event("request_denied", capability_view.name,
				       planner_participant_id,
				       &audit_ctx, req_id,
				       broker_participant ?
					       broker_participant->pid :
					       0,
				       broker_participant ?
					       broker_participant->registration_epoch :
					       0,
				       result->lease_id,
				       capability_view.approval_mode,
				       result->approval_state, result->reason,
				       lease_expiry_jiffies);
	if (result->decision == KERNEL_MCP_DECISION_ALLOW)
		planner_participant->allow_count++;
	else if (result->decision == KERNEL_MCP_DECISION_DENY)
		planner_participant->deny_count++;
	else
		planner_participant->defer_count++;
	strscpy(planner_participant->last_reason,
		kernel_mcp_reason_str(result->reason),
		sizeof(planner_participant->last_reason));
	mutex_unlock(&kernel_mcp_participants_lock);
	kernel_mcp_capability_account_decision(capability_id, result);
	return 0;

out_unlock_participant:
	mutex_unlock(&kernel_mcp_participants_lock);
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

static int
kernel_mcp_reply_capability_decision(
	struct genl_info *info, const char *participant_id, u32 capability_id,
	u64 req_id, u32 decision, u32 wait_ms, u32 tokens_left,
	const struct kernel_mcp_decision_result *result, const char *reason)
{
	struct sk_buff *reply_skb;
	void *reply_hdr;
	int ret;

	reply_skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!reply_skb)
		return -ENOMEM;

	reply_hdr = genlmsg_put_reply(reply_skb, info, &kernel_mcp_genl_family, 0,
				      KERNEL_MCP_CMD_CAPABILITY_DECISION);
	if (!reply_hdr) {
		nlmsg_free(reply_skb);
		return -EMSGSIZE;
	}

	ret = nla_put_string(reply_skb, KERNEL_MCP_ATTR_PARTICIPANT_ID,
			     participant_id);
	if (ret)
		goto nla_fail;
	ret = nla_put_u32(reply_skb, KERNEL_MCP_ATTR_CAPABILITY_ID,
			  capability_id);
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

static int kernel_mcp_cmd_capability_register(struct sk_buff *skb,
					      struct genl_info *info)
{
	u32 capability_id;
	u32 cost;
	u32 risk_level = 0;
	u32 approval_mode = 0;
	u32 audit_mode = 0;
	u32 max_inflight_per_participant = 0;
	struct kernel_mcp_rate_limit rl = { 0 };
	u64 required_caps = 0;
	const char *capability_name;
	const char *capability_hash = NULL;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_CAPABILITY_NAME] ||
	    !info->attrs[KERNEL_MCP_ATTR_CAPABILITY_COST])
		return -EINVAL;

	capability_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID]);
	capability_name = nla_data(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_NAME]);
	cost = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_COST]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_HASH])
		capability_hash =
			nla_data(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_HASH]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_REQUIRED_CAPS])
		required_caps =
			nla_get_u64(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_REQUIRED_CAPS]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_RISK_LEVEL])
		risk_level =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_RISK_LEVEL]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_APPROVAL_MODE])
		approval_mode =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_APPROVAL_MODE]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_AUDIT_MODE])
		audit_mode =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_AUDIT_MODE]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_MAX_INFLIGHT_PER_PARTICIPANT])
		max_inflight_per_participant = nla_get_u32(
			info->attrs[KERNEL_MCP_ATTR_CAPABILITY_MAX_INFLIGHT_PER_PARTICIPANT]);
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
	if (info->attrs[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_PARTICIPANT])
		rl.max_inflight_per_participant = nla_get_u32(
			info->attrs[KERNEL_MCP_ATTR_RL_MAX_INFLIGHT_PER_PARTICIPANT]);
	if (info->attrs[KERNEL_MCP_ATTR_RL_DEFER_WAIT_MS])
		rl.defer_wait_ms =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_RL_DEFER_WAIT_MS]);

	return kernel_mcp_register_capability(capability_id, capability_name,
					      cost, capability_hash, required_caps,
					      risk_level, approval_mode,
					      audit_mode,
					      max_inflight_per_participant, &rl);
}

static int kernel_mcp_cmd_participant_register(struct sk_buff *skb,
					       struct genl_info *info)
{
	const char *participant_id;
	u32 pid;
	u32 uid = 0;
	u32 trust_level = 0;
	u32 flags = 0;
	u32 participant_type = KERNEL_MCP_PARTICIPANT_TYPE_PLANNER;
	bool uid_set = false;
	u64 caps = 0;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_PID])
		return -EINVAL;

	participant_id = nla_data(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID]);
	pid = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_PID]);
	if (info->attrs[KERNEL_MCP_ATTR_UID]) {
		uid = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_UID]);
		uid_set = true;
	}
	if (info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_CAPS])
		caps = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_CAPS]);
	if (info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_TRUST_LEVEL])
		trust_level =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_TRUST_LEVEL]);
	if (info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_FLAGS])
		flags = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_FLAGS]);
	if (info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_TYPE])
		participant_type =
			nla_get_u32(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_TYPE]);

	return kernel_mcp_register_participant(participant_id, pid, uid_set, uid,
					       caps, trust_level, flags,
					       participant_type);
}

static int kernel_mcp_cmd_capability_request(struct sk_buff *skb,
					     struct genl_info *info)
{
	struct kernel_mcp_decision_result result;
	const char *participant_id;
	const char *broker_id = NULL;
	const char *provider_id = NULL;
	const char *provider_instance_id = NULL;
	const char *executor_id = NULL;
	const char *executor_instance_id = NULL;
	const char *requested_capability_hash = NULL;
	const char *approval_token = NULL;
	u32 capability_id;
	u32 request_flags = 0;
	u64 req_id;
	int ret;

	(void)skb;
	if (!info)
		return -EINVAL;
	if (!info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_REQ_ID])
		return -EINVAL;

	participant_id = nla_data(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID]);
	capability_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID]);
	req_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_REQ_ID]);
	if (info->attrs[KERNEL_MCP_ATTR_CAPABILITY_HASH])
		requested_capability_hash =
			nla_data(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_HASH]);
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
	ret = kernel_mcp_decide_request(participant_id, capability_id, req_id,
					requested_capability_hash, broker_id,
					provider_id, provider_instance_id,
					executor_id, executor_instance_id,
					request_flags, approval_token, &result);
	if (ret)
		return ret;

	return kernel_mcp_reply_capability_decision(
		info, participant_id, capability_id, req_id, result.decision,
		result.wait_ms, result.tokens_left, &result,
		kernel_mcp_reason_str(result.reason));
}

static int kernel_mcp_cmd_capability_complete(struct sk_buff *skb,
					      struct genl_info *info)
{
	struct kernel_mcp_participant *planner_participant;
	struct kernel_mcp_participant_capability_state *state;
	struct kernel_mcp_request *request;
	struct kernel_mcp_capability *capability;
	struct kernel_mcp_participant *broker_participant;
	const char *planner_participant_id;
	const char *broker_id = NULL;
	const char *provider_id = NULL;
	const char *provider_instance_id = NULL;
	const char *executor_id = NULL;
	const char *executor_instance_id = NULL;
	u32 capability_id;
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
	    !info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID] ||
	    !info->attrs[KERNEL_MCP_ATTR_STATUS] ||
	    !info->attrs[KERNEL_MCP_ATTR_EXEC_MS] ||
	    !info->attrs[KERNEL_MCP_ATTR_BROKER_ID])
		return -EINVAL;

	req_id = nla_get_u64(info->attrs[KERNEL_MCP_ATTR_REQ_ID]);
	planner_participant_id = nla_data(info->attrs[KERNEL_MCP_ATTR_PARTICIPANT_ID]);
	capability_id = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_CAPABILITY_ID]);
	status = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_STATUS]);
	exec_ms = nla_get_u32(info->attrs[KERNEL_MCP_ATTR_EXEC_MS]);
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
	key = kernel_mcp_participant_hash_key(planner_participant_id);
	mutex_lock(&kernel_mcp_participants_lock);
	planner_participant = kernel_mcp_find_participant_locked(
		planner_participant_id, key);
	if (!planner_participant) {
		mutex_unlock(&kernel_mcp_participants_lock);
		return -ENOENT;
	}
	if (planner_participant->participant_type !=
	    KERNEL_MCP_PARTICIPANT_TYPE_PLANNER) {
		mutex_unlock(&kernel_mcp_participants_lock);
		return -EPERM;
	}

	mutex_lock(&kernel_mcp_requests_lock);
	request = kernel_mcp_find_request_locked(req_id, planner_participant_id,
						 capability_id);
	if (!request) {
		planner_participant->invalid_complete_count++;
		strscpy(planner_participant->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_INVALID_COMPLETE),
			sizeof(planner_participant->last_reason));
		ret = -ENOENT;
		goto out_unlock;
	}

	if (request->completed) {
		planner_participant->duplicate_complete_count++;
		strscpy(planner_participant->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_DUPLICATE_COMPLETE),
			sizeof(planner_participant->last_reason));
		ret = -EALREADY;
		kernel_mcp_audit_event("duplicate_completion_attempt",
				       request->capability_domain,
				       planner_participant_id,
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
		planner_participant->invalid_complete_count++;
		strscpy(planner_participant->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_INVALID_COMPLETE),
			sizeof(planner_participant->last_reason));
		ret = -EPERM;
		goto out_unlock;
	}
	if (request->ctx.broker_id[0] == '\0') {
		planner_participant->invalid_complete_count++;
		strscpy(planner_participant->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_INVALID_COMPLETE),
			sizeof(planner_participant->last_reason));
		ret = -EPERM;
		goto out_unlock;
	}
	{
		u32 broker_key;

		broker_key = kernel_mcp_participant_hash_key(request->ctx.broker_id);
		broker_participant = kernel_mcp_find_participant_locked(
			request->ctx.broker_id, broker_key);
		if (!broker_participant ||
		    broker_participant->participant_type !=
			    KERNEL_MCP_PARTICIPANT_TYPE_BROKER ||
		    broker_participant->pid != request->broker_pid ||
		    broker_participant->registration_epoch != request->broker_epoch ||
		    broker_participant->uid_set != request->broker_uid_set ||
		    (broker_participant->uid_set &&
		     broker_participant->uid != request->broker_uid)) {
			planner_participant->invalid_complete_count++;
			strscpy(planner_participant->last_reason,
				kernel_mcp_reason_str(
					KERNEL_MCP_REASON_DENY_BROKER_IDENTITY),
				sizeof(planner_participant->last_reason));
			ret = -EPERM;
			goto out_unlock;
		}
	}
	if (time_after_eq(jiffies, request->lease_expiry_jiffies)) {
		state = kernel_mcp_find_participant_capability_state_locked(
			planner_participant, capability_id);
		if (state && state->inflight > 0)
			state->inflight--;
		planner_participant->timeout_count++;
		strscpy(planner_participant->last_reason,
			kernel_mcp_reason_str(KERNEL_MCP_REASON_LEASE_EXPIRED),
			sizeof(planner_participant->last_reason));
		kernel_mcp_audit_event("lease_expired", request->capability_domain,
				       planner_participant_id, &request->ctx,
				       req_id,
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
	state = kernel_mcp_find_participant_capability_state_locked(
		planner_participant, capability_id);
	if (state && state->inflight > 0)
		state->inflight--;

	if (status == KERNEL_MCP_COMPLETE_STATUS_OK)
		planner_participant->completed_ok_count++;
	else
		planner_participant->completed_err_count++;
	planner_participant->last_exec_ms = exec_ms;
	planner_participant->last_status = status;
	mutex_unlock(&kernel_mcp_requests_lock);
	mutex_unlock(&kernel_mcp_participants_lock);
	kernel_mcp_audit_event("execution_completed", request->capability_domain,
			       planner_participant_id, &request->ctx, req_id,
			       request->broker_pid, request->broker_epoch,
			       request->ctx.lease_id, 0,
			       request->ctx.approval_state, KERNEL_MCP_REASON_ALLOW,
			       request->lease_expiry_jiffies);

	mutex_lock(&kernel_mcp_capabilities_lock);
	capability = xa_load(&kernel_mcp_capabilities, capability_id);
	if (capability) {
		if (status == KERNEL_MCP_COMPLETE_STATUS_OK)
			capability->completed_ok_count++;
		else
			capability->completed_err_count++;
	}
	mutex_unlock(&kernel_mcp_capabilities_lock);
	return 0;

out_unlock:
	mutex_unlock(&kernel_mcp_requests_lock);
	mutex_unlock(&kernel_mcp_participants_lock);
	return ret;
}

static int kernel_mcp_cmd_list_capabilities_dump(struct sk_buff *skb,
						 struct netlink_callback *cb)
{
	struct kernel_mcp_capability *capability;
	unsigned long index = cb->args[0];
	void *msg_hdr;
	int ret = 0;

	mutex_lock(&kernel_mcp_capabilities_lock);
	for (;;) {
		capability = xa_find(&kernel_mcp_capabilities, &index, ULONG_MAX,
				     XA_PRESENT);
		if (!capability)
			break;

		msg_hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, &kernel_mcp_genl_family,
				      NLM_F_MULTI, KERNEL_MCP_CMD_LIST_CAPABILITIES);
		if (!msg_hdr) {
			ret = -EMSGSIZE;
			break;
		}

		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_CAPABILITY_ID,
				  capability->id);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_string(skb, KERNEL_MCP_ATTR_CAPABILITY_NAME,
				     capability->name);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_CAPABILITY_COST,
				  capability->cost);
		if (ret)
			goto dump_nla_fail;
		ret = nla_put_u32(skb, KERNEL_MCP_ATTR_STATUS,
				  KERNEL_MCP_CAPABILITY_STATUS_ACTIVE);
		if (ret)
			goto dump_nla_fail;
		if (capability->hash[0] != '\0') {
			ret = nla_put_string(skb, KERNEL_MCP_ATTR_CAPABILITY_HASH,
					     capability->hash);
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
	mutex_unlock(&kernel_mcp_capabilities_lock);

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
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.doit = kernel_mcp_cmd_ping,
	},
	{
		.cmd = KERNEL_MCP_CMD_CAPABILITY_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.doit = kernel_mcp_cmd_capability_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_LIST_CAPABILITIES,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.dumpit = kernel_mcp_cmd_list_capabilities_dump,
	},
	{
		.cmd = KERNEL_MCP_CMD_PARTICIPANT_REGISTER,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.doit = kernel_mcp_cmd_participant_register,
	},
	{
		.cmd = KERNEL_MCP_CMD_CAPABILITY_REQUEST,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.doit = kernel_mcp_cmd_capability_request,
	},
	{
		.cmd = KERNEL_MCP_CMD_CAPABILITY_COMPLETE,
		.flags = 0,
		.policy = kernel_mcp_policy,
		.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
		.doit = kernel_mcp_cmd_capability_complete,
	},
};

static struct genl_family kernel_mcp_genl_family = {
	.name = KERNEL_MCP_GENL_FAMILY_NAME,
	.version = KERNEL_MCP_GENL_FAMILY_VERSION,
	.maxattr = KERNEL_MCP_ATTR_TOKENS_LEFT,
	.module = THIS_MODULE,
	.ops = kernel_mcp_genl_ops,
	.n_ops = ARRAY_SIZE(kernel_mcp_genl_ops),
};

static int kernel_mcp_sysfs_init(void)
{
	kernel_mcp_sysfs_root = kobject_create_and_add("mcp", kernel_kobj);
	if (!kernel_mcp_sysfs_root)
		return -ENOMEM;

	kernel_mcp_sysfs_capabilities = kobject_create_and_add("capabilities",
							kernel_mcp_sysfs_root);
	if (!kernel_mcp_sysfs_capabilities)
		goto fail_root;

	kernel_mcp_sysfs_participants = kobject_create_and_add("participants",
							 kernel_mcp_sysfs_root);
	if (!kernel_mcp_sysfs_participants)
		goto fail_capabilities;

	return 0;

fail_capabilities:
	kobject_put(kernel_mcp_sysfs_capabilities);
	kernel_mcp_sysfs_capabilities = NULL;
fail_root:
	kobject_put(kernel_mcp_sysfs_root);
	kernel_mcp_sysfs_root = NULL;
	return -ENOMEM;
}

static void kernel_mcp_sysfs_exit(void)
{
	if (kernel_mcp_sysfs_participants) {
		kobject_put(kernel_mcp_sysfs_participants);
		kernel_mcp_sysfs_participants = NULL;
	}
	if (kernel_mcp_sysfs_capabilities) {
		kobject_put(kernel_mcp_sysfs_capabilities);
		kernel_mcp_sysfs_capabilities = NULL;
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
	kernel_mcp_participants_destroy_all();
	kernel_mcp_capabilities_destroy_all();
	kernel_mcp_sysfs_exit();
	pr_info("kernel_mcp: unloaded\n");
}

module_init(kernel_mcp_init);
module_exit(kernel_mcp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("linux-mcp");
MODULE_DESCRIPTION("Kernel MCP control-plane Generic Netlink");
MODULE_VERSION("0.3.0");
