#include <errno.h>
#include <linux/genetlink.h>
#include <linux/kernel_mcp_schema.h>
#include <linux/netlink.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif

#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#ifndef NLA_DATA
#define NLA_DATA(nla) ((void *)((char *)(nla) + NLA_HDRLEN))
#endif

#ifndef NLA_OK
#define NLA_OK(nla, len)                                                        \
	((len) >= (int)sizeof(struct nlattr) &&                                 \
	 (nla)->nla_len >= sizeof(struct nlattr) &&                             \
	 (nla)->nla_len <= (len))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, attrlen)                                                  \
	((attrlen) -= NLA_ALIGN((nla)->nla_len),                              \
	 (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

struct capability_args {
	uint32_t capability_id;
	char capability_name[128];
	char capability_hash[17];
	bool has_capability_hash;
	uint32_t perm;
	uint32_t cost;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --capability-id <u32> --capability-name <str> --perm <u32> --cost <u32> [--capability-hash <8hex>]\n",
		prog);
}

static int parse_hash(const char *s, char *out, size_t out_len)
{
	size_t i;
	size_t len = strlen(s);

	if (len == 0 || len >= out_len || len > 16)
		return -EINVAL;
	for (i = 0; i < len; i++) {
		char c = s[i];
		bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
			  (c >= 'A' && c <= 'F');
		if (!ok)
			return -EINVAL;
	}
	if (len != 8)
		return -EINVAL;
	memcpy(out, s, len + 1);
	return 0;
}

static int parse_u32(const char *s, uint32_t *out)
{
	char *end = NULL;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v > UINT32_MAX)
		return -EINVAL;
	*out = (uint32_t)v;
	return 0;
}

static int parse_args(int argc, char **argv, struct capability_args *args)
{
	int i;
	int seen_capability_id = 0;
	int seen_capability_name = 0;
	int seen_perm = 0;
	int seen_cost = 0;

	memset(args, 0, sizeof(*args));
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--capability-id") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->capability_id))
				return -EINVAL;
			seen_capability_id = 1;
			continue;
		}
		if (strcmp(argv[i], "--capability-name") == 0 && i + 1 < argc) {
			size_t nlen = strlen(argv[++i]);
			if (nlen == 0 || nlen >= sizeof(args->capability_name))
				return -EINVAL;
			memcpy(args->capability_name, argv[i], nlen + 1);
			seen_capability_name = 1;
			continue;
		}
		if (strcmp(argv[i], "--perm") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->perm))
				return -EINVAL;
			seen_perm = 1;
			continue;
		}
		if (strcmp(argv[i], "--capability-hash") == 0 && i + 1 < argc) {
			if (parse_hash(argv[++i], args->capability_hash,
				       sizeof(args->capability_hash)))
				return -EINVAL;
			args->has_capability_hash = true;
			continue;
		}
		if (strcmp(argv[i], "--cost") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->cost))
				return -EINVAL;
			seen_cost = 1;
			continue;
		}
		return -EINVAL;
	}

	if (!seen_capability_id || !seen_capability_name || !seen_perm || !seen_cost)
		return -EINVAL;
	return 0;
}

static int add_attr(struct nlmsghdr *nlh, size_t maxlen, uint16_t type,
		    const void *data, size_t data_len)
{
	size_t attr_len = NLA_HDRLEN + data_len;
	size_t attr_aligned = NLA_ALIGN(attr_len);
	size_t total = NLMSG_ALIGN(nlh->nlmsg_len) + attr_aligned;
	struct nlattr *attr;

	if (total > maxlen)
		return -EMSGSIZE;

	attr = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	attr->nla_type = type;
	attr->nla_len = (uint16_t)attr_len;
	memcpy((char *)attr + NLA_HDRLEN, data, data_len);

	if (attr_aligned > attr_len)
		memset((char *)attr + attr_len, 0, attr_aligned - attr_len);

	nlh->nlmsg_len = (uint32_t)total;
	return 0;
}

static int open_genl_socket(void)
{
	struct sockaddr_nl local = {0};
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

	if (fd < 0)
		return -errno;

	local.nl_family = AF_NETLINK;
	local.nl_pid = (uint32_t)getpid();
	local.nl_groups = 0;
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		int err = -errno;
		close(fd);
		return err;
	}

	return fd;
}

static int send_nlmsg(int fd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl kernel = {0};
	ssize_t sent;

	kernel.nl_family = AF_NETLINK;
	sent = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&kernel,
		      sizeof(kernel));
	if (sent < 0)
		return -errno;
	if ((size_t)sent != nlh->nlmsg_len)
		return -EIO;
	return 0;
}

static int recv_nlmsg(int fd, char *buf, size_t buf_size, ssize_t *out_len)
{
	ssize_t n = recv(fd, buf, buf_size, 0);
	if (n < 0)
		return -errno;
	if ((size_t)n < sizeof(struct nlmsghdr))
		return -EPROTO;
	*out_len = n;
	return 0;
}

static int parse_nl_error(const struct nlmsghdr *nlh)
{
	const struct nlmsgerr *err;

	if (nlh->nlmsg_type != NLMSG_ERROR)
		return 0;
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr)))
		return -EPROTO;
	err = (const struct nlmsgerr *)NLMSG_DATA(nlh);
	return err->error;
}

static int resolve_family_id(int fd, uint16_t *family_id)
{
	char txbuf[512] = {0};
	char rxbuf[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *ghdr;
	ssize_t rxlen;
	int ret;
	int attr_len;
	struct nlattr *attr;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;
	ghdr->reserved = 0;

	ret = add_attr(nlh, sizeof(txbuf), CTRL_ATTR_FAMILY_NAME,
		       KERNEL_MCP_GENL_FAMILY_NAME,
		       strlen(KERNEL_MCP_GENL_FAMILY_NAME) + 1);
	if (ret)
		return ret;

	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	ret = recv_nlmsg(fd, rxbuf, sizeof(rxbuf), &rxlen);
	if (ret)
		return ret;

	nlh = (struct nlmsghdr *)rxbuf;
	ret = parse_nl_error(nlh);
	if (ret == -ENOENT)
		return -ENOENT;
	if (ret)
		return ret;
	if (nlh->nlmsg_type != GENL_ID_CTRL)
		return -EPROTO;
	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
		return -EPROTO;

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	attr = (struct nlattr *)((char *)ghdr + GENL_HDRLEN);
	attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

	while (NLA_OK(attr, attr_len)) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
			if (attr->nla_len < NLA_HDRLEN + sizeof(uint16_t))
				return -EPROTO;
			memcpy(family_id, NLA_DATA(attr), sizeof(uint16_t));
			return 0;
		}
		attr = NLA_NEXT(attr, attr_len);
	}

	return -ENOENT;
}

static int register_capability(int fd, uint16_t family_id,
			       const struct capability_args *args)
{
	char txbuf[1024] = {0};
	char rxbuf[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *ghdr;
	ssize_t rxlen;
	int ret;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 2;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = KERNEL_MCP_CMD_CAPABILITY_REGISTER;
	ghdr->version = KERNEL_MCP_GENL_FAMILY_VERSION;
	ghdr->reserved = 0;

	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_ID,
		       &args->capability_id, sizeof(args->capability_id));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_NAME,
		       args->capability_name, strlen(args->capability_name) + 1);
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_PERM,
		       &args->perm, sizeof(args->perm));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_COST,
		       &args->cost, sizeof(args->cost));
	if (ret)
		return ret;
	if (args->has_capability_hash) {
		ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_HASH,
			       args->capability_hash,
			       strlen(args->capability_hash) + 1);
			if (ret)
				return ret;
	}

	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	ret = recv_nlmsg(fd, rxbuf, sizeof(rxbuf), &rxlen);
	if (ret)
		return ret;

	nlh = (struct nlmsghdr *)rxbuf;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;

	ret = parse_nl_error(nlh);
	return ret;
}

int main(int argc, char **argv)
{
	struct capability_args args;
	uint16_t family_id = 0;
	int fd;
	int ret;

	if (parse_args(argc, argv, &args)) {
		usage(argv[0]);
		return 1;
	}

	fd = open_genl_socket();
	if (fd < 0) {
		fprintf(stderr, "open_genl_socket failed: %s\n", strerror(-fd));
		return 2;
	}

	ret = resolve_family_id(fd, &family_id);
	if (ret < 0) {
		fprintf(stderr, "resolve_family_id failed: %s\n", strerror(-ret));
		close(fd);
		return 3;
	}

	ret = register_capability(fd, family_id, &args);
	if (ret < 0) {
		fprintf(stderr, "register_capability failed: %s\n", strerror(-ret));
		close(fd);
		return 4;
	}

	printf("registered capability id=%u name=%s perm=%u cost=%u",
	       args.capability_id, args.capability_name, args.perm, args.cost);
	if (args.has_capability_hash)
		printf(" hash=%s", args.capability_hash);
	printf("\n");
	close(fd);
	return 0;
}
