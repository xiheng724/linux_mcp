#include <errno.h>
#include <linux/genetlink.h>
#include <linux/kernel_mcp_schema.h>
#include <linux/netlink.h>
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

struct complete_args {
	char participant_id[64];
	uint32_t capability_id;
	uint64_t req_id;
	uint32_t status;
	uint32_t exec_ms;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --participant <id> --capability <u32> --req-id <u64> --status <u32> --exec-ms <u32>\n",
		prog);
}

static int parse_u32(const char *s, uint32_t *out)
{
	unsigned long v;
	char *end = NULL;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0' || v > UINT32_MAX)
		return -EINVAL;
	*out = (uint32_t)v;
	return 0;
}

static int parse_u64(const char *s, uint64_t *out)
{
	unsigned long long v;
	char *end = NULL;

	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return -EINVAL;
	*out = (uint64_t)v;
	return 0;
}

static int parse_args(int argc, char **argv, struct complete_args *args)
{
	int i;
	int seen_participant = 0;
	int seen_capability = 0;
	int seen_req = 0;
	int seen_status = 0;
	int seen_exec = 0;

	memset(args, 0, sizeof(*args));
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--participant") == 0 && i + 1 < argc) {
			size_t n = strlen(argv[++i]);
			if (n == 0 || n >= sizeof(args->participant_id))
				return -EINVAL;
			memcpy(args->participant_id, argv[i], n + 1);
			seen_participant = 1;
			continue;
		}
		if (strcmp(argv[i], "--capability") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->capability_id))
				return -EINVAL;
			seen_capability = 1;
			continue;
		}
		if (strcmp(argv[i], "--req-id") == 0 && i + 1 < argc) {
			if (parse_u64(argv[++i], &args->req_id))
				return -EINVAL;
			seen_req = 1;
			continue;
		}
		if (strcmp(argv[i], "--status") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->status))
				return -EINVAL;
			seen_status = 1;
			continue;
		}
		if (strcmp(argv[i], "--exec-ms") == 0 && i + 1 < argc) {
			if (parse_u32(argv[++i], &args->exec_ms))
				return -EINVAL;
			seen_exec = 1;
			continue;
		}
		return -EINVAL;
	}

	if (!seen_participant || !seen_capability || !seen_req || !seen_status ||
	    !seen_exec)
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
	struct nlattr *attr;
	int attr_len;
	ssize_t rxlen;
	int ret;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;

	ret = add_attr(nlh, sizeof(txbuf), CTRL_ATTR_FAMILY_NAME,
		       KERNEL_MCP_GENL_FAMILY_NAME,
		       strlen(KERNEL_MCP_GENL_FAMILY_NAME) + 1);
	if (ret)
		return ret;
	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	rxlen = recv(fd, rxbuf, sizeof(rxbuf), 0);
	if (rxlen < 0)
		return -errno;
	if ((size_t)rxlen < sizeof(struct nlmsghdr))
		return -EPROTO;

	nlh = (struct nlmsghdr *)rxbuf;
	ret = parse_nl_error(nlh);
	if (ret)
		return ret;
	if (nlh->nlmsg_type != GENL_ID_CTRL)
		return -EPROTO;
	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
		return -EPROTO;

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	attr = (struct nlattr *)((char *)ghdr + GENL_HDRLEN);
	attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));
	while (attr_len >= (int)sizeof(struct nlattr) &&
	       attr->nla_len >= sizeof(struct nlattr) &&
	       attr->nla_len <= attr_len) {
		if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
			if (attr->nla_len < NLA_HDRLEN + sizeof(uint16_t))
				return -EPROTO;
			memcpy(family_id, (char *)attr + NLA_HDRLEN,
			       sizeof(uint16_t));
			return 0;
		}
		attr_len -= NLA_ALIGN(attr->nla_len);
		attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
	}
	return -ENOENT;
}

static int send_capability_complete(int fd, uint16_t family_id,
				    const struct complete_args *args)
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
	nlh->nlmsg_seq = 41;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = KERNEL_MCP_CMD_CAPABILITY_COMPLETE;
	ghdr->version = KERNEL_MCP_GENL_FAMILY_VERSION;
	ghdr->reserved = 0;

	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_REQ_ID, &args->req_id,
		       sizeof(args->req_id));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_PARTICIPANT_ID,
		       args->participant_id, strlen(args->participant_id) + 1);
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_CAPABILITY_ID,
		       &args->capability_id, sizeof(args->capability_id));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_STATUS, &args->status,
		       sizeof(args->status));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_EXEC_MS, &args->exec_ms,
		       sizeof(args->exec_ms));
	if (ret)
		return ret;

	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	rxlen = recv(fd, rxbuf, sizeof(rxbuf), 0);
	if (rxlen < 0)
		return -errno;
	if ((size_t)rxlen < sizeof(struct nlmsghdr))
		return -EPROTO;

	nlh = (struct nlmsghdr *)rxbuf;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	return parse_nl_error(nlh);
}

int main(int argc, char **argv)
{
	struct complete_args args;
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

	ret = send_capability_complete(fd, family_id, &args);
	if (ret < 0) {
		fprintf(stderr, "capability_complete failed: %s\n", strerror(-ret));
		close(fd);
		return 4;
	}

	printf("reported capability completion req_id=%llu participant=%s capability=%u status=%u exec_ms=%u\n",
	       (unsigned long long)args.req_id, args.participant_id,
	       args.capability_id,
	       args.status, args.exec_ms);
	close(fd);
	return 0;
}
