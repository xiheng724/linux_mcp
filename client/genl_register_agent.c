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

struct participant_args {
	char id[64];
	uint32_t participant_type;
	uint64_t req_id;
};

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s --id <participant_id> [--type planner|broker]\n",
		prog);
}

static int parse_participant_type(const char *value, uint32_t *out)
{
	if (strcmp(value, "planner") == 0) {
		*out = KERNEL_MCP_PARTICIPANT_TYPE_PLANNER;
		return 0;
	}
	if (strcmp(value, "broker") == 0) {
		*out = KERNEL_MCP_PARTICIPANT_TYPE_BROKER;
		return 0;
	}
	return -EINVAL;
}

static int parse_args(int argc, char **argv, struct participant_args *args)
{
	int i;
	int seen_id = 0;

	memset(args, 0, sizeof(*args));
	args->req_id = 1;
	args->participant_type = KERNEL_MCP_PARTICIPANT_TYPE_PLANNER;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
			size_t n = strlen(argv[++i]);
			if (n == 0 || n >= sizeof(args->id))
				return -EINVAL;
			memcpy(args->id, argv[i], n + 1);
			seen_id = 1;
			continue;
		}
		if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
			if (parse_participant_type(argv[++i], &args->participant_type))
				return -EINVAL;
			continue;
		}
		return -EINVAL;
	}

	return seen_id ? 0 : -EINVAL;
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
	return (size_t)sent == nlh->nlmsg_len ? 0 : -EIO;
}

static int recv_nlmsg(int fd, char *buf, size_t len, ssize_t *out_len)
{
	ssize_t n = recv(fd, buf, len, 0);
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

	ret = recv_nlmsg(fd, rxbuf, sizeof(rxbuf), &rxlen);
	if (ret)
		return ret;

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

static int register_participant(int fd, uint16_t family_id,
				const struct participant_args *args)
{
	char txbuf[1024] = {0};
	char rxbuf[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *ghdr;
	ssize_t rxlen;
	uint32_t pid = (uint32_t)getpid();
	uint32_t uid = (uint32_t)getuid();
	int ret;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = 2;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = KERNEL_MCP_CMD_PARTICIPANT_REGISTER;
	ghdr->version = KERNEL_MCP_GENL_FAMILY_VERSION;

	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_AGENT_ID, args->id,
		       strlen(args->id) + 1);
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_PID, &pid, sizeof(pid));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_UID, &uid, sizeof(uid));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_REQ_ID, &args->req_id,
		       sizeof(args->req_id));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_PARTICIPANT_TYPE,
		       &args->participant_type, sizeof(args->participant_type));
	if (ret)
		return ret;

	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	ret = recv_nlmsg(fd, rxbuf, sizeof(rxbuf), &rxlen);
	if (ret)
		return ret;

	nlh = (struct nlmsghdr *)rxbuf;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	return parse_nl_error(nlh);
}

int main(int argc, char **argv)
{
	struct participant_args args;
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

	ret = register_participant(fd, family_id, &args);
	if (ret < 0) {
		fprintf(stderr, "register_participant failed: %s\n", strerror(-ret));
		close(fd);
		return 4;
	}

	printf("registered participant id=%s type=%s pid=%u\n", args.id,
	       args.participant_type == KERNEL_MCP_PARTICIPANT_TYPE_BROKER ?
		       "broker" :
		       "planner",
	       (uint32_t)getpid());
	close(fd);
	return 0;
}
