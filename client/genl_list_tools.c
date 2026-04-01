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

	rxlen = recv(fd, rxbuf, sizeof(rxbuf), 0);
	if (rxlen < 0)
		return -errno;
	if ((size_t)rxlen < sizeof(struct nlmsghdr))
		return -EPROTO;

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

static void print_one_tool(const struct genlmsghdr *ghdr, int payload_len)
{
	struct nlattr *attr;
	uint32_t tool_id = 0;
	uint32_t risk_flags = 0;
	uint32_t status = 0;
	char name[128] = "";
	char hash[32] = "";
	bool seen_id = false;
	bool seen_name = false;
	bool seen_risk_flags = false;
	bool seen_hash = false;

	attr = (struct nlattr *)((char *)ghdr + GENL_HDRLEN);
	while (NLA_OK(attr, payload_len)) {
		switch (attr->nla_type) {
		case KERNEL_MCP_ATTR_TOOL_ID:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t)) {
				memcpy(&tool_id, NLA_DATA(attr), sizeof(tool_id));
				seen_id = true;
			}
			break;
		case KERNEL_MCP_ATTR_TOOL_NAME: {
			size_t nlen = attr->nla_len - NLA_HDRLEN;
			if (nlen >= sizeof(name))
				nlen = sizeof(name) - 1;
			memcpy(name, NLA_DATA(attr), nlen);
			name[nlen] = '\0';
			seen_name = true;
			break;
		}
		case KERNEL_MCP_ATTR_TOOL_RISK_FLAGS:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t)) {
				memcpy(&risk_flags, NLA_DATA(attr),
				       sizeof(risk_flags));
				seen_risk_flags = true;
			}
			break;
		case KERNEL_MCP_ATTR_STATUS:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t))
				memcpy(&status, NLA_DATA(attr), sizeof(status));
			break;
		case KERNEL_MCP_ATTR_TOOL_HASH: {
			size_t hlen = attr->nla_len - NLA_HDRLEN;
			if (hlen >= sizeof(hash))
				hlen = sizeof(hash) - 1;
			memcpy(hash, NLA_DATA(attr), hlen);
			hash[hlen] = '\0';
			seen_hash = true;
			break;
		}
		default:
			break;
		}
		attr = NLA_NEXT(attr, payload_len);
	}

	if (!seen_id || !seen_name || !seen_risk_flags)
		return;

	printf("id=%u name=%s risk_flags=0x%08x status=%s", tool_id, name,
	       risk_flags, status == 1 ? "active" : "unknown");
	if (seen_hash)
		printf(" hash=%s", hash);
	printf("\n");
}

static int dump_tools(int fd, uint16_t family_id)
{
	char txbuf[512] = {0};
	char rxbuf[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *ghdr;
	uint32_t seq = 8;
	int ret;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = KERNEL_MCP_CMD_LIST_TOOLS;
	ghdr->version = KERNEL_MCP_GENL_FAMILY_VERSION;
	ghdr->reserved = 0;

	ret = send_nlmsg(fd, nlh);
	if (ret)
		return ret;

	for (;;) {
		ssize_t rxlen;
		int rem;

		rxlen = recv(fd, rxbuf, sizeof(rxbuf), 0);
		if (rxlen < 0)
			return -errno;
		if (rxlen == 0)
			return -EPIPE;

		rem = (int)rxlen;
		for (nlh = (struct nlmsghdr *)rxbuf; NLMSG_OK(nlh, rem);
		     nlh = NLMSG_NEXT(nlh, rem)) {
			if (nlh->nlmsg_seq != seq)
				continue;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				ret = parse_nl_error(nlh);
				if (ret == 0)
					continue;
				return ret;
			}
			if (nlh->nlmsg_type != family_id)
				continue;
			if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
				return -EPROTO;

			ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
			if (ghdr->cmd != KERNEL_MCP_CMD_LIST_TOOLS)
				continue;
			print_one_tool(ghdr,
				       (int)(nlh->nlmsg_len -
					     NLMSG_LENGTH(GENL_HDRLEN)));
		}
	}
}

int main(void)
{
	uint16_t family_id = 0;
	int fd;
	int ret;

	fd = open_genl_socket();
	if (fd < 0) {
		fprintf(stderr, "open_genl_socket failed: %s\n", strerror(-fd));
		return 1;
	}

	ret = resolve_family_id(fd, &family_id);
	if (ret < 0) {
		fprintf(stderr, "resolve_family_id failed: %s\n", strerror(-ret));
		close(fd);
		return 2;
	}

	printf("tools dump for family=%s id=%u\n", KERNEL_MCP_GENL_FAMILY_NAME,
	       family_id);
	ret = dump_tools(fd, family_id);
	if (ret < 0) {
		fprintf(stderr, "dump_tools failed: %s\n", strerror(-ret));
		close(fd);
		return 3;
	}

	close(fd);
	return 0;
}
