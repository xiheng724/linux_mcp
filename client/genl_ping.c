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
	if (err->error == 0)
		return 0;
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
	const char *family_name = KERNEL_MCP_GENL_FAMILY_NAME;

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = CTRL_CMD_GETFAMILY;
	ghdr->version = 1;
	ghdr->reserved = 0;

	ret = add_attr(nlh, sizeof(txbuf), CTRL_ATTR_FAMILY_NAME, family_name,
		       strlen(family_name) + 1);
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

	if (nlh->nlmsg_type == NLMSG_DONE)
		return -ENOENT;
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

static int send_ping(int fd, uint16_t family_id, uint64_t req_id,
		     const char *payload)
{
	char txbuf[1024] = {0};
	char rxbuf[8192] = {0};
	struct nlmsghdr *nlh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *ghdr;
	ssize_t rxlen;
	int ret;
	int attr_len;
	struct nlattr *attr;
	uint32_t status = UINT32_MAX;
	uint32_t payload_len_attr = UINT32_MAX;
	char echoed[512] = {0};
	uint64_t echoed_req_id = 0;
	bool seen_status = false;
	bool seen_payload = false;
	bool seen_req_id = false;
	size_t payload_len = strlen(payload);

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = 2;
	nlh->nlmsg_pid = (uint32_t)getpid();

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	ghdr->cmd = KERNEL_MCP_CMD_PING;
	ghdr->version = KERNEL_MCP_GENL_FAMILY_VERSION;
	ghdr->reserved = 0;

	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_REQ_ID, &req_id,
		       sizeof(req_id));
	if (ret)
		return ret;
	ret = add_attr(nlh, sizeof(txbuf), KERNEL_MCP_ATTR_MESSAGE, payload,
		       payload_len + 1);
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

	if (nlh->nlmsg_type != family_id)
		return -EPROTO;
	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
		return -EPROTO;

	ghdr = (struct genlmsghdr *)NLMSG_DATA(nlh);
	if (ghdr->cmd != KERNEL_MCP_CMD_PONG)
		return -EPROTO;

	attr = (struct nlattr *)((char *)ghdr + GENL_HDRLEN);
	attr_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN));

	while (NLA_OK(attr, attr_len)) {
		switch (attr->nla_type) {
		case KERNEL_MCP_ATTR_STATUS:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t)) {
				memcpy(&status, NLA_DATA(attr), sizeof(status));
				seen_status = true;
			}
			break;
		case KERNEL_MCP_ATTR_PAYLOAD_LEN:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint32_t)) {
				memcpy(&payload_len_attr, NLA_DATA(attr),
				       sizeof(payload_len_attr));
			}
			break;
		case KERNEL_MCP_ATTR_MESSAGE: {
			size_t msg_len = attr->nla_len - NLA_HDRLEN;
			if (msg_len >= sizeof(echoed))
				msg_len = sizeof(echoed) - 1;
			memcpy(echoed, NLA_DATA(attr), msg_len);
			echoed[msg_len] = '\0';
			seen_payload = true;
			break;
		}
		case KERNEL_MCP_ATTR_REQ_ID:
			if (attr->nla_len >= NLA_HDRLEN + sizeof(uint64_t)) {
				memcpy(&echoed_req_id, NLA_DATA(attr),
				       sizeof(echoed_req_id));
				seen_req_id = true;
			}
			break;
		default:
			break;
		}
		attr = NLA_NEXT(attr, attr_len);
	}

	if (!seen_status || !seen_payload || !seen_req_id)
		return -EPROTO;
	if (status != 0 || echoed_req_id != req_id)
		return -EIO;
	if (strcmp(echoed, payload) != 0)
		return -EBADE;
	if (payload_len_attr != (uint32_t)payload_len)
		return -EMSGSIZE;

	printf("PONG payload=\"%s\" req_id=%llu payload_len=%u\n", echoed,
	       (unsigned long long)echoed_req_id, payload_len_attr);
	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	uint16_t family_id = 0;
	int ret;
	const char *payload = "phase1-ping";

	if (argc > 1)
		payload = argv[1];

	fd = open_genl_socket();
	if (fd < 0) {
		fprintf(stderr, "open_genl_socket failed: %s\n", strerror(-fd));
		return 1;
	}

	ret = resolve_family_id(fd, &family_id);
	if (ret == -ENOENT) {
		fprintf(stderr,
			"family %s not found (module likely not loaded)\n",
			KERNEL_MCP_GENL_FAMILY_NAME);
		close(fd);
		return 3;
	}
	if (ret < 0) {
		fprintf(stderr, "resolve_family_id failed: %s\n", strerror(-ret));
		close(fd);
		return 2;
	}

	printf("family=%s id=%u version=%u\n", KERNEL_MCP_GENL_FAMILY_NAME,
	       family_id, KERNEL_MCP_GENL_FAMILY_VERSION);
	ret = send_ping(fd, family_id, 0x1020304050607080ULL, payload);
	if (ret < 0) {
		fprintf(stderr, "send_ping failed: %s\n", strerror(-ret));
		close(fd);
		return 4;
	}

	close(fd);
	return 0;
}

