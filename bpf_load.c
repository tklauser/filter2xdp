/*
 * Load XDP BPF program.
 *
 * Based on tools/lib/bpf/bpf.c and samples/bpf/bpf_load.c in the Linux kernel
 * sources.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2013-2015 Alexei Starovoitov
 * Copyright (C) 2015 Wang Nan
 * Copyright (C) 2015 Huawei Inc.
 * Subject to the GPL, version 2.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>

#include "bpf_load.h"

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

#define BPF_LOG_BUF_SIZE 65536

static char license[128] = "GPL";
static char bpf_log_buf[BPF_LOG_BUF_SIZE];

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
			    size_t insns_cnt, const char *license,
			    uint32_t kern_version, char *log_buf, size_t log_buf_sz)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));

	attr.prog_type = type;
	attr.insn_cnt = (__u32)insns_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64(license);
	attr.kern_version = kern_version;
	if (log_buf_sz > 0) {
		attr.log_buf = ptr_to_u64(log_buf);
		attr.log_size = log_buf_sz;
		attr.log_level = 1;
	}

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

int bpf_load_and_attach_xdp(struct bpf_insn *prog, size_t insns_cnt)
{
	int ret, fd;
	struct utsname uts;
	unsigned int x, y, z;
	uint32_t kern_version;

	ret = uname(&uts);
	if (ret < 0) {
		printf("Failed to get running kernel version: %s\n", strerror(errno));
		return -1;
	}

	ret = sscanf(uts.release, "%u.%u.%u", &x, &y, &z);
	if (ret != 3) {
		printf("Failed to parse running kernel version: %s\n", uts.release);
		return -1;
	}

	kern_version = KERNEL_VERSION(x, y, z);

	fd = bpf_load_program(BPF_PROG_TYPE_XDP, prog, insns_cnt, license, kern_version,
			      bpf_log_buf, BPF_LOG_BUF_SIZE);
	if (fd < 0) {
		printf("bpf_load_and_attach_xdp() err=%d\n%s", errno, bpf_log_buf);
		return -1;
	}

	return fd;
}

int set_link_xdp_fd(int ifindex, int fd)
{
	struct sockaddr_nl sa;
	int sock, len, ret = -1;
	uint32_t seq = 0;
	char buf[4096];
	struct nlattr *nla, *nla_xdp;
	struct {
		struct nlmsghdr  nh;
		struct ifinfomsg ifinfo;
		char             attrbuf[64];
	} req;
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nh.nlmsg_type = RTM_SETLINK;
	req.nh.nlmsg_pid = 0;
	req.nh.nlmsg_seq = ++seq;
	req.ifinfo.ifi_family = AF_UNSPEC;
	req.ifinfo.ifi_index = ifindex;
	nla = (struct nlattr *)(((char *)&req)
				+ NLMSG_ALIGN(req.nh.nlmsg_len));
	nla->nla_type = NLA_F_NESTED | 43/*IFLA_XDP*/;

	nla_xdp = (struct nlattr *)((char *)nla + NLA_HDRLEN);
	nla_xdp->nla_type = 1/*IFLA_XDP_FD*/;
	nla_xdp->nla_len = NLA_HDRLEN + sizeof(int);
	memcpy((char *)nla_xdp + NLA_HDRLEN, &fd, sizeof(fd));
	nla->nla_len = NLA_HDRLEN + nla_xdp->nla_len;

	req.nh.nlmsg_len += NLA_ALIGN(nla->nla_len);

	if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		printf("recv from netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len);
	     nh = NLMSG_NEXT(nh, len)) {
		if (nh->nlmsg_pid != (uint32_t)getpid()) {
			printf("Wrong pid %d, expected %d\n",
			       nh->nlmsg_pid, getpid());
			goto cleanup;
		}
		if (nh->nlmsg_seq != seq) {
			printf("Wrong seq %d, expected %d\n",
			       nh->nlmsg_seq, seq);
			goto cleanup;
		}
		switch (nh->nlmsg_type) {
		case NLMSG_ERROR:
			err = (struct nlmsgerr *)NLMSG_DATA(nh);
			if (!err->error)
				continue;
			printf("nlmsg error %s\n", strerror(-err->error));
			goto cleanup;
		case NLMSG_DONE:
			break;
		}
	}

	ret = 0;

cleanup:
	close(sock);
	return ret;
}
