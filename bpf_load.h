/*
 * Load XDP BPF.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#ifndef __BPF_LOAD_H
#define __BPF_LOAD_H

#include <stdlib.h>

#include <linux/bpf.h>

int bpf_load_and_attach_xdp(struct bpf_insn *prog, size_t insns_cnt);

int set_link_xdp_fd(int ifindex, int fd);

#endif
