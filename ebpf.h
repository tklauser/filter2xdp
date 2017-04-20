/*
 * eBPF helpers.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#ifndef __EBPF_H
#define __EBPF_H

#include <stdbool.h>
#include <stdlib.h>

#include <linux/bpf.h>

void ebpf_dump_all(struct bpf_insn *bpf, size_t len, bool raw);

#endif /* __EBPF_H */
