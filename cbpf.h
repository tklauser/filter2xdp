/*
 * cBPF helpers, partially taken from netsniff-ng
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2009 - 2012 Daniel Borkmann.
 * Copyright (C) 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef __CBPF_H
#define __CBPF_H

#include <stdint.h>
#include <stdlib.h>

#include <linux/filter.h>

void cbpf_dump_all(struct sock_fprog *bpf);
int cbpf_validate(const struct sock_fprog *bpf);

#endif /* __CBPF_H */
