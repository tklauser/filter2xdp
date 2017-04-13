/*
 * Note: Keep this in its own compilation unit as pcap.h defines its own struct
 * bpf_program and struct bpf_insns which clashes with definitions from
 * linux/bpf.h
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2013 Daniel Borkmann
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <linux/filter.h>
#include <pcap.h>

#include "cbpf.h"
#include "utils.h"

/* based on bpf_try_compile from netsniff-ng */
void filter_try_compile(const char *str, struct sock_fprog *cbpf, int link_type)
{
	int i, ret;
	const struct bpf_insn *ins;
	struct sock_filter *out;
	struct bpf_program _bpf;

	ret = pcap_compile_nopcap(65535, link_type, &_bpf, str, 1, 0xffffffff);
	if (ret < 0)
		panic("Cannot compile filter: %s\n", str);

	cbpf->len = _bpf.bf_len;
	cbpf->filter = xrealloc(cbpf->filter, cbpf->len * sizeof(*out));

	for (i = 0, ins = _bpf.bf_insns, out = cbpf->filter; i < cbpf->len;
	     ++i, ++ins, ++out) {
		out->code = ins->code;
		out->jt = ins->jt;
		out->jf = ins->jf;
		out->k = ins->k;

		if (out->code == 0x06 && out->k > 0)
			out->k = 0xFFFFFFFF;
	}

	pcap_freecode(&_bpf);

	if (cbpf_validate(cbpf) == 0)
		panic("Not a valid cBPF program!\n");
}
