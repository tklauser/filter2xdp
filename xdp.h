/*
 * XDP definitions.
 *
 * Based on tools/include/uapi/bpf.h in the Linux kernel sources.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2011-2014 PLUMgrid, http://plumgrid.com
 * Subject to the GPL, version 2.
 */

#ifndef __XDP_H
#define __XDP_H

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will result
 * in packet drop.
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
};

#endif /* __XDP_H */
