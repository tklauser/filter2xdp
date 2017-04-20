/*
 * cBPF helpers.
 *
 * Code partially taken from netsniff-ng.
 *
 * Copyright (C) 2017 Tobias Klauser
 * Copyright (C) 2009 - 2012 Daniel Borkmann.
 * Copyright (C) 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cbpf.h"
#include "utils.h"

#ifndef BPF_MEMWORDS
# define BPF_MEMWORDS	16
#endif

#define BPF_LD_B	(BPF_LD   |    BPF_B)
#define BPF_LD_H	(BPF_LD   |    BPF_H)
#define BPF_LD_W	(BPF_LD   |    BPF_W)
#define BPF_LDX_B	(BPF_LDX  |    BPF_B)
#define BPF_LDX_W	(BPF_LDX  |    BPF_W)
#define BPF_JMP_JA	(BPF_JMP  |   BPF_JA)
#define BPF_JMP_JEQ	(BPF_JMP  |  BPF_JEQ)
#define BPF_JMP_JGT	(BPF_JMP  |  BPF_JGT)
#define BPF_JMP_JGE	(BPF_JMP  |  BPF_JGE)
#define BPF_JMP_JSET	(BPF_JMP  | BPF_JSET)
#define BPF_ALU_ADD	(BPF_ALU  |  BPF_ADD)
#define BPF_ALU_SUB	(BPF_ALU  |  BPF_SUB)
#define BPF_ALU_MUL	(BPF_ALU  |  BPF_MUL)
#define BPF_ALU_DIV	(BPF_ALU  |  BPF_DIV)
#define BPF_ALU_MOD	(BPF_ALU  |  BPF_MOD)
#define BPF_ALU_NEG	(BPF_ALU  |  BPF_NEG)
#define BPF_ALU_AND	(BPF_ALU  |  BPF_AND)
#define BPF_ALU_OR	(BPF_ALU  |   BPF_OR)
#define BPF_ALU_XOR	(BPF_ALU  |  BPF_XOR)
#define BPF_ALU_LSH	(BPF_ALU  |  BPF_LSH)
#define BPF_ALU_RSH	(BPF_ALU  |  BPF_RSH)
#define BPF_MISC_TAX	(BPF_MISC |  BPF_TAX)
#define BPF_MISC_TXA	(BPF_MISC |  BPF_TXA)

static const char *op_table[] = {
	[BPF_LD_B]	=	"ldb",
	[BPF_LD_H]	=	"ldh",
	[BPF_LD_W]	=	"ld",
	[BPF_LDX]	=	"ldx",
	[BPF_LDX_B]	=	"ldxb",
	[BPF_ST]	=	"st",
	[BPF_STX]	=	"stx",
	[BPF_JMP_JA]	=	"ja",
	[BPF_JMP_JEQ]	=	"jeq",
	[BPF_JMP_JGT]	=	"jgt",
	[BPF_JMP_JGE]	=	"jge",
	[BPF_JMP_JSET]	=	"jset",
	[BPF_ALU_ADD]	=	"add",
	[BPF_ALU_SUB]	=	"sub",
	[BPF_ALU_MUL]	=	"mul",
	[BPF_ALU_DIV]	=	"div",
	[BPF_ALU_MOD]	=	"mod",
	[BPF_ALU_NEG]	=	"neg",
	[BPF_ALU_AND]	=	"and",
	[BPF_ALU_OR]	=	"or",
	[BPF_ALU_XOR]	=	"xor",
	[BPF_ALU_LSH]	=	"lsh",
	[BPF_ALU_RSH]	=	"rsh",
	[BPF_RET]	=	"ret",
	[BPF_MISC_TAX]	=	"tax",
	[BPF_MISC_TXA]	=	"txa",
};

static const char *cbpf_dump_linux_k(uint32_t k)
{
	switch (k) {
	default:
		return "[%d]";
	case SKF_AD_OFF + SKF_AD_PROTOCOL:
		return "proto";
	case SKF_AD_OFF + SKF_AD_PKTTYPE:
		return "type";
	case SKF_AD_OFF + SKF_AD_IFINDEX:
		return "ifidx";
	case SKF_AD_OFF + SKF_AD_NLATTR:
		return "nla";
	case SKF_AD_OFF + SKF_AD_NLATTR_NEST:
		return "nlan";
	case SKF_AD_OFF + SKF_AD_MARK:
		return "mark";
	case SKF_AD_OFF + SKF_AD_QUEUE:
		return "queue";
	case SKF_AD_OFF + SKF_AD_HATYPE:
		return "hatype";
	case SKF_AD_OFF + SKF_AD_RXHASH:
		return "rxhash";
	case SKF_AD_OFF + SKF_AD_CPU:
		return "cpu";
	case SKF_AD_OFF + SKF_AD_VLAN_TAG:
		return "vlant";
	case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
		return "vlanp";
	case SKF_AD_OFF + SKF_AD_PAY_OFFSET:
		return "poff";
	}
}

static char *__cbpf_dump(const struct sock_filter bpf, int n, bool raw)
{
	int v;
	const char *fmt, *op;
	static char image[256];
	char operand[64];
	char raw_insn[64] = {};

	if (raw) {
		uint8_t r[8];
		memcpy(&r, &bpf, sizeof(r));
		snprintf(raw_insn, sizeof(raw_insn), "%02x %02x %02x %02x %02x %02x %02x %02x ",
			 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
		raw_insn[sizeof(raw_insn) - 1] = '\0';
	}

	v = bpf.k;
	switch (bpf.code) {
	default:
		op = "unimp";
		fmt = "0x%x";
		v = bpf.code;
		break;
	case BPF_RET | BPF_K:
		op = op_table[BPF_RET];
		fmt = "#0x%x";
		break;
	case BPF_RET | BPF_A:
		op = op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_LD_W | BPF_ABS:
		op = op_table[BPF_LD_W];
		fmt = cbpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_H | BPF_ABS:
		op = op_table[BPF_LD_H];
		fmt = cbpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_B | BPF_ABS:
		op = op_table[BPF_LD_B];
		fmt = cbpf_dump_linux_k(bpf.k);
		break;
	case BPF_LD_W | BPF_LEN:
		op = op_table[BPF_LD_W];
		fmt = "#len";
		break;
	case BPF_LD_W | BPF_IND:
		op = op_table[BPF_LD_W];
		fmt = "[x + %d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = op_table[BPF_LD_H];
		fmt = "[x + %d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = op_table[BPF_LD_B];
		fmt = "[x + %d]";
		break;
	case BPF_LD | BPF_IMM:
		op = op_table[BPF_LD_W];
		fmt = "#0x%x";
		break;
	case BPF_LDX | BPF_IMM:
		op = op_table[BPF_LDX];
		fmt = "#0x%x";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_ST:
		op = op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = op_table[BPF_JMP_JA];
		fmt = "%d";
		v = n + 1 + bpf.k;
		break;
	case BPF_JMP_JGT | BPF_K:
		op = op_table[BPF_JMP_JGT];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = op_table[BPF_JMP_JGE];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = op_table[BPF_JMP_JEQ];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = op_table[BPF_JMP_JSET];
		fmt = "#0x%x";
		break;
	case BPF_JMP_JGT | BPF_X:
		op = op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_X:
		op = op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = op_table[BPF_ALU_ADD];
		fmt = "#%d";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = op_table[BPF_ALU_SUB];
		fmt = "#%d";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = op_table[BPF_ALU_MUL];
		fmt = "#%d";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = op_table[BPF_ALU_DIV];
		fmt = "#%d";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = op_table[BPF_ALU_MOD];
		fmt = "#%d";
		break;
	case BPF_ALU_AND | BPF_K:
		op = op_table[BPF_ALU_AND];
		fmt = "#0x%x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = op_table[BPF_ALU_OR];
		fmt = "#0x%x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = op_table[BPF_ALU_XOR];
		fmt = "#0x%x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = op_table[BPF_ALU_LSH];
		fmt = "#%d";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = op_table[BPF_ALU_RSH];
		fmt = "#%d";
		break;
	case BPF_ALU_NEG:
		op = op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_MISC_TAX:
		op = op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	}

	snprintf(operand, sizeof(operand), fmt, v);
	operand[sizeof(operand) - 1] = '\0';
	snprintf(image, sizeof(image),
		 (BPF_CLASS(bpf.code) == BPF_JMP &&
		  BPF_OP(bpf.code) != BPF_JA) ?
		 " L%d:\t%s%s %s, L%d, L%d" : " L%d:\t%s%s %s",
		 n, raw_insn, op, operand, n + 1 + bpf.jt, n + 1 + bpf.jf);
	image[sizeof(image) - 1] = '\0';
	return image;
}

void cbpf_dump_all(struct sock_fprog *bpf, bool raw)
{
	int i;

	for (i = 0; i < bpf->len; ++i)
		printf("%s\n", __cbpf_dump(bpf->filter[i], i, raw));
}

int cbpf_validate(const struct sock_fprog *bpf)
{
	uint32_t i, from;
	const struct sock_filter *p;

	if (!bpf)
		return 0;
	if (bpf->len < 1)
		return 0;

	for (i = 0; i < bpf->len; ++i) {
		p = &bpf->filter[i];
		switch (BPF_CLASS(p->code)) {
			/* Check that memory operations use valid addresses. */
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(p->code)) {
			case BPF_IMM:
				break;
			case BPF_ABS:
			case BPF_IND:
			case BPF_MSH:
				/* There's no maximum packet data size
				 * in userland.  The runtime packet length
				 * check suffices.
				 */
				break;
			case BPF_MEM:
				if (p->k >= BPF_MEMWORDS)
					return 0;
				break;
			case BPF_LEN:
				break;
			default:
				return 0;
			}
			break;
		case BPF_ST:
		case BPF_STX:
			if (p->k >= BPF_MEMWORDS)
				return 0;
			break;
		case BPF_ALU:
			switch (BPF_OP(p->code)) {
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_OR:
			case BPF_XOR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_NEG:
				break;
			case BPF_DIV:
			case BPF_MOD:
				/* Check for constant division by 0 (undefined
				 * for div and mod).
				 */
				if (BPF_RVAL(p->code) == BPF_K && p->k == 0)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_JMP:
			/* Check that jumps are within the code block,
			 * and that unconditional branches don't go
			 * backwards as a result of an overflow.
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we assume that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * assume that BPF_MAXINSNS is < the maximum size
			 * of a u_int, so that i + 1 doesn't overflow.
			 *
			 * For userland, we don't know that the from
			 * or len are <= BPF_MAXINSNS, but we know that
			 * from <= len, and, except on a 64-bit system,
			 * it's unlikely that len, if it truly reflects
			 * the size of the program we've been handed,
			 * will be anywhere near the maximum size of
			 * a u_int.  We also don't check for backward
			 * branches, as we currently support them in
			 * userland for the protochain operation.
			 */
			from = i + 1;
			switch (BPF_OP(p->code)) {
			case BPF_JA:
				if (from + p->k >= bpf->len)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= bpf->len ||
				    from + p->jf >= bpf->len)
					return 0;
				break;
			default:
				return 0;
			}
			break;
		case BPF_RET:
			break;
		case BPF_MISC:
			break;
		}
	}

	return BPF_CLASS(bpf->filter[bpf->len - 1].code) == BPF_RET;
}
