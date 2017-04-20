/*
 * eBPF helpers
 *
 * Copyright (C) 2017 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/bpf.h>

#include "ebpf.h"
#include "utils.h"

#define BPF_OP_INDEX(x)		(BPF_OP(x) >> 4)
#define BPF_SIZE_INDEX(x)	(BPF_SIZE(x) >> 3)

static const char *const class_tbl[] = {
	[BPF_LD]	= "ld",
	[BPF_LDX]	= "ldx",
	[BPF_ST]	= "st",
	[BPF_STX]	= "stx",
	[BPF_ALU]	= "alu",
	[BPF_JMP]	= "jmp",
	[BPF_RET]	= "ret",
	[BPF_MISC]	= "alu64",
};

static const char *const alu_op_tbl[16] = {
	[BPF_ADD >> 4]	= "add",
	[BPF_SUB >> 4]	= "sub",
	[BPF_MUL >> 4]	= "mul",
	[BPF_DIV >> 4]	= "div",
	[BPF_OR >> 4]	= "or",
	[BPF_AND >> 4]	= "and",
	[BPF_LSH >> 4]	= "lsh",
	[BPF_RSH >> 4]	= "rsh",
	[BPF_NEG >> 4]	= "neg",
	[BPF_MOD >> 4]	= "mod",
	[BPF_XOR >> 4]	= "xor",
	[BPF_MOV >> 4]  = "mov",
	[BPF_ARSH >> 4] = "arsh",
	[BPF_END >> 4]  = "endian",
};

static const char *const size_tbl[] = {
	[BPF_W >> 3]	= "w",
	[BPF_H >> 3]	= "h",
	[BPF_B >> 3]	= "b",
	[BPF_DW >> 3]	= "dw",
};

static const char *const jump_tbl[16] = {
	[BPF_JA >> 4]	= "ja",
	[BPF_JEQ >> 4]	= "jeq",
	[BPF_JGT >> 4]	= "jgt",
	[BPF_JGE >> 4]	= "jge",
	[BPF_JSET >> 4] = "jset",
	[BPF_JNE >> 4]	= "jne",
	[BPF_JSGT >> 4]	= "jsgt",
	[BPF_JSGE >> 4]	= "jsge",
	[BPF_CALL >> 4] = "call",
	[BPF_EXIT >> 4]	= "exit",
};

/* TODO: disassemble all possible eBPF insns */
static void __ebpf_dump(const struct bpf_insn insn, size_t n, bool raw)
{
	const char *op, *postfix = "";
	uint8_t cls = BPF_CLASS(insn.code);

	printf(" L%zu:\t", n);

	if (raw) {
		uint8_t r[8];
		int i;
		memcpy(&r, &insn, sizeof(r));
		for (i = 0; i < 8; i++)
			printf("%02x ", r[i]);
	}

	switch (cls) {
	default:
		printf("unimp 0x%x // class: %s\n", insn.code, class_tbl[cls]);
		break;
	case BPF_ALU:
		postfix = "32";
		/* fall through */
	case BPF_ALU64:
		op = alu_op_tbl[BPF_OP_INDEX(insn.code)];
		if (BPF_SRC(insn.code) == BPF_X)
			printf("%s%s r%u, r%u\n", op, postfix, insn.dst_reg, insn.src_reg);
		else
			printf("%s%s r%u, #0x%x\n", op, postfix, insn.dst_reg, insn.imm);
		break;
	case BPF_LD:
		op = "ld";
		postfix = size_tbl[BPF_SIZE_INDEX(insn.code)];
		if (BPF_MODE(insn.code) == BPF_IMM)
			printf("%s%s r%d, #0x%x\n", op, postfix, insn.dst_reg, insn.imm);
		else if (BPF_MODE(insn.code) == BPF_ABS)
			printf("%s%s r%d, [%d]\n", op, postfix, insn.dst_reg, insn.imm);
		else if (BPF_MODE(insn.code) == BPF_IND)
			printf("%s%s r%d, [r%u + %d]\n", op, postfix, insn.dst_reg, insn.src_reg, insn.imm);
		else
			printf("// BUG: LD opcode 0x%02x in eBPF insns\n", insn.code);
		break;
	case BPF_LDX:
		op = "ldx";
		postfix = size_tbl[BPF_SIZE_INDEX(insn.code)];
		printf("%s%s r%d, [r%u + %d]\n", op, postfix, insn.dst_reg, insn.src_reg, insn.off);
		break;
#define L(pc, off)	((int)(pc) + 1 + (off))
	case BPF_JMP:
		op = jump_tbl[BPF_OP_INDEX(insn.code)];
		bug_on(op == NULL);
		if (BPF_OP(insn.code) == BPF_JA)
			printf("%s L%d\n", op, L(n, insn.off));
		else if (BPF_OP(insn.code) == BPF_EXIT)
			printf("%s\n", op);
		else
			printf("%s r%u, #0x%x, L%d\n", op, insn.dst_reg,
			       insn.imm, L(n, insn.off));
		break;
	case BPF_RET:
		printf("// BUG: RET opcode 0x%02x in eBPF insns\n", insn.code);
		break;
	}
}

void ebpf_dump_all(struct bpf_insn *bpf, size_t len, bool raw)
{
	size_t i;

	for (i = 0; i < len; ++i)
		__ebpf_dump(bpf[i], i, raw);
}
