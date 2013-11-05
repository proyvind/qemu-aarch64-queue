/*
 *  AArch64 translation
 *
 *  Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "cpu.h"
#include "tcg-op.h"
#include "qemu/log.h"
#include "translate.h"
#include "qemu/host-utils.h"

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"

static TCGv_i64 cpu_X[32];
static TCGv_i64 cpu_pc;
static TCGv_i32 pstate;

static const char *regnames[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "lr", "sp"
};

/* initialize TCG globals.  */
void a64_translate_init(void)
{
    int i;

    cpu_pc = tcg_global_mem_new_i64(TCG_AREG0,
                                    offsetof(CPUARMState, pc),
                                    "pc");
    for (i = 0; i < 32; i++) {
        cpu_X[i] = tcg_global_mem_new_i64(TCG_AREG0,
                                          offsetof(CPUARMState, xregs[i]),
                                          regnames[i]);
    }

    pstate = tcg_global_mem_new_i32(TCG_AREG0,
                                    offsetof(CPUARMState, pstate),
                                    "pstate");
}

void aarch64_cpu_dump_state(CPUState *cs, FILE *f,
                            fprintf_function cpu_fprintf, int flags)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    int i;

    cpu_fprintf(f, "PC=%016"PRIx64"  SP=%016"PRIx64"\n",
            env->pc, env->xregs[31]);
    for (i = 0; i < 31; i++) {
        cpu_fprintf(f, "X%02d=%016"PRIx64, i, env->xregs[i]);
        if ((i % 4) == 3) {
            cpu_fprintf(f, "\n");
        } else {
            cpu_fprintf(f, " ");
        }
    }
    cpu_fprintf(f, "PSTATE=%c%c%c%c\n",
        env->pstate & PSTATE_N ? 'n' : '.',
        env->pstate & PSTATE_Z ? 'z' : '.',
        env->pstate & PSTATE_C ? 'c' : '.',
        env->pstate & PSTATE_V ? 'v' : '.');
    cpu_fprintf(f, "\n");
}

void gen_a64_set_pc_im(uint64_t val)
{
    tcg_gen_movi_i64(cpu_pc, val);
}

static void gen_exception(int excp)
{
    TCGv_i32 tmp = tcg_temp_new_i32();
    tcg_gen_movi_i32(tmp, excp);
    gen_helper_exception(cpu_env, tmp);
    tcg_temp_free_i32(tmp);
}

static void gen_exception_insn(DisasContext *s, int offset, int excp)
{
    gen_a64_set_pc_im(s->pc - offset);
    gen_exception(excp);
    s->is_jmp = DISAS_JUMP;
}

static void unallocated_encoding(DisasContext *s)
{
    gen_exception_insn(s, 4, EXCP_UDEF);
}

#define unsupported_encoding(s, insn)                        \
    do {                                                     \
        qemu_log_mask(LOG_UNIMP,                                        \
                      "%s:%d: unsupported instruction encoding 0x%08x", \
                      __FILE__, __LINE__, insn);                        \
        unallocated_encoding(s);                                        \
    } while (0);

/*
 * the instruction disassembly implemented here matches
 * the instruction encoding classifications in chapter 3 (C3)
 * of the ARM Architecture Reference Manual (DDI0487A_a)
 */

/* Unconditional branch (immediate) */
static void disas_uncond_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Compare & branch (immediate) */
static void disas_comp_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Test & branch (immediate) */
static void disas_test_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional branch (immediate) */
static void disas_cond_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* System */
static void disas_sys(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Exception generation */
static void disas_exc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Unconditional branch (register) */
static void disas_uncond_b_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.2 Branches, exception generating and system instructions */
static void disas_b_exc_sys(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 25, 7)) {
    case 0x0a: case 0x0b:
    case 0x4a: case 0x4b: /* Unconditional branch (immediate) */
        disas_uncond_b_imm(s, insn);
        break;
    case 0x1a: case 0x5a: /* Compare & branch (immediate) */
        disas_comp_b_imm(s, insn);
        break;
    case 0x1b: case 0x5b: /* Test & branch (immediate) */
        disas_test_b_imm(s, insn);
        break;
    case 0x2a: /* Conditional branch (immediate) */
        disas_cond_b_imm(s, insn);
        break;
    case 0x6a: /* Exception generation / System */
        if (insn & (1 << 24)) {
            disas_sys(s, insn);
        } else {
            disas_exc(s, insn);
        }
        break;
    case 0x6b: /* Unconditional branch (register) */
        disas_uncond_b_reg(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* Load/store exclusive */
static void disas_ldst_excl(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load register (literal) */
static void disas_ld_lit(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store pair (all forms) */
static void disas_ldst_pair(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store register (all forms) */
static void disas_ldst_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store multiple structures */
static void disas_ldst_multiple_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store single structure */
static void disas_ldst_single_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.3 Loads and stores */
static void disas_ldst(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 6)) {
    case 0x08: /* Load/store exclusive */
        disas_ldst_excl(s, insn);
        break;
    case 0x18: case 0x1c: /* Load register (literal) */
        disas_ld_lit(s, insn);
        break;
    case 0x28: case 0x29:
    case 0x2c: case 0x2d: /* Load/store pair (all forms) */
        disas_ldst_pair(s, insn);
        break;
    case 0x38: case 0x39:
    case 0x3c: case 0x3d: /* Load/store register (all forms) */
        disas_ldst_reg(s, insn);
        break;
    case 0x0c: /* AdvSIMD load/store multiple structures */
        disas_ldst_multiple_struct(s, insn);
        break;
    case 0x0d: /* AdvSIMD load/store single structure */
        disas_ldst_single_struct(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* PC-rel. addressing */
static void disas_pc_rel_adr(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (immediate) */
static void disas_add_sub_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Logical (immediate) */
static void disas_logic_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Move wide (immediate) */
static void disas_movw_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Bitfield */
static void disas_bitfield(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Extract */
static void disas_extract(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.4 Data processing - immediate */
static void disas_data_proc_imm(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 23, 6)) {
    case 0x20: case 0x21: /* PC-rel. addressing */
        disas_pc_rel_adr(s, insn);
        break;
    case 0x22: case 0x23: /* Add/subtract (immediate) */
        disas_add_sub_imm(s, insn);
        break;
    case 0x24: /* Logical (immediate) */
        disas_logic_imm(s, insn);
        break;
    case 0x25: /* Move wide (immediate) */
        disas_movw_imm(s, insn);
        break;
    case 0x26: /* Bitfield */
        disas_bitfield(s, insn);
        break;
    case 0x27: /* Extract */
        disas_extract(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* Logical (shifted register) */
static void disas_logic_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (extended register) */
static void disas_add_sub_ext_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (shifted register) */
static void disas_add_sub_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (3 source) */
static void disas_data_proc_3src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (with carry) */
static void disas_adc_sbc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (immediate) */
static void disas_cc_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (register) */
static void disas_cc_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional select */
static void disas_csel(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (1 source) */
static void disas_data_proc_1src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (2 source) */
static void disas_data_proc_2src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.5 Data processing - register */
static void disas_data_proc_reg(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 5)) {
    case 0x0a: /* Logical (shifted register) */
        disas_logic_reg(s, insn);
        break;
    case 0x0b: /* Add/subtract */
        if (insn & (1 << 21)) { /* (extended register) */
            disas_add_sub_ext_reg(s, insn);
        } else {
            disas_add_sub_reg(s, insn);
        }
        break;
    case 0x1b: /* Data-processing (3 source) */
        disas_data_proc_3src(s, insn);
        break;
    case 0x1a:
        switch (extract32(insn, 21, 3)) {
        case 0x0: /* Add/subtract (with carry) */
            disas_adc_sbc(s, insn);
            break;
        case 0x2: /* Conditional compare */
            if (insn & (1 << 11)) { /* (immediate) */
                disas_cc_imm(s, insn);
            } else {            /* (register) */
                disas_cc_reg(s, insn);
            }
            break;
        case 0x4: /* Conditional select */
            disas_csel(s, insn);
            break;
        case 0x6: /* Data-processing */
            if (insn & (1 << 30)) { /* (1 source) */
                disas_data_proc_1src(s, insn);
            } else {            /* (2 source) */
                disas_data_proc_2src(s, insn);
            }
            break;
        default:
            unallocated_encoding(s);
            break;
        }
    default:
        unallocated_encoding(s);
        break;
    }
}

/* C3.6 Data processing - SIMD and floating point */
static void disas_data_proc_simd_fp(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.1 A64 instruction index by encoding */
void disas_a64_insn(CPUARMState *env, DisasContext *s)
{
    uint32_t insn;

    insn = arm_ldl_code(env, s->pc, s->bswap_code);
    s->insn = insn;
    s->pc += 4;

    switch (extract32(insn, 25, 4)) {
    case 0x0: case 0x1: case 0x2: case 0x3: /* UNALLOCATED */
        unallocated_encoding(s);
        break;
    case 0x8: case 0x9: /* Data processing - immediate */
        disas_data_proc_imm(s, insn);
        break;
    case 0xa: case 0xb: /* Branch, exception generation and system insns */
        disas_b_exc_sys(s, insn);
        break;
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe:      /* Loads and stores */
        disas_ldst(s, insn);
        break;
    case 0x5:
    case 0xd:      /* Data processing - register */
        disas_data_proc_reg(s, insn);
        break;
    case 0x7:
    case 0xf:      /* Data processing - SIMD and floating point */
        disas_data_proc_simd_fp(s, insn);
        break;
    default:
        assert(FALSE); /* all 15 cases should be handled above */
        break;
    }

    if (unlikely(s->singlestep_enabled) && (s->is_jmp == DISAS_TB_JUMP)) {
        /* go through the main loop for single step */
        s->is_jmp = DISAS_JUMP;
    }
}
