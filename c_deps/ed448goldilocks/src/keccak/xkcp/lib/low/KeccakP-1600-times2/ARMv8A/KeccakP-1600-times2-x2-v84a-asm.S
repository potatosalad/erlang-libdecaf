// Adapted 2026-10-25: round count supplied in x2; round loop unchanged.
// Keccak-p[1600]x2 permutation for AArch64 using the ARMv8.4-A SHA3
// instructions (eor3/rax1/xar/bcax), processing two parallel states.
//
// The 24-round computation kernel is the verified implementation from
// mlkem-native (keccak_f1600_x2_v84a_aarch64_asm.S), itself derived from:
//
//   [HYBRID] Hybrid scalar/vector implementations of Keccak and SPHINCS+ on AArch64
//            Becker, Kannwischer, https://eprint.iacr.org/2022/1243
//
// The mlkem routine takes two *sequential* states (state0[25], state1[25]) and
// interleaves/deinterleaves them on load/store. XKCP's Keccak-p[1600]x2 instead
// stores the two states already interleaved as 25 consecutive 128-bit lanes
// (uint64x2_t A[25], with A[i] = { state0 lane i, state1 lane i }) -- which is
// exactly the in-register form the kernel operates on. We therefore load/store
// those 25 vectors directly and leave the verified round loop unchanged.
//
// Original authors: Hanno Becker <hanno.becker@arm.com>,
//                   Matthias Kannwischer <matthias@kannwischer.eu>
//
// SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
// Copyright (c) The mlkem-native project authors
// Copyright (c) 2021-2022 Arm Limited
// Copyright (c) 2022 Matthias Kannwischer
//
// void KeccakP1600times2_v84a_permute_nrounds(void *statesAsLanes /*x0*/,
//                                       const uint64_t *rc /*x1*/)

#if defined(__ARM_FEATURE_SHA3)

#if defined(__APPLE__)
#  define XKCP_SYM(name) _##name
#else
#  define XKCP_SYM(name) name
#endif

.text
.balign 4
.global XKCP_SYM(KeccakP1600times2_v84a_permute_nrounds)
#if defined(__ELF__)
.type XKCP_SYM(KeccakP1600times2_v84a_permute_nrounds), %function
#endif
XKCP_SYM(KeccakP1600times2_v84a_permute_nrounds):

        .cfi_startproc
        sub sp, sp, #0x40
        .cfi_adjust_cfa_offset 0x40
        stp d8, d9, [sp]
        .cfi_rel_offset d8, 0x0
        .cfi_rel_offset d9, 0x8
        stp d10, d11, [sp, #0x10]
        .cfi_rel_offset d10, 0x10
        .cfi_rel_offset d11, 0x18
        stp d12, d13, [sp, #0x20]
        .cfi_rel_offset d12, 0x20
        .cfi_rel_offset d13, 0x28
        stp d14, d15, [sp, #0x30]
        .cfi_rel_offset d14, 0x30
        .cfi_rel_offset d15, 0x38

        // Load the 25 interleaved state vectors A[0..24] (400 bytes) into v0..v24.
        ldp q0, q1, [x0, #0x000]
        ldp q2, q3, [x0, #0x020]
        ldp q4, q5, [x0, #0x040]
        ldp q6, q7, [x0, #0x060]
        ldp q8, q9, [x0, #0x080]
        ldp q10, q11, [x0, #0x0a0]
        ldp q12, q13, [x0, #0x0c0]
        ldp q14, q15, [x0, #0x0e0]
        ldp q16, q17, [x0, #0x100]
        ldp q18, q19, [x0, #0x120]
        ldp q20, q21, [x0, #0x140]
        ldp q22, q23, [x0, #0x160]
        ldr q24, [x0, #0x180]

Lkeccak_f1600_x2_v84a_xkcp_loop:
        eor3 v30.16b, v0.16b, v5.16b, v10.16b
        eor3 v29.16b, v1.16b, v6.16b, v11.16b
        eor3 v28.16b, v2.16b, v7.16b, v12.16b
        eor3 v27.16b, v3.16b, v8.16b, v13.16b
        eor3 v26.16b, v4.16b, v9.16b, v14.16b
        eor3 v30.16b, v30.16b, v15.16b, v20.16b
        eor3 v29.16b, v29.16b, v16.16b, v21.16b
        eor3 v28.16b, v28.16b, v17.16b, v22.16b
        eor3 v27.16b, v27.16b, v18.16b, v23.16b
        eor3 v26.16b, v26.16b, v19.16b, v24.16b
        rax1 v25.2d, v30.2d, v28.2d
        rax1 v28.2d, v28.2d, v26.2d
        rax1 v26.2d, v26.2d, v29.2d
        rax1 v29.2d, v29.2d, v27.2d
        rax1 v27.2d, v27.2d, v30.2d
        eor v30.16b, v0.16b, v26.16b
        xar v0.2d, v2.2d, v29.2d, #0x2
        xar v2.2d, v12.2d, v29.2d, #0x15
        xar v12.2d, v13.2d, v28.2d, #0x27
        xar v13.2d, v19.2d, v27.2d, #0x38
        xar v19.2d, v23.2d, v28.2d, #0x8
        xar v23.2d, v15.2d, v26.2d, #0x17
        xar v15.2d, v1.2d, v25.2d, #0x3f
        xar v1.2d, v8.2d, v28.2d, #0x9
        xar v8.2d, v16.2d, v25.2d, #0x13
        xar v16.2d, v7.2d, v29.2d, #0x3a
        xar v7.2d, v10.2d, v26.2d, #0x3d
        xar v10.2d, v3.2d, v28.2d, #0x24
        xar v3.2d, v18.2d, v28.2d, #0x2b
        xar v18.2d, v17.2d, v29.2d, #0x31
        xar v17.2d, v11.2d, v25.2d, #0x36
        xar v11.2d, v9.2d, v27.2d, #0x2c
        xar v9.2d, v22.2d, v29.2d, #0x3
        xar v22.2d, v14.2d, v27.2d, #0x19
        xar v14.2d, v20.2d, v26.2d, #0x2e
        xar v20.2d, v4.2d, v27.2d, #0x25
        xar v4.2d, v24.2d, v27.2d, #0x32
        xar v24.2d, v21.2d, v25.2d, #0x3e
        xar v21.2d, v5.2d, v26.2d, #0x1c
        xar v27.2d, v6.2d, v25.2d, #0x14
        ld1r { v31.2d }, [x1], #8
        bcax v5.16b, v10.16b, v7.16b, v11.16b
        bcax v6.16b, v11.16b, v8.16b, v7.16b
        bcax v7.16b, v7.16b, v9.16b, v8.16b
        bcax v8.16b, v8.16b, v10.16b, v9.16b
        bcax v9.16b, v9.16b, v11.16b, v10.16b
        bcax v10.16b, v15.16b, v12.16b, v16.16b
        bcax v11.16b, v16.16b, v13.16b, v12.16b
        bcax v12.16b, v12.16b, v14.16b, v13.16b
        bcax v13.16b, v13.16b, v15.16b, v14.16b
        bcax v14.16b, v14.16b, v16.16b, v15.16b
        bcax v15.16b, v20.16b, v17.16b, v21.16b
        bcax v16.16b, v21.16b, v18.16b, v17.16b
        bcax v17.16b, v17.16b, v19.16b, v18.16b
        bcax v18.16b, v18.16b, v20.16b, v19.16b
        bcax v19.16b, v19.16b, v21.16b, v20.16b
        bcax v20.16b, v0.16b, v22.16b, v1.16b
        bcax v21.16b, v1.16b, v23.16b, v22.16b
        bcax v22.16b, v22.16b, v24.16b, v23.16b
        bcax v23.16b, v23.16b, v0.16b, v24.16b
        bcax v24.16b, v24.16b, v1.16b, v0.16b
        bcax v0.16b, v30.16b, v2.16b, v27.16b
        bcax v1.16b, v27.16b, v3.16b, v2.16b
        bcax v2.16b, v2.16b, v4.16b, v3.16b
        bcax v3.16b, v3.16b, v30.16b, v4.16b
        bcax v4.16b, v4.16b, v27.16b, v30.16b
        eor v0.16b, v0.16b, v31.16b
        sub x2, x2, #0x1
        cbnz x2, Lkeccak_f1600_x2_v84a_xkcp_loop

        // Store the 25 interleaved state vectors back to A[0..24].
        stp q0, q1, [x0, #0x000]
        stp q2, q3, [x0, #0x020]
        stp q4, q5, [x0, #0x040]
        stp q6, q7, [x0, #0x060]
        stp q8, q9, [x0, #0x080]
        stp q10, q11, [x0, #0x0a0]
        stp q12, q13, [x0, #0x0c0]
        stp q14, q15, [x0, #0x0e0]
        stp q16, q17, [x0, #0x100]
        stp q18, q19, [x0, #0x120]
        stp q20, q21, [x0, #0x140]
        stp q22, q23, [x0, #0x160]
        str q24, [x0, #0x180]

        ldp d8, d9, [sp]
        .cfi_restore d8
        .cfi_restore d9
        ldp d10, d11, [sp, #0x10]
        .cfi_restore d10
        .cfi_restore d11
        ldp d12, d13, [sp, #0x20]
        .cfi_restore d12
        .cfi_restore d13
        ldp d14, d15, [sp, #0x30]
        .cfi_restore d14
        .cfi_restore d15
        add sp, sp, #0x40
        .cfi_adjust_cfa_offset -0x40
        ret
        .cfi_endproc

#if defined(__ELF__)
.size XKCP_SYM(KeccakP1600times2_v84a_permute_nrounds), .-XKCP_SYM(KeccakP1600times2_v84a_permute_nrounds)
#endif

#endif /* __ARM_FEATURE_SHA3 */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
