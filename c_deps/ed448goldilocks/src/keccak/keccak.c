/* Runtime-selected XKCP permutations. The Decaf state stays canonical, with
 * little-endian lanes, so existing sponge/PRNG contexts and copies retain ABI.
 * Copyright (c) 2026 Andrew Bennett. Released under the MIT license. */
#include "config.h"
#include "keccak_internal.h"
#include <assert.h>
#include <limits.h>
#include <string.h>
#if defined(DECAF_KECCAK_SHA3) || defined(DECAF_KECCAK_X86)
#include <stdatomic.h>
#endif
#include "KeccakP-1600-plain64.h"
#include <decaf/common.h>

#if defined(DECAF_KECCAK_SHA3)
#include "KeccakP-1600-times2-SnP.h"
#if defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <asm/hwcap.h>
#include <sys/auxv.h>
#elif defined(__FreeBSD__)
#include <machine/elf.h>
#include <sys/auxv.h>
#endif
extern void KeccakP1600_v84a_permute_nrounds(void *state,
                                             const uint64_t *constants,
                                             unsigned int rounds);
extern void KeccakP1600times2_v84a_permute_nrounds(void *states,
                                                   const uint64_t *constants,
                                                   unsigned int rounds);
extern size_t KeccakP1600_ARMv8Asha3_12rounds_FastLoop_Absorb(
    void *state, unsigned int lanes, const uint8_t *input, size_t length);
extern void KT128_ARMv8Asha3_Process2Leaves(const uint8_t *input,
                                            uint8_t *output);
extern void KT256_ARMv8Asha3_Process2Leaves(const uint8_t *input,
                                            uint8_t *output);
static const uint64_t round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
#endif
#if defined(DECAF_KECCAK_X86)
#include "KeccakP-1600-AVX2.h"
#include "KeccakP-1600-AVX512.h"
#include "KeccakP-1600-times2-SIMD128.h"
#include "KeccakP-1600-times4-AVX2.h"
#include "KeccakP-1600-times8-AVX512.h"
#endif

enum { PORTABLE = 1, SHA3 = 2, SSSE3 = 4, AVX2 = 8, AVX512 = 16 };

static unsigned int cpu_features(void) {
#if !defined(DECAF_KECCAK_SHA3) && !defined(DECAF_KECCAK_X86)
  return PORTABLE;
#else
  static atomic_uint cached;
  unsigned int features = atomic_load_explicit(&cached, memory_order_relaxed);
  if (features != 0)
    return features;
  features = PORTABLE;
#if defined(DECAF_KECCAK_SHA3)
  int available = 0;
#if defined(__APPLE__)
  size_t length = sizeof(available);
  if (sysctlbyname("hw.optional.arm.FEAT_SHA3", &available, &length, NULL, 0) !=
      0) {
    length = sizeof(available);
    if (sysctlbyname("hw.optional.armv8_2_sha3", &available, &length, NULL,
                     0) != 0)
      available = 0;
  }
#elif defined(__linux__) && defined(HWCAP_SHA3)
  available = (getauxval(AT_HWCAP) & HWCAP_SHA3) != 0;
#elif defined(__FreeBSD__) && defined(HWCAP_SHA3)
  unsigned long capabilities = 0;
  if (elf_aux_info(AT_HWCAP, &capabilities, sizeof(capabilities)) == 0)
    available = (capabilities & HWCAP_SHA3) != 0;
#endif
  if (available)
    features |= SHA3;
#endif
#if defined(DECAF_KECCAK_X86)
  /* These builtins include the OSXSAVE/XCR0 checks required to use YMM/ZMM. */
  __builtin_cpu_init();
  if (__builtin_cpu_supports("ssse3"))
    features |= SSSE3;
  if (__builtin_cpu_supports("avx2"))
    features |= AVX2;
  if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl") &&
      __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("avx512dq"))
    features |= AVX512;
#endif
  atomic_store_explicit(&cached, features, memory_order_relaxed);
  return features;
#endif
}

const char *decaf_keccak_backend(void) {
  unsigned int features = cpu_features();
  if (features & SHA3)
    return "XKCP ARM SHA3 (x1/x2)";
  if (features & AVX512)
    return "XKCP AVX-512 (x1/x8)";
  if (features & AVX2)
    return "XKCP AVX2 (x1/x4)";
  if (features & SSSE3)
    return "XKCP portable64 + SSSE3 (x2)";
  return "XKCP portable64";
}

unsigned int decaf_keccak_parallelism(void) {
  unsigned int features = cpu_features();
  if (features & AVX512)
    return 8;
  if (features & AVX2)
    return 4;
  if (features & (SHA3 | SSSE3))
    return 2;
  return 1;
}

void keccakf(kdomain_t state, uint8_t start_round) {
  assert(start_round <= 24);
  if (start_round >= 24)
    return;
  unsigned int features = cpu_features();
#if defined(DECAF_KECCAK_SHA3)
  if (features & SHA3) {
    KeccakP1600_v84a_permute_nrounds(state, round_constants + start_round,
                                     24 - start_round);
    return;
  }
#endif
#if defined(DECAF_KECCAK_X86)
  if (features & AVX512) {
    KeccakP1600_AVX512_Permute_Nrounds((KeccakP1600_plain64_state *)state,
                                       24 - start_round);
    return;
  }
  if (features & AVX2) {
    KeccakP1600_AVX2_state local;
    KeccakP1600_AVX2_OverwriteBytes(&local, state->b, 0, 200);
    KeccakP1600_AVX2_Permute_Nrounds(&local, 24 - start_round);
    KeccakP1600_AVX2_ExtractBytes(&local, state->b, 0, 200);
    decaf_bzero(&local, sizeof(local));
    return;
  }
#endif
  (void)features;
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
  KeccakP1600_plain64_Permute_Nrounds((KeccakP1600_plain64_state *)state,
                                      24 - start_round);
#else
  KeccakP1600_plain64_state local;
  KeccakP1600_plain64_OverwriteBytes(&local, state->b, 0, 200);
  KeccakP1600_plain64_Permute_Nrounds(&local, 24 - start_round);
  KeccakP1600_plain64_ExtractBytes(&local, state->b, 0, 200);
  decaf_bzero(&local, sizeof(local));
#endif
}

/* Interleaved canonical little-endian lanes: state[lane * width + instance].
 * Scratch storage supplied by callers must be aligned to 64 bytes. */
void decaf_keccak_permute_parallel(uint64_t *states, unsigned int width,
                                   uint8_t start_round) {
  assert(width == 1 || width == 2 || width == 4 || width == 8);
  assert(start_round <= 24);
  if (start_round >= 24)
    return;
  unsigned int features = cpu_features();
#if defined(DECAF_KECCAK_SHA3)
  if (width == 2 && (features & SHA3)) {
    KeccakP1600times2_v84a_permute_nrounds(
        states, round_constants + start_round, 24 - start_round);
    return;
  }
#endif
#if defined(DECAF_KECCAK_X86)
  if (start_round == 0 || start_round == 12) {
    if (width == 8 && (features & AVX512)) {
      if (start_round == 0)
        KeccakP1600times8_AVX512_PermuteAll_24rounds((void *)states);
      else
        KeccakP1600times8_AVX512_PermuteAll_12rounds((void *)states);
      return;
    }
    if (width == 4 && (features & AVX2)) {
      if (start_round == 0)
        KeccakP1600times4_AVX2_PermuteAll_24rounds((void *)states);
      else
        KeccakP1600times4_AVX2_PermuteAll_12rounds((void *)states);
      return;
    }
    if (width == 2 && (features & SSSE3)) {
      if (start_round == 0)
        KeccakP1600times2_SSSE3_PermuteAll_24rounds((void *)states);
      else
        KeccakP1600times2_SSSE3_PermuteAll_12rounds((void *)states);
      return;
    }
  }
#endif
  (void)features;
  for (unsigned int instance = 0; instance < width; ++instance) {
    kdomain_t state;
    for (unsigned int lane = 0; lane < 25; ++lane)
      state->w[lane] = states[lane * width + instance];
    keccakf(state, start_round);
    for (unsigned int lane = 0; lane < 25; ++lane)
      states[lane * width + instance] = state->w[lane];
    decaf_bzero(state, sizeof(state));
  }
}

/* Only complete lanes and complete blocks enter these loops. Callers retain
 * the byte-oriented path for non-word rates and partial blocks. */
size_t decaf_keccak_absorb_blocks(kdomain_t state, unsigned int rate,
                                  uint8_t start_round, const uint8_t *input,
                                  size_t length) {
  assert(rate > 0 && rate < 200 && rate % 8 == 0);
  if (length < rate)
    return 0;
  unsigned int features = cpu_features();
#if defined(DECAF_KECCAK_X86)
  if ((start_round == 0 || start_round == 12) && (features & AVX512)) {
    if (start_round == 0)
      return KeccakF1600_AVX512_FastLoop_Absorb((void *)state, rate / 8, input,
                                                length);
    return KeccakP1600_12rounds_AVX512_FastLoop_Absorb((void *)state, rate / 8,
                                                       input, length);
  }
  if ((start_round == 0 || start_round == 12) && (features & AVX2)) {
    KeccakP1600_AVX2_state local;
    size_t consumed;
    KeccakP1600_AVX2_OverwriteBytes(&local, state->b, 0, 200);
    if (start_round == 0)
      consumed =
          KeccakF1600_AVX2_FastLoop_Absorb(&local, rate / 8, input, length);
    else
      consumed = KeccakP1600_12rounds_AVX2_FastLoop_Absorb(&local, rate / 8,
                                                           input, length);
    KeccakP1600_AVX2_ExtractBytes(&local, state->b, 0, 200);
    decaf_bzero(&local, sizeof(local));
    return consumed;
  }
#endif
#if defined(DECAF_KECCAK_SHA3)
  if (start_round == 12 && (rate == 136 || rate == 168) && (features & SHA3))
    return KeccakP1600_ARMv8Asha3_12rounds_FastLoop_Absorb(state, rate / 8,
                                                           input, length);
#endif
  (void)features;
  size_t consumed = length - length % rate;
  for (size_t offset = 0; offset < consumed; offset += rate) {
    for (unsigned int lane = 0; lane < rate / 8; ++lane) {
      uint64_t word;
      memcpy(&word, input + offset + 8 * lane, 8);
      state->w[lane] ^= word;
    }
    keccakf(state, start_round);
  }
  return consumed;
}

/* The KT-specific kernels keep both absorb and permutation state in registers.
 * Use only for contiguous complete 8192-byte leaves with the standard domains.
 */
int decaf_keccak_hash_leaves(uint8_t *const *outputs,
                             const uint8_t *const *inputs, unsigned int width,
                             unsigned int rate) {
  for (unsigned int instance = 1; instance < width; ++instance)
    if ((uintptr_t)inputs[instance] != (uintptr_t)inputs[0] + 8192 * instance)
      return 0;
  unsigned int features = cpu_features();
  uint8_t chaining[8 * 64];
  int handled = 0;
#if defined(DECAF_KECCAK_SHA3)
  if (width == 2 && (features & SHA3)) {
    if (rate == 168)
      KT128_ARMv8Asha3_Process2Leaves(inputs[0], chaining);
    else
      KT256_ARMv8Asha3_Process2Leaves(inputs[0], chaining);
    handled = 1;
  }
#endif
#if defined(DECAF_KECCAK_X86)
  if (width == 8 && (features & AVX512)) {
    if (rate == 168)
      KeccakP1600times8_AVX512_KT128ProcessLeaves(inputs[0], chaining);
    else
      KeccakP1600times8_AVX512_KT256ProcessLeaves(inputs[0], chaining);
    handled = 1;
  } else if (width == 4 && (features & AVX2)) {
    if (rate == 168)
      KeccakP1600times4_AVX2_KT128ProcessLeaves(inputs[0], chaining);
    else
      KeccakP1600times4_AVX2_KT256ProcessLeaves(inputs[0], chaining);
    handled = 1;
  }
#endif
  (void)features;
  if (handled)
    for (unsigned int instance = 0; instance < width; ++instance)
      memcpy(outputs[instance], chaining + instance * (200 - rate), 200 - rate);
  decaf_bzero(chaining, width * (200 - rate));
  return handled;
}

#if defined(DECAF_KECCAK_SHA3)
/* The imported ARM absorb loops use these helpers only for uncommon rates. */
void KeccakP1600times2_AddLanesAll(KeccakP1600times2_states *states,
                                   const unsigned char *data,
                                   unsigned int lane_count,
                                   unsigned int lane_offset) {
  uint64_t *lanes = (uint64_t *)states;
  for (unsigned int instance = 0; instance < 2; ++instance)
    for (unsigned int lane = 0; lane < lane_count; ++lane) {
      uint64_t word;
      memcpy(&word, data + 8 * ((size_t)instance * lane_offset + lane), 8);
      lanes[2 * lane + instance] ^= word;
    }
}
void KeccakP1600times2_PermuteAll_4rounds(KeccakP1600times2_states *states) {
  decaf_keccak_permute_parallel((uint64_t *)states, 2, 20);
}
void KeccakP1600times2_PermuteAll_6rounds(KeccakP1600times2_states *states) {
  decaf_keccak_permute_parallel((uint64_t *)states, 2, 18);
}
void KeccakP1600times2_PermuteAll_12rounds(KeccakP1600times2_states *states) {
  decaf_keccak_permute_parallel((uint64_t *)states, 2, 12);
}
void KeccakP1600times2_PermuteAll_24rounds(KeccakP1600times2_states *states) {
  decaf_keccak_permute_parallel((uint64_t *)states, 2, 0);
}
#endif

/* Dispatch an entire absorb loop, keeping the state in SIMD registers across
 * blocks. All streams must be contiguous equal-sized, whole-lane slices. */
size_t decaf_keccak_absorb_parallel(uint64_t *states, unsigned int width,
                                    const uint8_t *const *inputs, size_t length,
                                    unsigned int rate, uint8_t start_round) {
  if ((width != 2 && width != 4 && width != 8) || length < rate ||
      length % 8 != 0 || (rate != 136 && rate != 168) ||
      (start_round != 0 && start_round != 12) || length / 8 > UINT_MAX ||
      length > SIZE_MAX / width)
    return 0;
  for (unsigned int instance = 1; instance < width; ++instance)
    if ((uintptr_t)inputs[instance] != (uintptr_t)inputs[0] + length * instance)
      return 0;
  unsigned int features = cpu_features();
#if defined(DECAF_KECCAK_SHA3)
  if (width == 2 && (features & SHA3)) {
    if (start_round == 0)
      return KeccakF1600times2_FastLoop_Absorb((void *)states, rate / 8,
                                               length / 8, rate / 8, inputs[0],
                                               2 * length);
    return KeccakP1600times2_12rounds_FastLoop_Absorb(
        (void *)states, rate / 8, length / 8, rate / 8, inputs[0], 2 * length);
  }
#endif
#if defined(DECAF_KECCAK_X86)
  if (width == 8 && (features & AVX512)) {
    if (start_round == 0)
      return KeccakF1600times8_AVX512_FastLoop_Absorb((void *)states, rate / 8,
                                                      length / 8, rate / 8,
                                                      inputs[0], 8 * length);
    return KeccakP1600times8_12rounds_AVX512_FastLoop_Absorb(
        (void *)states, rate / 8, length / 8, rate / 8, inputs[0], 8 * length);
  }
  if (width == 4 && (features & AVX2)) {
    if (start_round == 0)
      return KeccakF1600times4_AVX2_FastLoop_Absorb((void *)states, rate / 8,
                                                    length / 8, rate / 8,
                                                    inputs[0], 4 * length);
    return KeccakP1600times4_12rounds_AVX2_FastLoop_Absorb(
        (void *)states, rate / 8, length / 8, rate / 8, inputs[0], 4 * length);
  }
  if (width == 2 && (features & SSSE3)) {
    if (start_round == 0)
      return KeccakF1600times2_SSSE3_FastLoop_Absorb((void *)states, rate / 8,
                                                     length / 8, rate / 8,
                                                     inputs[0], 2 * length);
    return KeccakP1600times2_12rounds_SSSE3_FastLoop_Absorb(
        (void *)states, rate / 8, length / 8, rate / 8, inputs[0], 2 * length);
  }
#endif
  (void)states;
  (void)features;
  return 0;
}
