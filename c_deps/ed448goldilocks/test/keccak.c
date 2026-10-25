/* Differential tests of the XKCP adapters against the previous Decaf
 * permutation. The reference retains its original MIT/CC0 notices from
 * src/shake.c. Copyright (c) 2015 Cryptography Research, Inc. Uses
 * public-domain code by Mathias Panzenboeck and CC0 code by David Leon Gil.
 */
#define _DEFAULT_SOURCE 1
#include "keccak_internal.h"
#include "portable_endian.h"
#include <decaf/common.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/** Constants. **/
static const uint8_t pi[24] = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                               15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1};

#define RC_B(x, n) ((((x##ull) >> n) & 1) << ((1 << n) - 1))
#define RC_X(x)                                                                \
  (RC_B(x, 0) | RC_B(x, 1) | RC_B(x, 2) | RC_B(x, 3) | RC_B(x, 4) |            \
   RC_B(x, 5) | RC_B(x, 6))
static const uint64_t RC[24] = {
    RC_X(0x01), RC_X(0x1a), RC_X(0x5e), RC_X(0x70), RC_X(0x1f), RC_X(0x21),
    RC_X(0x79), RC_X(0x55), RC_X(0x0e), RC_X(0x0c), RC_X(0x35), RC_X(0x26),
    RC_X(0x3f), RC_X(0x4f), RC_X(0x5d), RC_X(0x53), RC_X(0x52), RC_X(0x48),
    RC_X(0x16), RC_X(0x66), RC_X(0x79), RC_X(0x58), RC_X(0x21), RC_X(0x74)};

static inline uint64_t rol(uint64_t x, int s) {
  return (x << s) | (x >> (64 - s));
}

/* Helper macros to unroll the permutation. */
#define REPEAT5(e) e e e e e
#define FOR51(v, e)                                                            \
  v = 0;                                                                       \
  REPEAT5(e; v += 1;)
#ifndef SHAKE_NO_UNROLL_LOOPS
#define FOR55(v, e)                                                            \
  v = 0;                                                                       \
  REPEAT5(e; v += 5;)
#define REPEAT24(e) e e e e e e e e e e e e e e e e e e e e e e e e
#else
#define FOR55(v, e)                                                            \
  for (v = 0; v < 25; v += 5) {                                                \
    e;                                                                         \
  }
#define REPEAT24(e)                                                            \
  {                                                                            \
    int _j = 0;                                                                \
    for (_j = 0; _j < 24; _j++) {                                              \
      e                                                                        \
    }                                                                          \
  }
#endif

/*** The Keccak-f[1600] permutation ***/
static void reference_keccakf(kdomain_t state, uint8_t start_round) {
  uint64_t *a = state->w;
  uint64_t b[5] = {0}, t, u;
  uint8_t x, y, i;

  for (i = 0; i < 25; i++)
    a[i] = le64toh(a[i]);

  for (i = start_round; i < 24; i++) {
    FOR51(x, b[x] = 0;)
    FOR55(y, FOR51(x, b[x] ^= a[x + y];))
    FOR55(y, FOR51(x, a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1);))
    // Rho and pi
    t = a[1];
    x = y = 0;
    REPEAT24(u = a[pi[x]]; y += x + 1; a[pi[x]] = rol(t, y % 64); t = u; x++;)
    // Chi
    FOR55(y, FOR51(x, b[x] = a[y + x];) FOR51(
                 x, a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);))
    // Iota
    a[0] ^= RC[i];
  }

  for (i = 0; i < 25; i++)
    a[i] = htole64(a[i]);
}

int main(void) {
  unsigned int start, sample, width, instance, lane;
  uint64_t interleaved[25 * 8] __attribute__((aligned(64)));
  kdomain_t states[8], expected[8];
  for (start = 0; start <= 24; ++start) {
    for (sample = 0; sample < 32; ++sample) {
      for (instance = 0; instance < 8; ++instance) {
        for (lane = 0; lane < 200; ++lane)
          states[instance]->b[lane] =
              (uint8_t)(lane * 29 + instance * 37 + sample * 43);
        memcpy(expected[instance], states[instance], sizeof(kdomain_t));
        reference_keccakf(expected[instance], (uint8_t)start);
      }
      kdomain_t single;
      memcpy(single, states[0], sizeof(single));
      keccakf(single, (uint8_t)start);
      if (memcmp(single, expected[0], sizeof(single))) {
        fprintf(stderr, "single permutation mismatch: start=%u sample=%u\n",
                start, sample);
        return 1;
      }
      for (width = 1; width <= 8; width *= 2) {
        for (lane = 0; lane < 25; ++lane)
          for (instance = 0; instance < width; ++instance)
            interleaved[lane * width + instance] = states[instance]->w[lane];
        decaf_keccak_permute_parallel(interleaved, width, (uint8_t)start);
        for (lane = 0; lane < 25; ++lane)
          for (instance = 0; instance < width; ++instance)
            if (interleaved[lane * width + instance] !=
                expected[instance]->w[lane]) {
              fprintf(stderr,
                      "parallel permutation mismatch: start=%u width=%u "
                      "instance=%u sample=%u\n",
                      start, width, instance, sample);
              return 1;
            }
      }
    }
  }
  decaf_bzero(interleaved, sizeof(interleaved));
  decaf_bzero(states, sizeof(states));
  decaf_bzero(expected, sizeof(expected));
  printf("%s: all 25 round counts and widths 1/2/4/8 match Decaf reference "
         "(800 cases)\n",
         decaf_keccak_backend());
  return 0;
}
