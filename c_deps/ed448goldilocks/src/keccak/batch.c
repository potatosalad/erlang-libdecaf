/* Equal-length independent sponge hashes using XKCP's parallel permutations.
 * Copyright (c) 2026 Andrew Bennett. Released under the MIT license. */
#include "keccak_internal.h"
#include <assert.h>
#include <decaf/common.h>
#include <decaf/shake.h>
#include <string.h>

/* Scratch lanes are interleaved in the same canonical little-endian byte
 * representation used by Decaf. Byte addressing also works on big-endian CPUs.
 */
static void add_byte(uint64_t *state, unsigned int width, unsigned int instance,
                     size_t offset, uint8_t byte) {
  ((uint8_t *)state)[(offset / 8 * width + instance) * 8 + offset % 8] ^= byte;
}

decaf_error_t decaf_sha3_hash_parallel(uint8_t *const *outputs,
                                       size_t output_length,
                                       const uint8_t *const *inputs,
                                       size_t input_length, unsigned int width,
                                       const struct decaf_kparams_s *params) {
  if ((width != 1 && width != 2 && width != 4 && width != 8) ||
      params->rate == 0 || params->rate >= 200)
    return DECAF_FAILURE;
  decaf_error_t result =
      params->max_out != 0xff && output_length > params->max_out
          ? DECAF_FAILURE
          : DECAF_SUCCESS;
  if (input_length == 8192 && params->start_round == 12 &&
      params->pad == 0x0b && params->rate_pad == 0x80 &&
      (params->rate == 168 || params->rate == 136) &&
      output_length == (size_t)(200 - params->rate) &&
      decaf_keccak_hash_leaves(outputs, inputs, width, params->rate))
    return result;
  uint64_t state[25 * 8] __attribute__((aligned(64)));
  decaf_bzero(state, sizeof(state));
  size_t offset = 0, rate = params->rate;
  while (input_length - offset >= rate) {
    for (unsigned int instance = 0; instance < width; ++instance) {
      size_t byte = 0;
      for (; byte + 8 <= rate; byte += 8) {
        uint64_t word;
        memcpy(&word, inputs[instance] + offset + byte, 8);
        state[byte / 8 * width + instance] ^= word;
      }
      for (; byte < rate; ++byte)
        add_byte(state, width, instance, byte, inputs[instance][offset + byte]);
    }
    decaf_keccak_permute_parallel(state, width, params->start_round);
    offset += rate;
  }
  for (unsigned int instance = 0; instance < width; ++instance) {
    for (size_t byte = 0; byte < input_length - offset; ++byte)
      add_byte(state, width, instance, byte, inputs[instance][offset + byte]);
    add_byte(state, width, instance, input_length - offset, params->pad);
    add_byte(state, width, instance, rate - 1, params->rate_pad);
  }
  decaf_keccak_permute_parallel(state, width, params->start_round);
  offset = 0;
  while (offset < output_length) {
    size_t take = output_length - offset;
    if (take > rate)
      take = rate;
    for (unsigned int instance = 0; instance < width; ++instance) {
      size_t byte = 0;
      for (; byte + 8 <= take; byte += 8)
        memcpy(outputs[instance] + offset + byte,
               &state[byte / 8 * width + instance], 8);
      for (; byte < take; ++byte)
        outputs[instance][offset + byte] =
            ((uint8_t *)state)[(byte / 8 * width + instance) * 8 + byte % 8];
    }
    offset += take;
    if (offset < output_length)
      decaf_keccak_permute_parallel(state, width, params->start_round);
  }
  decaf_bzero(state, sizeof(state));
  return result;
}
