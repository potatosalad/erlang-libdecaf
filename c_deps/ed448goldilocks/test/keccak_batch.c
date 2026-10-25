/* Parallel sponge, KT leaf-kernel, unaligned input and boundary regressions. */
#include "keccak_internal.h"
#include <decaf/common.h>
#include <decaf/shake.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t input[8 * 20001 + 1], output[8][337], reference[337];
  const uint8_t *inputs[8];
  uint8_t *outputs[8];
  const unsigned int rates[] = {7, 8, 9, 72, 104, 136, 144, 168};
  const unsigned int rounds[] = {0, 1, 12, 23};
  const size_t lengths[] = {0,   1,   7,   8,   71,   72,   135,  136,
                            137, 167, 168, 169, 8191, 8192, 8193, 20000};
  for (size_t byte = 0; byte < sizeof(input); ++byte)
    input[byte] = (uint8_t)(byte * 31 + byte / 17);
  for (size_t r = 0; r < sizeof(rates) / sizeof(rates[0]); ++r)
    for (size_t n = 0; n < sizeof(rounds) / sizeof(rounds[0]); ++n)
      for (unsigned int width = 1; width <= 8; width *= 2)
        for (size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l)
          for (unsigned int separate = 0; separate < 2; ++separate) {
            size_t length = lengths[l];
            decaf_kparams_s params = {
                0,    'A',  rates[r], rounds[n], rounds[n] == 12 ? 0x0b : 0x1f,
                0x80, 0xff, 0xff};
            size_t output_length =
                length == 8192 ? 200 - rates[r] : sizeof(reference);
            for (unsigned int instance = 0; instance < width; ++instance) {
              inputs[instance] = input + 1 + instance * (length + separate);
              outputs[instance] = output[instance];
            }
            if (decaf_sha3_hash_parallel(outputs, output_length, inputs, length,
                                         width, &params) != DECAF_SUCCESS)
              return 1;
            for (unsigned int instance = 0; instance < width; ++instance) {
              decaf_keccak_sponge_t sponge;
              decaf_sha3_init(sponge, &params);
              /* Feed irregular chunks to exercise prefix/bulk/suffix
               * transitions. */
              size_t prefix = length < 13 ? length : 13;
              decaf_sha3_update(sponge, inputs[instance], prefix);
              decaf_sha3_update(sponge, inputs[instance] + prefix,
                                length - prefix);
              decaf_sha3_output(sponge, reference, output_length);
              decaf_sha3_destroy(sponge);
              if (memcmp(outputs[instance], reference, output_length)) {
                fprintf(stderr,
                        "batch mismatch: rate=%u start=%u width=%u length=%zu "
                        "separate=%u instance=%u\n",
                        rates[r], rounds[n], width, length, separate, instance);
                return 1;
              }
            }
          }
  decaf_bzero(input, sizeof(input));
  decaf_bzero(output, sizeof(output));
  decaf_bzero(reference, sizeof(reference));
  puts("Parallel sponge and KT kernels match streaming results at all "
       "rate/block boundaries");
  return 0;
}
