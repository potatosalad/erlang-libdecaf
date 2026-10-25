#include <decaf/spongerng.h>
#include <decaf/common.h>
#include <stdio.h>
#include <string.h>

int
main(void)
{
    const size_t lengths[] = {0, 1, 8, 31, 32, 135, 136, 137, 271, 272, 273, 2048, 4096, 65536, 65537};
    uint8_t seed[64], output[2][65537], expected[2][65537];
    decaf_keccak_prng_s states[2], reference[2];
    for (size_t i = 0; i < sizeof(seed); ++i)
        seed[i] = (uint8_t)i;
    decaf_spongerng_init_from_buffer(&states[0], seed, 17, 1);
    decaf_spongerng_init_from_buffer(&states[1], seed, 64, 1);
    memcpy(reference, states, sizeof(states));
    for (size_t round = 0; round < 256; ++round) {
        size_t length = lengths[round % (sizeof(lengths) / sizeof(lengths[0]))];
        decaf_spongerng_next2(&states[0], &states[1], output[0], output[1], length);
        for (size_t lane = 0; lane < 2; ++lane) {
            decaf_spongerng_next(&reference[lane], expected[lane], length);
            if (memcmp(output[lane], expected[lane], length) != 0 ||
                memcmp(&states[lane], &reference[lane], sizeof(states[lane])) != 0) {
                fprintf(stderr, "SpongeRNG mismatch at round %zu, lane %zu, length %zu\n", round, lane, length);
                return 1;
            }
        }
        if (round % 3 == 0) {
            decaf_spongerng_stir(&states[0], seed, round % sizeof(seed));
            decaf_spongerng_stir(&reference[0], seed, round % sizeof(seed));
        }
    }
    decaf_bzero(states, sizeof(states));
    decaf_bzero(reference, sizeof(reference));
    decaf_bzero(seed, sizeof(seed));
    decaf_bzero(output, sizeof(output));
    decaf_bzero(expected, sizeof(expected));
    puts("Paired SpongeRNG matches upstream output and complete state (256 differential cases)");
    return 0;
}
