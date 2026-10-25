# Hash and XOF throughput measurements

Measured 2026-10-25 on an Apple M3 Max with 14 online schedulers, OTP 29.1.2,
and `XKCP ARM SHA3 (x1/x2)`. Each entry is the maximum of five warmed,
alternating-order complete streaming passes through the public Erlang API.
Input storage is a reused 64 MiB zero-filled binary, allocated before timing.
Ordinary messages are 1 GiB; parallel messages are 32 GiB. ParallelHash and
ParallelHashXOF use 8192-byte blocks. Parallel worker budget is zero (drain until
idle). There is one caller; initialization, all updates, and final output are timed.

Hash outputs are the normal digest size or 32/64 bytes for strength 128/256.
Keyed constructions use a 32-byte key and 32-byte customization string.
TupleHash and TupleHashXOF treat each update as one tuple element. Small-input
outputs are checked against the ordinary one-shot APIs before measurement.

```sh
gmake
elixir bench/hash_highlights.exs
# Override message sizes and repeated passes:
BENCH_GIB=2 BENCH_PARALLEL_GIB=32 BENCH_REPEATS=7 elixir bench/hash_highlights.exs
```

Values below are decimal GB/s, retained to three decimals so that README rounding
and speedup calculations can be checked. These are warm-input measurements;
CPU placement, clock frequency, input size, and other work affect results.
HopMAC shares KT's leaf kernel, so their bulk rates are effectively equal within
measurement variation.

| Algorithm | Ordinary API GB/s | Parallel API GB/s |
| --- | ---: | ---: |
| SHA2-512 | 0.710 | — |
| SHA3-224 | 1.025 | — |
| SHA3-256 | 0.951 | — |
| SHA3-384 | 0.737 | — |
| SHA3-512 | 0.511 | — |
| SHAKE128 | 1.184 | — |
| SHAKE256 | 0.965 | — |
| cSHAKE128 | 1.176 | — |
| cSHAKE256 | 0.944 | — |
| KMAC128 | 1.180 | — |
| KMAC256 | 0.964 | — |
| KMACXOF128 | 1.184 | — |
| KMACXOF256 | 0.958 | — |
| TupleHash128 | 1.181 | — |
| TupleHash256 | 0.958 | — |
| TupleHashXOF128 | 1.186 | — |
| TupleHashXOF256 | 0.965 | — |
| ParallelHash128 | 1.158 | 20.530 |
| ParallelHash256 | 0.924 | 15.987 |
| ParallelHashXOF128 | 1.161 | 20.096 |
| ParallelHashXOF256 | 0.931 | 15.789 |
| Keccak-224 | 1.020 | — |
| Keccak-256 | 0.958 | — |
| Keccak-384 | 0.742 | — |
| Keccak-512 | 0.511 | — |
| Keccak-XOF-128 | 1.185 | — |
| Keccak-XOF-256 | 0.950 | — |
| TurboSHAKE128 | 2.457 | — |
| TurboSHAKE256 | 2.023 | — |
| KT128 | 2.410 | 40.508 |
| KT256 | 1.950 | 31.291 |
| HopMAC128 | 2.417 | 41.059 |
| HopMAC256 | 1.946 | 31.204 |
