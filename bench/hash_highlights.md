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

Values below use decimal MB/s for the ordinary API and GB/s for the parallel API, retained to three decimals so that README rounding
and speedup calculations can be checked. These are warm-input measurements;
CPU placement, clock frequency, input size, and other work affect results.
HopMAC shares KT's leaf kernel, so their bulk rates are effectively equal within
measurement variation.

| Algorithm | Ordinary API MB/s | Parallel API GB/s |
| --- | ---: | ---: |
| SHA2-512 | 710.000 | — |
| SHA3-224 | 1025.000 | — |
| SHA3-256 | 951.000 | — |
| SHA3-384 | 737.000 | — |
| SHA3-512 | 511.000 | — |
| SHAKE128 | 1184.000 | — |
| SHAKE256 | 965.000 | — |
| cSHAKE128 | 1176.000 | — |
| cSHAKE256 | 944.000 | — |
| KMAC128 | 1180.000 | — |
| KMAC256 | 964.000 | — |
| KMACXOF128 | 1184.000 | — |
| KMACXOF256 | 958.000 | — |
| TupleHash128 | 1181.000 | — |
| TupleHash256 | 958.000 | — |
| TupleHashXOF128 | 1186.000 | — |
| TupleHashXOF256 | 965.000 | — |
| ParallelHash128 | 1158.000 | 20.530 |
| ParallelHash256 | 924.000 | 15.987 |
| ParallelHashXOF128 | 1161.000 | 20.096 |
| ParallelHashXOF256 | 931.000 | 15.789 |
| Keccak-224 | 1020.000 | — |
| Keccak-256 | 958.000 | — |
| Keccak-384 | 742.000 | — |
| Keccak-512 | 511.000 | — |
| Keccak-XOF-128 | 1185.000 | — |
| Keccak-XOF-256 | 950.000 | — |
| TurboSHAKE128 | 2457.000 | — |
| TurboSHAKE256 | 2023.000 | — |
| KT128 | 2410.000 | 40.508 |
| KT256 | 1950.000 | 31.291 |
| HopMAC128 | 2417.000 | 41.059 |
| HopMAC256 | 1946.000 | 31.204 |
