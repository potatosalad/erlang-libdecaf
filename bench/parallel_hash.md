# Parallel hashing measurements

Build first, then compare update sizes with the same message size and worker budget:

```sh
gmake
BENCH_GIB=16 BENCH_MIB=4 elixir bench/parallel_hash_stress.exs
BENCH_GIB=16 BENCH_MIB=32 elixir bench/parallel_hash_stress.exs
BENCH_GIB=16 elixir bench/parallel_hash_sweep.exs
BENCH_GIB=16 BENCH_MIBS='16 32 64' elixir bench/parallel_hash_sweep.exs
```

The general streaming benchmarks default to 4 MiB updates. The dedicated parallel
benchmarks default to 64 MiB. The sweep covers 4, 8, 16, 32, 64 and 128 MiB.
Each scenario times complete initialization, updates and finalization, with input
storage reused. It retains one timed pass; repeat runs on an otherwise idle
machine before comparing medians. These numbers are not cold-memory bandwidth.

## Update size and native window size

These are separate settings. The native window remains capped at 4,096 leaves:
32 MiB for KT/HopMAC and 8 KiB ParallelHash blocks. A larger update spans multiple
native windows while retaining the original input binary. ParallelHash with a
different block size has a different byte window.

On an Apple M3 Max with 14 online schedulers and the ARM SHA3 backend, the update
sweep showed a broad 32–128 MiB plateau. One pass reached 34.8 GiB/s for KT128
with 64 MiB updates, while ParallelHash128 peaked at 18.8 GiB/s with 32 MiB
updates. Native windows of 2,048, 8,192 and 16,384 leaves did not establish a
consistent improvement over 4,096 across all algorithms. There is no measured
universal optimum; retain the default as a compromise and sweep on the target CPU.

## SIMD/root batching comparison

Three separate before/after runs, using 16 GiB messages for 32 MiB updates and
8 GiB messages for 4 MiB updates. Values below are median GiB/s on that M3 Max.
Both builds use the same benchmark and the same reused input storage.

| Algorithm | 32 MiB before | 32 MiB after | 4 MiB before | 4 MiB after |
| --- | ---: | ---: | ---: | ---: |
| KT128 | 30.64 | 29.57 | 18.86 | 20.33 |
| KT256 | 24.80 | 26.52 | 16.28 | 16.70 |
| HopMAC128 | 27.39 | 32.73 | 17.59 | 19.10 |
| HopMAC256 | 25.15 | 25.95 | 15.07 | 17.59 |
| ParallelHash128 | 15.97 | 17.67 | 9.85 | 11.87 |
| ParallelHash256 | 12.49 | 13.71 | 9.49 | 10.04 |

KT128's 32 MiB results varied substantially, so that comparison does not establish
an improvement. An isolated native A/B comparison showed about 8–12% higher
24-round leaf throughput from register-resident SIMD absorption. Root chaining
values are also absorbed in batches, and larger KT updates use fewer worker
wakeups. Updates below 2 MiB of leaf work retain the original fan-out.
