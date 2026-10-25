# XKCP Keccak backends

Vendored from https://github.com/XKCP/XKCP at
`4affab454735d54e78156880b3b44e38dcbf765c` (2026-10-25).
`SHA256SUMS` records the original files before the adaptations below.
The original notices and complete upstream license are retained in `LICENSE`.

Only Keccak-p[1600] low-level backends and their dependencies are included.
The existing Decaf sponge, PRNG, and context representation are retained.
The adapter in the parent directory uses thread-safe runtime CPU detection;
instruction-set flags apply only to the corresponding backend objects.

Two ARM SHA3 assembly files have been renamed `.S` for preprocessing and their
`permute24` symbols renamed `permute_nrounds`. The hardcoded `mov x2, #24`
is removed: the caller supplies the round count and matching round-constant
suffix. The permutation round bodies are unchanged. This also accelerates
12-round TurboSHAKE/KangarooTwelve, rather than falling back to scalar code.
These adaptations are tested against the original portable permutation for
every round count, including zero, and for independent interleaved states.

The AVX2/AVX-512 assembly fast loops select Mach-O calls without the ELF-only
`@PLT` suffix when `old_gas_syntax` is enabled (the existing XKCP macOS flag).

CMake option `ENABLE_KECCAK_OPTIMIZATIONS=OFF` builds only portable C.
On unsupported CPUs/operating systems runtime detection retains portable C.
Keccak states keep their existing byte order and alignment requirements.
