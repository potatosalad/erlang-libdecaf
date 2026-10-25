# Changelog

## 3.0.0 (????-??-??)

* Fixes
  * Retry temporary parallel absorb startup failures without restarting routers or losing pending wakeups.
  * Fix ARM64 architecture detection on macOS to use the generic 64-bit implementation.
  * Erase temporary Ed25519 and Ed448 keypairs before returning mismatch errors.
  * Preserve legacy Keccak support in the NIF using the upstream sponge API.
  * Fix native dependency ordering and rebuilds, and update macOS linking flags.
  * Fix empty-message null-pointer contract violations in the vendored EdDSA and SHA-512 wrappers.
* Library Support
  * 3GPP TUAK TOPc derivation and f1, f1*, f2, f3, f4, f5, f5* authentication and key-generation functions, including combined f2345, both key sizes, all specified output lengths, and configurable Keccak iterations.
    * Dedicated `libdecaf_tuak` API and `tuak_*` NIF functions, tested against all TUAK sets from TS 35.232 and TS 35.233 Release 19.
  * SP 800-185 KMAC, TupleHash, and ParallelHash at strengths 128 and 256, including their XOF variants, all 36 NIST sample vectors, and all 18 KMAC vectors from draft-ietf-ipsecme-sha3-02.
  * RFC 9861 HopMAC128 and HopMAC256 with keyed Hash and XOF lifecycles.
  * RFC 9861 KangarooTwelve KT128 and KT256 with one-shot and incremental customization support.
  * RFC 9861 TurboSHAKE128 and TurboSHAKE256 with configurable domain separation bytes.
  * cSHAKE128 and cSHAKE256 with SP 800-185 function-name and customization strings.
    * `libdecaf:xof/3` and `libdecaf:xof_init/1`, using `cshake128` or `cshake256`.
  * Original Keccak-XOF-128 and Keccak-XOF-256 through `libdecaf:xof/3` and the incremental XOF API.
    * Algorithm names: `keccakxof_128` and `keccakxof_256`.
  * Native streaming Ed25519ph and Ed448ph signing and verification with immutable, algorithm-specific resources.
    * `ed25519ph_*` and `ed448ph_*` functions on the NIF and respective curve modules.
    * Separate `*_keypair_sign_init/1,2` and `*_sign_init/1,2` constructors for native keypairs and encoded seed/public key pairs, with shared signing update/final functions.
    * Native state retains the keypair and context; large prehash updates yield and cancelled updates release their private state.
  * Ristretto255 and Decaf448 prime-order groups.
    * `libdecaf_ristretto255` and `libdecaf_decaf448` point and scalar APIs.
    * Uniform byte mapping and precomputed multiplication.
* Enhancements
  * Add parallel Hash and XOF APIs for KT, HopMAC, and ParallelHash with retained input slices, bulk native queues, ordered chaining-value assembly, and caller cancellation.
    * Configure worker budgets through `parallel_absorb(RouterNumber, MaxRounds)` or the `parallel_absorb_rounds` application option; zero drains until empty.
    * Batch pairs of leaves with SIMD, coalesce completion notifications, and size worker fan-outs to amortize scheduling costs.
    * Reuse registered absorb workers, steal queued work in short batches, and grow dispatch storage with input up to 4096 leaves. The calling dirty scheduler computes a share of the leaves; bounded root collection runs on normal schedulers.
    * Queue spans of 16 leaves to reduce resource references and completion atomics; retain exact worker leaf budgets when splitting jobs and safely retire legacy queues on NIF upgrades.
  * Add scheduler-numbered parallel routers with `rest_for_one` absorb supervision, asynchronously prepared reusable workers, coalesced wakeups, and idle hibernation.
  * Add high-level EdDSA and ECDH APIs in `libdecaf`, with opaque algorithm-specific keypairs, explicit seed/signing-key formats, and immutable native Ed25519ph/Ed448ph streaming.
  * Modernize `libdecaf_spongerng` with direct native calls, named typespecs, descriptive documentation, and runnable examples while preserving its wrapped-state API.
  * Add `libdecaf:spongerng_random_bytes/1` with automatically seeded thread-local native state, periodic reseeding, and a `crypto:strong_rand_bytes/1` entropy fallback.
  * Add immutable advancing `absorb`/`squeeze` APIs for every XOF family, following the two-phase streaming interface in the SP 800-185 Revision 1 initial public draft.
  * Generate the deprecated `libdecaf_sha2`, `libdecaf_sha3`, and `libdecaf_keccak_sha3` compatibility modules, retaining wrapped states and directing callers to the hash and XOF APIs in `libdecaf`.
  * Add Docker and native ASan, LSan, and UBSan checks for ed448goldilocks and the NIF, including resource cleanup stress.
  * Expose high-level `hash`/`xof` one-shot and streaming APIs in `libdecaf`, with algorithm-specific one-shot NIFs and explicit `_hash_init`/`_xof_init` constructors.
  * Give Hash and XOF independent contexts, resource types, registries, dispatch, and trapping lifecycles under `hash/` and `xof/`, with each construction in its own component directory.
  * Reuse the cSHAKE primitive in KMAC, TupleHash, and ParallelHash, the KT primitive in HopMAC, and TurboSHAKE in KT.
  * Keep algorithm callbacks private and generate component headers with explicit extern declarations, named parameters, and C++ linkage guards.
  * Generate opaque Hash and XOF states that retain initialization parameters, including chosen hash output lengths and KT customization, with human-friendly public documentation and runnable examples.
  * Track C header dependencies so generated atom-table changes rebuild every affected native object.
  * Upstream update to [`ed448goldilocks` version `features-20261022-v1.0.5`](https://github.com/potatosalad/ed448goldilocks/tree/features-20261022-v1.0.5), based on tag `v1.0.5` (vendored as part of `libdecaf` app).
  * Add X25519 high-bit, non-canonical coordinate, and low-order input regression tests.
  * Add RFC 9496 generator, invalid encoding, and uniform byte mapping test vectors.

## 2.1.1 (2022-08-31)

* Fixes
  * Include `Makefile` in hex.pm package so it works correctly with erlang.mk

## 2.1.0 (2022-08-28)

* Fixes
  * Security fix for [Misuse of public apis can result in private key exposure #13](https://github.com/potatosalad/erlang-libdecaf/issues/13) (see [report here](https://github.com/MystenLabs/ed25519-unsafe-libs)).
* Library Support
  * Legacy KECCAK SHA-3 (thanks to [@ukazap](https://github.com/ukazap))
    * `libdecaf_keccak_sha3:hash/2`, `libdecaf_keccak_sha3:hash/3`
    * `libdecaf_keccak_sha3:init/1`
    * `libdecaf_keccak_sha3:update/2`
    * `libdecaf_keccak_sha3:final/1`, `libdecaf_keccak_sha3:final/2`
* Enhancements
  * New Keypair API for Ed25519 and Ed448 operations (see [#13](https://github.com/potatosalad/erlang-libdecaf/issues/13)).
  * [Add legacy Keccak support #15](https://github.com/potatosalad/erlang-libdecaf/pull/15) (see also [#12](https://github.com/potatosalad/erlang-libdecaf/issues/12).)
  * Upstream update to [`ed448goldilocks` version `features-20220828`](https://github.com/potatosalad/ed448goldilocks/tree/features-20220828) (vendored as part of `libdecaf` app).

## 2.0.0 (2022-01-25)

* Fixes
  * Remove `xnif_slice` related code and refactor to use regular timeslice reduction bumping (see [#7](https://github.com/potatosalad/erlang-libdecaf/issues/7)).
  * Compilation problems on macOS and Erlang/OTP 23+ compatibility.
* Enhancements
  * Upstream update to [`ed448goldilocks` version `features-20220121`](https://github.com/potatosalad/ed448goldilocks/tree/features-20220121) (now vendored as part of `libdecaf` app).
  * Added tests for timeslice checking with large input and/or large output.
  * Switch from Travis CI to GitHub Actions.
  * Relicense library under MIT license.

## 1.0.0 (2018-11-30)

* Upstream update to [`ed448goldilocks` version 1.0](https://sourceforge.net/p/ed448goldilocks/code/ci/v1.0/tree/)
* Library Support
  * SPONGERNG
    * `libdecaf_spongerng:init_from_buffer/2`
    * `libdecaf_spongerng:init_from_file/3`
    * `libdecaf_spongerng:init_from_dev_urandom/0`
    * `libdecaf_spongerng:next/2`
    * `libdecaf_spongerng:stir/2`
  * Verious improvements to the build system (more appropriate usage of dirty schedulers and time slices).
  * Added Ed25519 to X25519 and Ed448 to X448 conversion functions.

## 0.0.4 (2016-09-02)

* Upstream version [features-20160902](https://github.com/potatosalad/ed448goldilocks/tree/features-20160902) which adds support for Ed25519ctx according to [draft 08 of EdDSA](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-08#section-5.1).

* Library Support
  * EdDSA
    * `libdecaf_curve25519:ed25519ctx_sign/3`
    * `libdecaf_curve25519:ed25519ctx_verify/4`

## 0.0.3 (2016-03-10)

* Upstream version [features-20160629](https://github.com/potatosalad/ed448goldilocks/tree/features-20160629)

* Fixes
  * Support for modern versions of FreeBSD, NetBSD, and DragonflyBSD.

## 0.0.2 (2016-03-10)

* Upstream version [f29b338f3788f052441478bb03b5d9e6fdd3eb28](https://github.com/potatosalad/ed448goldilocks/tree/f29b338f3788f052441478bb03b5d9e6fdd3eb28)

* Library Support
  * ECDH
    * `libdecaf:x25519_generate_key/1`
    * `libdecaf:x25519/2`
    * `libdecaf:x448_generate_key/1`
    * `libdecaf:x448/2`
  * EdDSA
    * `libdecaf:ed25519_derive_public_key/1`
    * `libdecaf:ed25519_sign/4`
    * `libdecaf:ed25519_sign_prehash/3`
    * `libdecaf:ed25519_verify/4`
    * `libdecaf:ed25519_verify_prehash/3`
    * `libdecaf:ed448_derive_public_key/1`
    * `libdecaf:ed448_sign/5`
    * `libdecaf:ed448_sign_prehash/4`
    * `libdecaf:ed448_verify/5`
    * `libdecaf:ed448_verify_prehash/4`

* Fixes
  * Include `stdint.h` to hopefully fix build issues on Linux.

## 0.0.1 (2016-03-01)

* Initial Release

* Publish to [hex.pm](https://hex.pm/packages/libdecaf).

* Library Support
  * ECDH
    * `libdecaf:decaf_x25519_base_scalarmul/1`
    * `libdecaf:decaf_x25519_direct_scalarmul/2`
    * `libdecaf:decaf_x448_base_scalarmul/1`
    * `libdecaf:decaf_x448_direct_scalarmul/2`
  * EdDSA
    * `libdecaf:decaf_255_eddsa_derive_public_key/1`
    * `libdecaf:decaf_255_eddsa_sign/4`
    * `libdecaf:decaf_255_eddsa_verify/4`
    * `libdecaf:decaf_448_eddsa_derive_public_key/1`
    * `libdecaf:decaf_448_eddsa_sign/5`
    * `libdecaf:decaf_448_eddsa_verify/5`
  * SHA-2
    * `libdecaf:sha2_512/2`
    * Streaming support
      * `libdecaf:sha2_512_init/0`, `libdecaf:sha2_512_update/2`, `libdecaf:sha2_512_final/2`
  * SHA-3
    * `libdecaf:sha3_224/1`
    * `libdecaf:sha3_256/1`
    * `libdecaf:sha3_384/1`
    * `libdecaf:sha3_512/1`
    * `libdecaf:shake128/2`
    * `libdecaf:shake256/2`
    * Streaming support
      * `libdecaf:sha3_224_init/0`, `libdecaf:sha3_224_update/2`, `libdecaf:sha3_224_final/1`
      * `libdecaf:sha3_256_init/0`, `libdecaf:sha3_256_update/2`, `libdecaf:sha3_256_final/1`
      * `libdecaf:sha3_384_init/0`, `libdecaf:sha3_384_update/2`, `libdecaf:sha3_384_final/1`
      * `libdecaf:sha3_512_init/0`, `libdecaf:sha3_512_update/2`, `libdecaf:sha3_512_final/1`
      * `libdecaf:shake128_init/0`, `libdecaf:shake128_update/2`, `libdecaf:shake128_final/2`
      * `libdecaf:shake256_init/0`, `libdecaf:shake256_update/2`, `libdecaf:shake256_final/2`

* Basic Tests based on the [draft-irtf-cfrg-eddsa](https://tools.ietf.org/html/draft-irtf-cfrg-eddsa), [FIPS 180-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf), [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), and [RFC 7748](https://tools.ietf.org/html/rfc7748) test vectors.
