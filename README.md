# libdecaf

[![CI](https://github.com/potatosalad/erlang-libdecaf/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/potatosalad/erlang-libdecaf/actions)
[![Hex.pm](https://img.shields.io/hexpm/v/libdecaf.svg)](https://hex.pm/packages/libdecaf)
[![HexDocs](https://img.shields.io/badge/docs-hexdocs-blue.svg)](https://hexdocs.pm/libdecaf)

Cryptographic signatures, key agreement, hashes, extendable-output functions (XOFs),
and random bytes for Erlang and Elixir. Built on
[ed448goldilocks](https://github.com/potatosalad/ed448goldilocks), with
[XKCP](https://github.com/XKCP/XKCP) and [K12](https://github.com/XKCP/K12)
acceleration selected at runtime on ARM64 and x86-64.

Use `libdecaf` for the high-level API. Specialized modules provide group
arithmetic, TUAK, and explicit PRNG state management.

[API reference](https://hexdocs.pm/libdecaf/3.0.0/) ·
[Hash and XOF guide](guides/hash-and-xof.md) ·
[Migrating to 3.0](guides/migrating-to-3.0.md) ·
[Changelog](CHANGELOG.md)

## Algorithm Support

| Algorithm | Group | Purpose | Definition |
| --- | --- | --- | --- |
| [Ed25519](#signatures-and-key-agreement) | EdDSA | Signature | [RFC 8032][rfc8032] |
| [Ed25519ctx](#signatures-and-key-agreement) | EdDSA | Signature | [RFC 8032][rfc8032] |
| [Ed25519ph](#signatures-and-key-agreement) | EdDSA | Signature | [RFC 8032][rfc8032] |
| [Ed448](#signatures-and-key-agreement) | EdDSA | Signature | [RFC 8032][rfc8032] |
| [Ed448ph](#signatures-and-key-agreement) | EdDSA | Signature | [RFC 8032][rfc8032] |
| [X25519](#signatures-and-key-agreement) | ECDH | Key agreement | [RFC 7748][rfc7748] |
| [X448](#signatures-and-key-agreement) | ECDH | Key agreement | [RFC 7748][rfc7748] |
| [Ristretto255](#specialized-modules) | Curve25519 | Prime-order group | [RFC 9496][rfc9496] |
| [Decaf448](#specialized-modules) | Curve448 | Prime-order group | [RFC 9496][rfc9496] |
| [SHA2-512 (SHA-512)](#hashes-authentication-tags-and-xofs) | SHA-2 | Hash | [FIPS 180-4][fips180] |
| [SHA3-224](#hashes-authentication-tags-and-xofs) | SHA-3 | Hash | [FIPS 202][fips202] |
| [SHA3-256](#hashes-authentication-tags-and-xofs) | SHA-3 | Hash | [FIPS 202][fips202] |
| [SHA3-384](#hashes-authentication-tags-and-xofs) | SHA-3 | Hash | [FIPS 202][fips202] |
| [SHA3-512](#hashes-authentication-tags-and-xofs) | SHA-3 | Hash | [FIPS 202][fips202] |
| [Keccak-224](#hashes-authentication-tags-and-xofs) | Keccak | Hash | [Keccak submission v3][keccak] |
| [Keccak-256](#hashes-authentication-tags-and-xofs) | Keccak | Hash | [Keccak submission v3][keccak] |
| [Keccak-384](#hashes-authentication-tags-and-xofs) | Keccak | Hash | [Keccak submission v3][keccak] |
| [Keccak-512](#hashes-authentication-tags-and-xofs) | Keccak | Hash | [Keccak submission v3][keccak] |
| [SHAKE128](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [FIPS 202][fips202] |
| [SHAKE256](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [FIPS 202][fips202] |
| [cSHAKE128](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [SP 800-185][sp800185] |
| [cSHAKE256](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [SP 800-185][sp800185] |
| [TurboSHAKE128](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [RFC 9861][rfc9861] |
| [TurboSHAKE256](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [RFC 9861][rfc9861] |
| [Keccak-XOF-128](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [Keccak submission v3][keccak] |
| [Keccak-XOF-256](#hashes-authentication-tags-and-xofs) | Keccak | Hash / XOF | [Keccak submission v3][keccak] |
| [KT128 (KangarooTwelve)](#hashes-authentication-tags-and-xofs) | Keccak | Parallel hash / XOF | [RFC 9861][rfc9861] |
| [KT256](#hashes-authentication-tags-and-xofs) | Keccak | Parallel hash / XOF | [RFC 9861][rfc9861] |
| [KMAC128](#hashes-authentication-tags-and-xofs) | Keccak | MAC | [SP 800-185][sp800185] |
| [KMAC256](#hashes-authentication-tags-and-xofs) | Keccak | MAC | [SP 800-185][sp800185] |
| [KMACXOF128](#hashes-authentication-tags-and-xofs) | Keccak | Keyed XOF | [SP 800-185][sp800185] |
| [KMACXOF256](#hashes-authentication-tags-and-xofs) | Keccak | Keyed XOF | [SP 800-185][sp800185] |
| [HopMAC128](#hashes-authentication-tags-and-xofs) | Keccak | Parallel MAC / keyed XOF | [RFC 9861][rfc9861] |
| [HopMAC256](#hashes-authentication-tags-and-xofs) | Keccak | Parallel MAC / keyed XOF | [RFC 9861][rfc9861] |
| [TupleHash128](#hashes-authentication-tags-and-xofs) | Keccak | Tuple hash | [SP 800-185][sp800185] |
| [TupleHash256](#hashes-authentication-tags-and-xofs) | Keccak | Tuple hash | [SP 800-185][sp800185] |
| [TupleHashXOF128](#hashes-authentication-tags-and-xofs) | Keccak | Tuple XOF | [SP 800-185][sp800185] |
| [TupleHashXOF256](#hashes-authentication-tags-and-xofs) | Keccak | Tuple XOF | [SP 800-185][sp800185] |
| [ParallelHash128](#hashes-authentication-tags-and-xofs) | Keccak | Parallel hash | [SP 800-185][sp800185] |
| [ParallelHash256](#hashes-authentication-tags-and-xofs) | Keccak | Parallel hash | [SP 800-185][sp800185] |
| [ParallelHashXOF128](#hashes-authentication-tags-and-xofs) | Keccak | Parallel XOF | [SP 800-185][sp800185] |
| [ParallelHashXOF256](#hashes-authentication-tags-and-xofs) | Keccak | Parallel XOF | [SP 800-185][sp800185] |
| [TUAK](#specialized-modules) | Keccak | Mobile authentication / key generation | [3GPP TS 35.231][tuak] |
| [SpongeRNG](#specialized-modules) | Keccak | Pseudorandom bytes | [Upstream SpongeRNG API][spongerng] |

[rfc8032]: https://www.rfc-editor.org/rfc/rfc8032
[rfc7748]: https://www.rfc-editor.org/rfc/rfc7748
[rfc9496]: https://www.rfc-editor.org/rfc/rfc9496
[rfc9861]: https://www.rfc-editor.org/rfc/rfc9861
[fips180]: https://csrc.nist.gov/pubs/fips/180-4/upd1/final
[fips202]: https://csrc.nist.gov/pubs/fips/202/final
[sp800185]: https://csrc.nist.gov/pubs/sp/800/185/final
[keccak]: https://keccak.team/files/Keccak-submission-3.pdf
[tuak]: https://www.etsi.org/deliver/etsi_ts/135200_135299/135231/19.00.00_60/ts_135231v190000p.pdf
[spongerng]: https://github.com/potatosalad/erlang-libdecaf/blob/main/c_deps/ed448goldilocks/src/public_include/decaf/spongerng.h

## Installation

Erlang with Rebar3:

```erlang
{deps, [{libdecaf, "3.0.0"}]}.
```

Elixir:

```elixir
defp deps do
  [{:libdecaf, "~> 3.0"}]
end
```

For erlang.mk, add `libdecaf` to `DEPS` and set
`dep_libdecaf = hex 3.0.0`.

Building requires Erlang/OTP 28 or later, GNU Make 4 or later, a C/C++ toolchain
with C23/C++20 support, CMake 3.22 or later, and Python 3. CI covers the latest
OTP 28 and OTP 29. The native dependency is included in the package.

## Quick start

Erlang:

```erlang
{ok, _} = libdecaf:start(),
Digest = libdecaf:hash(sha3_256, <<"abc">>),
<<"3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532">> = binary:encode_hex(Digest),
Token = libdecaf:strong_rand_bytes(32).
```

Elixir calls the same Erlang API:

```elixir
{:ok, _} = :libdecaf.start()
digest = :libdecaf.hash(:sha3_256, "abc")
token = :libdecaf.strong_rand_bytes(32)
```

## Signatures and key agreement

Generate an Ed25519 keypair, sign a message, and verify it:

```erlang
Keypair = libdecaf:eddsa_keypair(ed25519),
PublicKey = libdecaf:eddsa_keypair_extract_public_key(Keypair),
Signature = libdecaf:eddsa_sign({ed25519, Keypair}, <<"message">>),
true = libdecaf:eddsa_verify({ed25519, PublicKey}, Signature, <<"message">>).
```

Ed25519ctx, Ed25519ph, Ed448, and Ed448ph accept an optional context in the
parameter tuple. Ed25519ph and Ed448ph also support streaming:

```erlang
Keypair = libdecaf:eddsa_keypair(ed448),
S0 = libdecaf:eddsa_sign_init({ed448ph, Keypair, <<"protocol/v1">>}),
S1 = libdecaf:eddsa_sign_update(S0, [<<"hello ">>, <<"world">>]),
Signature = libdecaf:eddsa_sign_final(S1),
V0 = libdecaf:eddsa_verify_init({ed448ph, Keypair, <<"protocol/v1">>}, Signature),
V1 = libdecaf:eddsa_verify_update(V0, <<"hello world">>),
true = libdecaf:eddsa_verify_final(V1).
```

Pass original message bytes; the prehash is computed internally.

For X25519 or X448 key agreement:

```erlang
Alice = libdecaf:ecdh_keypair(x25519),
Bob = libdecaf:ecdh_keypair(x25519),
Shared = libdecaf:ecdh_shared_secret(x25519, Alice, Bob),
Shared = libdecaf:ecdh_shared_secret(x25519, Bob, Alice).
```

Shared secrets are raw bytes for your protocol's key derivation. A rejected
peer key returns `error`. For curve-specific operations and encoded-key APIs,
see `libdecaf_curve25519` and `libdecaf_curve448`.

## Hashes, authentication tags, and XOFs

Choose the algorithm and options when initializing a stream. Keep each returned
state; states are immutable and can be reused to branch a computation. Input
accepts iodata, and all lengths are in **bytes**.

```erlang
H0 = libdecaf:hash_init(sha3_256),
H1 = libdecaf:hash_update(H0, <<"hello ">>),
H2 = libdecaf:hash_update(H1, <<"world">>),
Digest = libdecaf:hash_final(H2),
Digest = libdecaf:hash(sha3_256, <<"hello world">>).
```

KMAC and HopMAC take a key and optional customization string:

```erlang
Key = libdecaf:strong_rand_bytes(32),
Tag = libdecaf:hash({kmac128, 32, Key, <<"orders/v1">>}, <<"invoice-42">>).
```

XOFs let you read as much output as needed. Once squeezing starts, the returned
state can keep squeezing but cannot absorb more input:

```erlang
X0 = libdecaf:xof_init(shake128),
X1 = libdecaf:xof_absorb(X0, <<"abc">>),
{X2, First} = libdecaf:xof_squeeze(X1, 16),
{_X3, Second} = libdecaf:xof_squeeze(X2, 16),
Output = <<First/binary, Second/binary>>,
Output = libdecaf:xof(shake128, <<"abc">>, 32).
```

KT, HopMAC, and ParallelHash can use the parallel APIs for large inputs:

```erlang
Input = binary:copy(<<"abc">>, 10000),
Digest = libdecaf:parallel_hash(kt128, Input),
Digest = libdecaf:hash(kt128, Input).
```

The parallel streaming APIs are `parallel_hash_init/1`,
`parallel_hash_update/2`, `parallel_hash_final/1`, and the corresponding
`parallel_xof_init/1`, `parallel_xof_absorb/2`, `parallel_xof_squeeze/2` functions.
They produce the same output as the ordinary APIs.

See the [Hash and XOF guide](guides/hash-and-xof.md) for parameter forms,
TupleHash element boundaries, customization, and parallel configuration.

## Specialized modules

`libdecaf_ristretto255` and `libdecaf_decaf448` provide prime-order group arithmetic.
`libdecaf_tuak` exposes TUAK authentication and key generation. Use
`libdecaf:strong_rand_bytes/1` for automatically seeded random bytes, or
`libdecaf_spongerng` for explicit seeded streams.

Implementations are checked against published vectors from RFCs
[7748](https://www.rfc-editor.org/rfc/rfc7748.html),
[8032](https://www.rfc-editor.org/rfc/rfc8032.html),
[9496](https://www.rfc-editor.org/rfc/rfc9496.html), and
[9861](https://www.rfc-editor.org/rfc/rfc9861.html), NIST
[FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final),
[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final),
[SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final), and 3GPP TUAK conformance data.

## Benchmark highlights

Representative **unkeyed parallel hashing** throughput on an Apple M3 Max
(14 schedulers, OTP 29, ARM SHA3 backend):

| Algorithm | Throughput |
| --- | ---: |
| KT128 | 39 GB/s |
| KT256 | 29 GB/s |
| ParallelHash128 | 20 GB/s |
| ParallelHash256 | 16 GB/s |

Whole-number decimal GB/s, using the median of seven warmed passes with
32 GiB messages, reused 64 MiB updates, 8 KiB ParallelHash blocks, and worker
budget zero. These are completed hashes, including root processing. Results vary
with CPU and input size; small messages favor the ordinary API. HopMAC adds
keyed authentication to KT and is covered separately by the benchmark scripts.

```sh
elixir bench/parallel_hash_highlights.exs
elixir bench/parallel_hash_stress.exs
elixir bench/parallel_xof_stress.exs
```

[Benchmark measurements](https://github.com/potatosalad/erlang-libdecaf/blob/main/bench/parallel_hash.md)
include size sweeps and native leaf baselines.

## Building, testing, and documentation

```sh
gmake
gmake tests
gmake lint
gmake docs
```

ExDoc writes the API reference and guides to `doc/index.html`, including source
links for release `3.0.0`. `rebar3 ex_doc` builds the same documentation directly.

Use `gmake format` after editing C or Erlang sources. Generated files are
maintained through `just codegen`. [Development](guides/development.md) covers
code generation, selected test suites, sanitizers, and package checks.

## License

[MIT](LICENSE.md). Vendored dependencies retain their own license notices.
