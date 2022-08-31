# libdecaf NIF

[![Build Status](https://github.com/potatosalad/erlang-libdecaf/actions/workflows/main.yml/badge.svg?branch=main)](https://github.com/potatosalad/erlang-libdecaf/actions) [![Hex.pm](https://img.shields.io/hexpm/v/libdecaf.svg)](https://hex.pm/packages/libdecaf)

[ed448goldilocks (libdecaf)](https://sourceforge.net/p/ed448goldilocks) NIF with timeslice reductions for Erlang and Elixir.

See [&ldquo;Decaf: Eliminating cofactors through point compression&rdquo;](https://eprint.iacr.org/2015/673.pdf) by [Mike Hamburg](https://shiftleft.org/) for more information.

The timeslice reductions allow the NIF to perform certain operations on very large inputs without blocking the scheduler or requiring the Erlang VM to support dirty schedulers.  See the [bitwise](https://github.com/vinoski/bitwise) project from which the strategy was derived.

Tested against the [RFC 8032](https://tools.ietf.org/html/rfc8032), [FIPS 180-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf), [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), and [RFC 7748](https://tools.ietf.org/html/rfc7748) test vectors.

## Algorithm Support

| Algorithm                   | Group             | Purpose       | Definition |
| --------------------------- | ----------------- | ------------- | ---------- |
| [Ed25519](#ed25519)         | [EdDSA](#eddsa)   | Signature     | [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.1) |
| [Ed25519ctx](#ed25519ctx)   | [EdDSA](#eddsa)   | Signature     | [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.1) |
| [Ed25519ph](#ed25519ph)     | [EdDSA](#eddsa)   | Signature     | [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.1) |
| [Ed448](#ed448)             | [EdDSA](#eddsa)   | Signature     | [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.2) |
| [Ed448ph](#ed448ph)         | [EdDSA](#eddsa)   | Signature     | [RFC 8032](https://tools.ietf.org/html/rfc8032#section-5.2) |
| [SPONGERNG](#spongerng)     | [KECCAK](#keccak) | Pseudo-Random | [`decaf/spongerng.h`](https://sourceforge.net/p/ed448goldilocks/code/ci/v1.0/tree/src/public_include/decaf/spongerng.h) |
| [SHA2-512](#sha-2)          | [SHA-2](#sha-2)   | Hash          | [FIPS 180-4](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf) |
| [SHA3-224](#sha-3)          | [SHA-3](#sha-3)   | Hash          | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [SHA3-256](#sha-3)          | [SHA-3](#sha-3)   | Hash          | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [SHA3-384](#sha-3)          | [SHA-3](#sha-3)   | Hash          | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [SHA3-512](#sha-3)          | [SHA-3](#sha-3)   | Hash          | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [KECCAK-224](#keccak-sha-3) | [KECCAK](#keccak) | Hash          | [Keccak submission (version 3)](https://keccak.team/files/Keccak-submission-3.pdf) |
| [KECCAK-256](#keccak-sha-3) | [KECCAK](#keccak) | Hash          | [Keccak submission (version 3)](https://keccak.team/files/Keccak-submission-3.pdf) |
| [KECCAK-384](#keccak-sha-3) | [KECCAK](#keccak) | Hash          | [Keccak submission (version 3)](https://keccak.team/files/Keccak-submission-3.pdf) |
| [KECCAK-512](#keccak-sha-3) | [KECCAK](#keccak) | Hash          | [Keccak submission (version 3)](https://keccak.team/files/Keccak-submission-3.pdf) |
| [SHAKE128](#sha-3)          | [SHA-3](#sha-3)   | XOF           | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [SHAKE256](#sha-3)          | [SHA-3](#sha-3)   | XOF           | [FIPS 202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| [X25519](#x25519)           | [ECDH](#ecdh)     | Key Exchange  | [RFC 7748](https://tools.ietf.org/html/rfc7748#section-5) |
| [X448](#x448)               | [ECDH](#ecdh)     | Key Exchange  | [RFC 7748](https://tools.ietf.org/html/rfc7748#section-5) |

## Installation

Add `libdecaf` to your project's dependencies in `mix.exs`

```elixir
defp deps do
  [
    {:libdecaf, "~> 2.1.1"}
  ]
end
```

Add `libdecaf` to your project's dependencies in your `Makefile` for [`erlang.mk`](https://github.com/ninenines/erlang.mk) or the following to your `rebar.config`

```erlang
{deps, [
  {libdecaf, "2.1.1"}
]}.
```

## Usage

### ECDH

#### X25519

```erlang
%% X25519 (curve25519) Key Generation
{AlicePK25519, AliceSK25519} = libdecaf_curve25519:x25519_keypair().
% {<<155,64,184,119,41,134,146,219,250,18,4,67,204,130,43,123,254,96,68,174,200,23,238,126,79,238,85,159,186,4,120,75>>, <<32,212,161,45,202,186,28,152,196,19,74,127,44,14,73,165,194,228,179,252,108,220,81,163,201,183,167,144,143,160,212,206>>}
{BobPK25519, BobSK25519} = libdecaf_curve25519:x25519_keypair().
% {<<31,100,69,143,46,85,11,129,240,52,225,219,164,100,9,171,242,98,210,112,8,222,150,66,16,160,143,122,102,188,146,10>>, <<39,232,51,250,201,211,41,191,120,143,42,86,105,150,4,24,169,238,245,77,238,40,179,198,96,157,144,229,162,41,205,77>>}

%% X25519 Shared Secret
SharedSecretX25519 = libdecaf_curve25519:x25519(AliceSK25519, BobPK25519).
% <<83,191,246,24,100,87,227,192,3,237,26,132,143,40,62,213,67,232,33,97,240,8,73,139,64,160,13,107,150,146,246,30>>
SharedSecretX25519 =:= libdecaf_curve25519:x25519(BobSK25519, AlicePK25519).
% true
```

#### X448

```erlang
%% X448 (curve448) Key Generation
{AlicePK448, AliceSK448} = libdecaf_curve448:x448_keypair().
% {<<105,143,129,11,70,98,185,191,191,50,127,193,175,72,161,79,83,138,120,81,31,104,18,241,113,197,243,49,93,92,165,124,198,141,92,186,199,33,67,132,244,217,138,213,64,67,106,63,33,144,227,46,158,169,74,242>>, <<167,49,168,47,44,91,156,96,5,153,110,156,108,175,53,145,63,251,245,180,129,161,206,122,26,197,27,146,248,100,74,167,70,130,43,193,21,169,118,30,80,74,145,200,176,112,94,139,59,250,167,118,103,50,209,53>>}
{BobPK448, BobSK448} = libdecaf_curve448:x448_keypair().
% {<<83,3,128,166,199,125,249,189,28,86,204,99,239,204,162,180,230,199,198,77,55,120,44,169,165,153,238,230,47,255,223,187,18,7,65,152,205,235,76,65,152,93,38,236,177,36,70,199,146,235,67,245,226,142,27,24>>, <<90,248,1,221,137,251,205,121,215,99,121,204,122,92,97,157,88,173,213,171,171,83,64,140,72,156,96,242,230,239,89,242,76,190,148,109,13,145,159,138,105,240,246,86,169,137,144,80,241,224,91,73,108,165,156,31>>}

%% X448 Shared Secret
SharedSecretX448 = libdecaf_curve448:x448(AliceSK448, BobPK448).
% <<114,107,110,164,14,165,169,174,160,230,53,253,116,87,238,193,5,2,210,229,81,43,197,195,128,229,181,13,30,139,203,164,6,24,167,53,193,173,199,233,232,41,221,244,18,176,233,77,209,27,22,90,189,218,201,227>>
SharedSecretX448 =:= libdecaf_curve448:x448(BobSK448, AlicePK448).
% true
```

### EdDSA

```erlang
%% EdDSA (edwards25519) Key Generation
{PK25519, SK25519} = libdecaf_curve25519:eddsa_keypair().
% {<<211,65,121,173,153,86,193,196,218,254,23,46,4,146,26,124,131,219,63,144,210,48,209,178,189,10,233,246,248,65,158,48>>, <<63,238,247,145,210,20,146,223,78,100,90,126,134,45,223,41,104,231,121,9,5,104,69,122,233,171,44,76,57,171,155,211,211,65,121,173,153,86,193,196,218,254,23,46,4,146,26,124,131,219,63,144,210,48,209,178,189,10,233,246,248,65,158,48>>}

%% EdDSA (edwards448) Key Generation
{PK448, SK448} = libdecaf_curve448:eddsa_keypair().
% {<<241,233,41,181,164,174,226,117,24,66,133,47,149,210,164,224,28,126,128,72,91,188,104,161,195,124,68,135,92,239,242,16,54,103,127,106,169,175,41,108,92,133,176,221,9,217,123,174,85,37,243,51,184,123,208,112,0>>, <<208,201,124,71,171,63,19,141,159,70,248,214,101,209,110,44,221,16,92,150,231,227,56,223,39,52,47,163,35,76,103,204,158,103,184,236,28,255,121,25,147,183,188,212,197,107,37,71,183,104,96,32,107,139,114,245,155,241,233,41,181,164,174,226,117,24,66,133,47,149,210,164,224,28,126,128,72,91,188,104,161,195,124,68,135,92,239,242,16,54,103,127,106,169,175,41,108,92,133,176,221,9,217,123,174,85,37,243,51,184,123,208,112,0>>}
```

The following message `M` and context `C` will be used for all signature examples below.

```erlang
M = <<>>.       % Message used below for signing
C = <<"test">>. % Context used below by Ed448 and Ed448ph
```

#### Ed25519

```erlang
%% Ed25519 Sign
SigEd25519 = libdecaf_curve25519:ed25519_sign(M, SK25519).
% <<206,59,70,86,114,42,116,11,30,183,149,16,90,90,105,162,112,182,99,62,90,20,207,102,102,98,230,18,23,175,212,150,146,27,83,120,107,135,209,56,75,214,152,204,24,205,48,128,129,191,174,137,11,189,75,14,7,242,3,255,122,176,182,2>>

%% Ed25519 Verify
libdecaf_curve25519:ed25519_verify(SigEd25519, M, PK25519).
% true
```

#### Ed25519ctx

```erlang
%% Ed25519ctx Sign
SigEd25519ctx = libdecaf_curve25519:ed25519ctx_sign(M, SK25519, C).
% <<121,125,214,50,137,200,252,109,235,4,97,17,231,63,160,143,199,137,100,132,145,175,61,245,212,221,100,99,189,35,73,77,245,64,153,81,110,135,155,211,105,100,232,173,157,219,89,197,185,173,83,83,136,183,47,69,41,27,81,37,28,120,127,0>>

%% Ed25519ctx Verify
libdecaf_curve25519:ed25519ctx_verify(SigEd25519ctx, M, PK25519, C).
% true
```

#### Ed25519ph

```erlang
%% Ed25519ph Sign
SigEd25519ph = libdecaf_curve25519:ed25519ph_sign(M, SK25519).
% <<38,138,35,252,20,194,155,187,120,255,150,145,241,64,155,210,107,134,239,171,190,219,2,221,254,79,19,187,208,183,18,156,190,45,181,85,100,10,19,108,180,189,207,24,244,9,44,13,69,215,88,57,227,71,72,50,84,134,211,28,160,175,164,15>>

%% Ed25519ph Verify
libdecaf_curve25519:ed25519ph_verify(SigEd25519ph, M, PK25519).
% true
```

#### Ed448

```erlang
%% Ed448 Sign
SigEd448 = libdecaf_curve448:ed448_sign(M, SK448).
% <<119,207,247,95,201,79,152,97,43,180,45,185,35,106,183,196,49,213,79,187,29,138,177,18,179,169,69,199,186,168,245,4,237,201,28,60,238,248,239,35,24,16,96,225,82,210,43,71,15,26,235,67,34,209,41,34,0,196,180,145,251,47,102,57,80,10,3,131,169,40,130,129,165,20,33,208,230,218,127,231,61,84,146,237,77,239,56,241,73,165,24,89,55,149,175,238,154,238,27,88,206,242,238,5,161,22,157,229,47,171,26,168,6,0>>

%% Ed448 Verify
libdecaf_curve448:ed448_verify(SigEd448, M, PK448).
% true

%% Ed448 Sign with Context
SigEd448C = libdecaf_curve448:ed448_sign(M, SK448, C).
% <<198,30,160,202,201,28,194,205,148,240,61,130,243,165,24,200,41,118,93,214,56,253,177,171,146,176,149,237,247,108,171,59,123,218,127,48,4,191,227,3,193,177,33,211,120,44,104,86,71,202,97,76,109,41,178,54,0,214,106,192,185,186,130,72,187,199,95,189,203,25,173,26,36,89,1,91,220,192,18,141,7,168,190,107,76,243,251,56,248,121,183,193,138,72,130,96,119,44,97,69,224,186,129,29,205,60,242,222,247,123,130,7,54,0>>

%% Ed448 Verify with Context
libdecaf_curve448:ed448_verify(SigEd448C, M, PK448, C).
% true
```

#### Ed448ph

```erlang
%% Ed448ph Sign
SigEd448ph = libdecaf_curve448:ed448ph_sign(M, SK448).
% <<61,28,185,125,227,93,73,177,186,177,224,87,60,237,63,115,204,239,209,169,157,197,155,42,67,29,32,148,120,33,52,6,40,207,172,33,82,122,134,20,59,153,62,159,69,229,218,26,163,145,20,237,15,54,164,101,128,204,197,240,72,160,203,235,124,201,33,215,72,197,140,53,203,165,55,190,209,166,212,90,29,69,89,136,159,83,55,110,11,22,45,222,98,164,8,237,166,57,180,150,63,126,227,124,239,6,131,62,140,135,234,94,20,0>>

%% Ed448 Verify
libdecaf_curve448:ed448ph_verify(SigEd448ph, M, PK448).
% true

%% Ed448ph Sign with Context
SigEd448phC = libdecaf_curve448:ed448ph_sign(M, SK448, C).
% <<231,37,236,141,234,175,12,81,19,66,127,155,15,245,146,181,254,95,216,109,5,90,94,219,70,51,211,22,42,172,96,248,227,95,109,101,142,17,76,5,71,111,73,138,157,28,214,114,69,126,50,44,234,241,25,142,128,199,224,67,223,66,203,103,92,103,153,207,116,200,158,81,228,140,64,67,69,143,112,128,92,229,218,76,149,33,31,79,55,242,221,19,168,143,31,197,73,95,148,73,143,107,18,217,63,136,43,25,218,20,124,118,37,0>>

%% Ed448ph Verify with Context
libdecaf_curve448:ed448ph_verify(SigEd448phC, M, PK448, C).
% true
```

### KECCAK

##### SPONGERNG

#### `libdecaf_spongerng:init_from_buffer/2`

This function allows you to specify an initial seed buffer and whether the PRNG will be deterministic or not.

```erlang
%% Deterministic
libdecaf_spongerng:init_from_buffer(<<>>, true).
% {spongerng, #Ref<0.0.0.1>}
%% Non-deterministic
libdecaf_spongerng:init_from_buffer(<<>>, false).
% {spongerng, #Ref<0.0.0.2>}
```

#### `libdecaf_spongerng:init_from_file/3`

This function allows you specify an initial seed file up to the given length and whether the PRNG will be deterministic or not.

```erlang
%% Deterministic
libdecaf_spongerng:init_from_file("seed.txt", 16, true).
% {spongerng, #Ref<0.0.0.3>}
%% Non-deterministic
libdecaf_spongerng:init_from_file("seed.txt", 16, false).
% {spongerng, #Ref<0.0.0.4>}
```

#### `libdecaf_spongerng:init_from_dev_urandom/0`

This function reads an initial seed from `/dev/urandom` and is only allowed to be non-deterministic.

```erlang
%% Non-deterministic
libdecaf_spongerng:init_from_dev_urandom().
% {spongerng, #Ref<0.0.0.5>}
```

#### `libdecaf_spongerng:next/2`

This function returns the next length of bytes from the sponge and returns the new sponge state.

```erlang
Sponge0 = libdecaf_spongerng:init_from_buffer(<<>>, true),
{Sponge1, Output} = libdecaf_spongerng:next(Sponge0, 8).
% {{spongerng, #Ref<0.0.0.6>}, <<99,190,253,62,125,162,80,150>>}
```

#### `libdecaf_spongerng:stir/2`

This function modifies the sponge state (stirs the pot) with the given input.

```erlang
Sponge0 = libdecaf_spongerng:init_from_buffer(<<>>, true),
Sponge1 = libdecaf_spongerng:stir(Sponge0, <<"test">>),
{Sponge2, Output} = libdecaf_spongerng:next(Sponge1, 8).
% {{spongerng, #Ref<0.0.0.7>}, <<168,214,5,0,60,110,186,33>>}
```

### KECCAK-SHA-3

#### `libdecaf_keccak_sha3:hash/2`

This function can be used for the following hash algorithms:

 * KECCAK-224 (`keccak_224`)
 * KECCAK-256 (`keccak_256`)
 * KECCAK-384 (`keccak_384`)
 * KECCAK-512 (`keccak_512`)

```erlang
libdecaf_keccak_sha3:hash(keccak_224, <<"test">>).
% <<59,227,10,159,246,79,52,165,134,17,22,197,25,137,135,173,120,1,101,248,54,110,103,175,244,118,11,94>>

libdecaf_keccak_sha3:hash(keccak_256, <<"test">>).
% <<156,34,255,95,33,240,184,27,17,62,99,247,219,109,169,79,237,239,17,178,17,155,64,136,184,150,100,251,154,60,182,88>>

libdecaf_keccak_sha3:hash(keccak_384, <<"test">>).
% <<83,208,186,19,115,7,212,194,249,182,103,76,131,237,189,88,183,12,15,67,64,19,62,208,173,198,251,161,210,71,138,106,3,183,120,130,41,231,117,210,222,138,232,192,117,157,5,39>>

libdecaf_keccak_sha3:hash(keccak_512, <<"test">>).
% <<30,46,159,194,0,43,0,45,117,25,139,117,3,33,12,5,161,186,172,69,96,145,106,60,109,147,188,206,58,80,215,240,15,211,149,191,22,71,185,171,184,209,175,204,156,118,194,137,176,201,56,59,163,134,169,86,218,75,56,147,68,23,120,158>>
```

#### `libdecaf_keccak_sha3:init/1`

This function can be used for the following algorithms:

 * KECCAK-224 (`keccak_224`)
 * KECCAK-256 (`keccak_256`)
 * KECCAK-384 (`keccak_384`)
 * KECCAK-512 (`keccak_512`)

##### KECCAK-224 (`keccak_224`)

```erlang
Sponge0 = libdecaf_keccak_sha3:init(keccak_224).
% {keccak_224, #Ref<0.0.0.7>}
```

##### KECCAK-256 (`keccak_256`)

```erlang
Sponge0 = libdecaf_keccak_sha3:init(keccak_256).
% {keccak_256, #Ref<0.0.0.8>}
```

##### KECCAK-384 (`keccak_384`)

```erlang
Sponge0 = libdecaf_keccak_sha3:init(keccak_384).
% {keccak_384, #Ref<0.0.0.9>}
```

##### KECCAK-512 (`keccak_512`)

```erlang
Sponge0 = libdecaf_keccak_sha3:init(keccak_512).
% {keccak_512, #Ref<0.0.0.10>}
```

#### `libdecaf_keccak_sha3:update/2`

This function can be used for the following algorithms:

 * KECCAK-224 (`keccak_224`)
 * KECCAK-256 (`keccak_256`)
 * KECCAK-384 (`keccak_384`)
 * KECCAK-512 (`keccak_512`)

The examples below use the `Sponge0` for each algorithm from the examples above for `libdecaf_keccak_sha3:init/1`.

##### KECCAK-224 (`keccak_224`)

```erlang
Sponge1 = libdecaf_keccak_sha3:update(Sponge0, <<"test">>).
% {keccak_224, #Ref<0.0.0.17>}
```

##### KECCAK-256 (`keccak_256`)

```erlang
Sponge1 = libdecaf_keccak_sha3:update(Sponge0, <<"test">>).
% {keccak_256, #Ref<0.0.0.18>}
```

##### KECCAK-384 (`keccak_384`)

```erlang
Sponge1 = libdecaf_keccak_sha3:update(Sponge0, <<"test">>).
% {keccak_384, #Ref<0.0.0.19>}
```

##### KECCAK-512 (`keccak_512`)

```erlang
Sponge1 = libdecaf_keccak_sha3:update(Sponge0, <<"test">>).
% {keccak_512, #Ref<0.0.0.20>}
```

#### `libdecaf_keccak_sha3:final/1`

This function can be used for the following hash algorithms:

 * KECCAK-224 (`keccak_224`)
 * KECCAK-256 (`keccak_256`)
 * KECCAK-384 (`keccak_384`)
 * KECCAK-512 (`keccak_512`)

The examples below use the `Sponge1` for each algorithm from the examples above for `libdecaf_keccak_sha3:update/2`.

##### KECCAK-224 (`keccak_224`)

```erlang
Out = libdecaf_keccak_sha3:final(Sponge1).
% <<59,227,10,159,246,79,52,165,134,17,22,197,25,137,135,173,120,1,101,248,54,110,103,175,244,118,11,94>>
```

##### KECCAK-256 (`keccak_256`)

```erlang
Out = libdecaf_keccak_sha3:final(Sponge1).
% <<156,34,255,95,33,240,184,27,17,62,99,247,219,109,169,79,237,239,17,178,17,155,64,136,184,150,100,251,154,60,182,88>>
```

##### KECCAK-384 (`keccak_384`)

```erlang
Out = libdecaf_keccak_sha3:final(Sponge1).
% <<83,208,186,19,115,7,212,194,249,182,103,76,131,237,189,88,183,12,15,67,64,19,62,208,173,198,251,161,210,71,138,106,3,183,120,130,41,231,117,210,222,138,232,192,117,157,5,39>>
```

##### KECCAK-512 (`keccak_512`)

```erlang
Out = libdecaf_keccak_sha3:final(Sponge1).
% <<30,46,159,194,0,43,0,45,117,25,139,117,3,33,12,5,161,186,172,69,96,145,106,60,109,147,188,206,58,80,215,240,15,211,149,191,22,71,185,171,184,209,175,204,156,118,194,137,176,201,56,59,163,134,169,86,218,75,56,147,68,23,120,158>>
```

### SHA-2

#### `libdecaf_sha2:hash/2`

This function can be used for the following algorithms:

 * SHA2-512 (`sha2_512`)

##### SHA2-512 (`sha2_512`)

```erlang
libdecaf_sha2:hash(sha2_512, <<"test">>).
% <<238,38,176,221,74,247,231,73,170,26,142,227,193,10,233,146,63,97,137,128,119,46,71,63,136,25,165,212,148,14,13,178,122,193,133,248,160,225,213,248,79,136,188,136,127,214,123,20,55,50,195,4,204,95,169,173,142,111,87,245,0,40,168,255>>
```

#### `libdecaf_sha2:init/1`

This function can be used for the following algorithms:

 * SHA2-512 (`sha2_512`)

##### SHA2-512 (`sha2_512`)

```erlang
Context0 = libdecaf_sha2:init(sha2_512).
% {sha2_512, #Ref<0.0.0.1>}
```

#### `libdecaf_sha2:update/2`

This function can be used for the following algorithms:

 * SHA2-512 (`sha2_512`)

The examples below use the `Context0` for each algorithm from the examples above for `libdecaf_sha2:init/1`.

##### SHA2-512 (`sha2_512`)

```erlang
Context1 = libdecaf_sha2:update(Context0, <<"test">>).
% {sha2_512, #Ref<0.0.0.2>}
```

#### `libdecaf_sha2:final/2`

This function can be used for the following algorithms:

 * SHA2-512 (`sha2_512`)

The examples below use the `Context1` for each algorithm from the examples above for `libdecaf_sha2:update/2`.

##### SHA2-512 (`sha2_512`)

```erlang
Out = libdecaf_sha2:final(Context1).
% <<238,38,176,221,74,247,231,73,170,26,142,227,193,10,233,146,63,97,137,128,119,46,71,63,136,25,165,212,148,14,13,178,122,193,133,248,160,225,213,248,79,136,188,136,127,214,123,20,55,50,195,4,204,95,169,173,142,111,87,245,0,40,168,255>>
```

### SHA-3

#### `libdecaf_sha3:hash/2`

This function can be used for the following hash algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)

```erlang
libdecaf_sha3:hash(sha3_224, <<"test">>).
% <<55,151,191,10,251,191,202,74,123,187,167,96,42,43,85,39,70,135,101,23,167,249,183,206,45,176,174,123>>

libdecaf_sha3:hash(sha3_256, <<"test">>).
% <<54,240,40,88,11,176,44,200,39,42,154,2,15,66,0,227,70,226,118,174,102,78,69,238,128,116,85,116,226,245,171,128>>

libdecaf_sha3:hash(sha3_384, <<"test">>).
% <<229,22,218,187,35,182,227,0,38,134,53,67,40,39,128,163,174,13,204,240,85,81,207,2,149,23,141,127,240,241,180,30,236,185,219,63,242,25,0,124,78,9,114,96,213,134,33,189>>

libdecaf_sha3:hash(sha3_512, <<"test">>).
% <<158,206,8,110,155,172,73,31,172,92,29,16,70,202,17,215,55,185,42,43,46,189,147,240,5,215,183,16,17,12,10,103,130,136,22,110,127,190,121,104,131,164,242,233,179,202,159,72,79,82,29,12,228,100,52,92,193,174,201,103,121,20,156,20>>
```

#### `libdecaf_sha3:xof/3`

This function can be used for the following [eXtendable-Output Function (XOF)](https://csrc.nist.gov/glossary/term/extendable_output_function) algorithms:

 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

These algorithms can output arbitrary length digests, so an output length must be specified.

```erlang
libdecaf_sha3:xof(shake128, <<"test">>, 16).
% <<211,176,170,156,216,183,37,86,34,206,188,99,30,134,125,64>>

libdecaf_sha3:xof(shake256, <<"test">>, 16).
% <<181,79,247,37,87,5,167,30,226,146,94,74,62,48,228,26>>
```

#### `libdecaf_sha3:init/1`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)
 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

##### SHA3-224 (`sha3_224`)

```erlang
Sponge0 = libdecaf_sha3:init(sha3_224).
% {sha3_224, #Ref<0.0.0.3>}
```

##### SHA3-256 (`sha3_256`)

```erlang
Sponge0 = libdecaf_sha3:init(sha3_256).
% {sha3_256, #Ref<0.0.0.4>}
```

##### SHA3-384 (`sha3_384`)

```erlang
Sponge0 = libdecaf_sha3:init(sha3_384).
% {sha3_384, #Ref<0.0.0.5>}
```

##### SHA3-512 (`sha3_512`)

```erlang
Sponge0 = libdecaf_sha3:init(sha3_512).
% {sha3_512, #Ref<0.0.0.6>}
```

##### SHAKE128 (`shake128`)

```erlang
Sponge0 = libdecaf_sha3:init(shake128).
% {shake128, #Ref<0.0.0.11>}
```

##### SHAKE256 (`shake256`)

```erlang
Sponge0 = libdecaf_sha3:init(shake256).
% {shake256, #Ref<0.0.0.12>}
```

#### `libdecaf_sha3:update/2`

This function can be used for the following algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)
 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

The examples below use the `Sponge0` for each algorithm from the examples above for `libdecaf_sha3:init/1`.

##### SHA3-224 (`sha3_224`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {sha3_224, #Ref<0.0.0.13>}
```

##### SHA3-256 (`sha3_256`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {sha3_256, #Ref<0.0.0.14>}
```

##### SHA3-384 (`sha3_384`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {sha3_384, #Ref<0.0.0.15>}
```

##### SHA3-512 (`sha3_512`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {sha3_512, #Ref<0.0.0.16>}
```

##### SHAKE128 (`shake128`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {shake128, #Ref<0.0.0.21>}
```

##### SHAKE256 (`shake256`)

```erlang
Sponge1 = libdecaf_sha3:update(Sponge0, <<"test">>).
% {shake256, #Ref<0.0.0.22>}
```

#### `libdecaf_sha3:final/1`

This function can be used for the following hash algorithms:

 * SHA3-224 (`sha3_224`)
 * SHA3-256 (`sha3_256`)
 * SHA3-384 (`sha3_384`)
 * SHA3-512 (`sha3_512`)

The examples below use the `Sponge1` for each algorithm from the examples above for `libdecaf_sha3:update/2`.

##### SHA3-224 (`sha3_224`)

```erlang
Out = libdecaf_sha3:final(Sponge1).
% <<55,151,191,10,251,191,202,74,123,187,167,96,42,43,85,39,70,135,101,23,167,249,183,206,45,176,174,123>>
```

##### SHA3-256 (`sha3_256`)

```erlang
Out = libdecaf_sha3:final(Sponge1).
% <<54,240,40,88,11,176,44,200,39,42,154,2,15,66,0,227,70,226,118,174,102,78,69,238,128,116,85,116,226,245,171,128>>
```

##### SHA3-384 (`sha3_384`)

```erlang
Out = libdecaf_sha3:final(Sponge1).
% <<229,22,218,187,35,182,227,0,38,134,53,67,40,39,128,163,174,13,204,240,85,81,207,2,149,23,141,127,240,241,180,30,236,185,219,63,242,25,0,124,78,9,114,96,213,134,33,189>>
```

##### SHA3-512 (`sha3_512`)

```erlang
Out = libdecaf_sha3:final(Sponge1).
% <<158,206,8,110,155,172,73,31,172,92,29,16,70,202,17,215,55,185,42,43,46,189,147,240,5,215,183,16,17,12,10,103,130,136,22,110,127,190,121,104,131,164,242,233,179,202,159,72,79,82,29,12,228,100,52,92,193,174,201,103,121,20,156,20>>
```

#### `libdecaf_sha3:final/2`

This function can be used for the following [eXtendable-Output Function (XOF)](https://csrc.nist.gov/glossary/term/extendable_output_function) algorithms:

 * SHAKE128 (`shake128`)
 * SHAKE256 (`shake256`)

These algorithms can output arbitrary length digests, so an output length must be specified.

The examples below use the `Sponge1` for each algorithm from the examples above for `libdecaf_sha3:update/2`.

##### SHAKE128 (`shake128`)

```erlang
Out = libdecaf_sha3:final(Sponge1, 16).
% <<211,176,170,156,216,183,37,86,34,206,188,99,30,134,125,64>>
```

##### SHAKE256 (`shake256`)

```erlang
Out = libdecaf_sha3:final(Sponge1, 16).
% <<181,79,247,37,87,5,167,30,226,146,94,74,62,48,228,26>>
```
