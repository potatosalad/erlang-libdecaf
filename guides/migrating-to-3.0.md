# Migrating to 3.0

Version 3.0 adds high-level ECDH, EdDSA, Hash, and XOF APIs to `libdecaf`.
Historical top-level functions remain available and are marked deprecated.
The compatibility modules `libdecaf_sha2`, `libdecaf_sha3`, and
`libdecaf_keccak_sha3` are also deprecated.

## Hashes and SHAKE

| Previous call | Replacement |
| --- | --- |
| `libdecaf:sha3_256(Data)` | `libdecaf:hash(sha3_256, Data)` |
| `libdecaf:sha3_256(Data, Length)` | `libdecaf:hash({sha3_256, Length}, Data)` |
| `libdecaf_sha3:hash(sha3_256, Data)` | `libdecaf:hash(sha3_256, Data)` |
| `libdecaf_sha3:hash(sha3_256, Data, Length)` | `libdecaf:hash({sha3_256, Length}, Data)` |
| `libdecaf:sha3_256_init()` | `libdecaf:hash_init(sha3_256)` |
| `libdecaf:sha3_256_update(State, Data)` | `libdecaf:hash_update(State, Data)` |
| `libdecaf:sha3_256_final(State)` | `libdecaf:hash_final(State)` |
| `libdecaf:shake128(Data, Length)` | `libdecaf:xof(shake128, Data, Length)` |
| `libdecaf:shake128_init()` | `libdecaf:xof_init(shake128)` |
| `libdecaf:shake128_update(State, Data)` | `libdecaf:xof_absorb(State, Data)` |
| `libdecaf:shake128_final(State, Length)` | `libdecaf:xof_squeeze(State, Length)` |

The new Hash and XOF APIs return opaque states directly. Compatibility modules
retain their historical `{Algorithm, NativeState}` wrapper; use each module's
update/final functions with the state it created.

Choose a shortened digest's length when initializing the new Hash API:

```erlang
H0 = libdecaf:hash_init({sha3_256, 16}),
H1 = libdecaf:hash_update(H0, <<"abc">>),
Digest = libdecaf:hash_final(H1),
16 = byte_size(Digest).
```

Unlike historical SHAKE finalizers, `libdecaf:xof_squeeze/2` returns
`{NextState, Output}`. Keep the next state to continue reading:

```erlang
X0 = libdecaf:xof_absorb(libdecaf:xof_init(shake128), <<"abc">>),
{X1, First} = libdecaf:xof_squeeze(X0, 16),
{_X2, Second} = libdecaf:xof_squeeze(X1, 16).
```

See [Hashes and XOFs](hash-and-xof.md) for the complete parameter forms.

## Signatures and key agreement

New code should use `libdecaf:eddsa_keypair/1`, `libdecaf:eddsa_sign/2`,
`libdecaf:eddsa_verify/3`, and `libdecaf:ecdh_shared_secret/3`. The curve-specific
modules remain available for encoded keys and individual signature variants.

EdDSA keypair extraction returns `{PublicKey, SecretSeed}`. The curve modules'
`eddsa_keypair/0,1` functions instead return `{PublicKey, SigningKey}`, where the
signing key contains `Seed || PublicKey`. Both formats are accepted by the
high-level signing API.

Use `libdecaf:eddsa_sign_init/1` and `libdecaf:eddsa_verify_init/2` for streaming
Ed25519ph or Ed448ph. Pass original message bytes: these functions perform the
prehash internally. Explicit `*_sign_prehash` functions in the native API are for
callers that already have the algorithm's prehash bytes.

The historical top-level curve functions retain their argument order and flag
behavior. Their deprecation notices identify the matching native binding;
the high-level API uses algorithm-and-key parameter tuples instead.

## Random bytes

Use `libdecaf:strong_rand_bytes/1` for automatically seeded random bytes.
`libdecaf_spongerng` remains available for explicit seed/state management,
including deterministic streams. The historical `libdecaf:spongerng_*`
functions are deprecated in favor of the corresponding native
`libdecaf_nif:spongerng_csprng_*` bindings when raw native states are needed.

## Direct NIF callers

`libdecaf_nif` now uses shared lifecycle functions in place of the old
algorithm-specific update and final functions:

| Previous native call | Replacement |
| --- | --- |
| `sha3_256_hash(Input, Length)` | `sha3_256(Input, Length)` |
| `sha3_256_hash_init()` | `sha3_256_hash_init()` or `sha3_256_hash_init(Length)` |
| `sha3_256_hash_update(State, Input)` | `hash_update(State, Input)` |
| `sha3_256_hash_final(State, Length)` | Initialize with the desired length, then `hash_final(State)` |
| `shake128_xof(Input, Length)` | `shake128(Input, Length)` |
| `shake128_xof_init()` | `shake128_xof_init()` |
| `shake128_xof_update(State, Input)` | `xof_absorb(State, Input)` |
| `shake128_xof_output(State, Length)` | `xof_squeeze(State, Length)`, returning `{NextState, Output}` |

The same changes apply to SHA-512, the other SHA-3/Keccak sizes, and SHAKE256.
The old native convenience aliases such as `sha3_256_init/0` follow the same
migration. For most callers, the high-level `libdecaf` functions above are simpler.

## Runtime and builds

CI targets OTP 28 and OTP 29. Rebuild the native library when upgrading.
