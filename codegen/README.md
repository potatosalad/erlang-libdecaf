# libdecaf code generation

This development-only Python project generates committed NIF sources for libdecaf.
Normal `gmake` builds use the generated C files and do not need Python dependencies.

Requires Python 3.13 or later and Poetry 2.1 or later with the `poetry-plugin-export` plugin.
The local `reference/` directory contains copied examples and is ignored by Git.

From the repository root:

```sh
just lock       # Refresh poetry.lock and exported requirements.txt
just codegen    # Render, format, and sign generated sources
just format     # Format C, Erlang, templates, and Python sources
```

`just docker-codegen` runs generation in a Linux image built by `just docker-build`.
The image caches the locked Python dependencies separately from the host's `.venv`.
Docker helpers also cover formatting, locking, signing, and an interactive shell.

With uv installed, the pinned Poetry/export toolchain can run the lock recipe
without changing the global Poetry installation:

```sh
uvx --from 'poetry==2.5.1' --with 'poetry-plugin-export==1.10.1' just lock
```

`templates0/` renders configured definitions first. The generator then scans C
sources and headers under `c_src/nif/` for literal `ATOM(name)` references and
renders the atom table from `templates1/`. Comments, strings, macro parameters,
and the old generated atom files are excluded from discovery. Explicit atoms in
`config.yaml` preserve atoms that have no literal use in the source yet.

Change the templates or configuration and run `just codegen`; generated C is
committed so ordinary builds do not run the generator. Generated files carry a
content signature applied after formatting, and repeated generation is stable.

The first stage generates `c_src/nif/hash/hash.{c,h}`, the XOF family implementations
under `c_src/nif/xof/`, the Ristretto255 and Decaf448 implementations under their
curve directories, and the native registration table in
`c_src/nif/libdecaf_nif.c`. XOFs expose only grouped entry points; there is
no generic XOF dispatch layer.

Native components own their resource types, destructors, and load functions.
`csprng/` contains the sponge PRNG; `curve25519/` contains Ed25519, X25519, and
Ristretto255; `curve448/` contains Ed448, X448, and Decaf448. Curve folders do not
add a prefix to the native function names. The main NIF file registers functions
and invokes component loaders on initial load and upgrade; it includes no C
implementation fragments.

`context/groups.py` supplies the prime-order group metadata used by the native
templates, registrations, and Erlang bindings. `prime_order_group.c.inc` and
`prime_order_group.h.inc` expand into ordinary `ristretto255.{c,h}` and
`decaf448.{c,h}` files. Each implementation owns its aligned precomputation
tables and resource lifecycle. There are no group-instantiation C macros.

`src/prime_order_group.erl.inc` generates `libdecaf_ristretto255.erl` and
`libdecaf_decaf448.erl` from the same group metadata and native function contracts.
These modules call `libdecaf_nif` directly, document canonical encodings and
validation, and expose an opaque precomputation resource type. Their only
Erlang-side convenience operation is `scalar_random/0`, which reduces wide
random input from `crypto`. RFC 9496 tests exercise both public modules and
execute the examples embedded in their module and function documentation.

`src/legacy_hash.erl.inc` generates the deprecated `libdecaf_sha2`,
`libdecaf_sha3`, and `libdecaf_keccak_sha3` compatibility modules. Their
algorithm lists and default lengths come from the hash/XOF configuration.
They call the current NIF APIs directly while preserving tagged
`{Algorithm, NativeState}` tuples, truncation, SHAKE aliases, and wrapper
argument errors. Module and function documentation points callers to
`libdecaf:hash*` and `libdecaf:xof_sha3*`, which use unwrapped native states.

`nif.kmac` configures KMAC128 and KMAC256. `kmac/kmac.{c,h}` owns its
keyed state and absorb/squeeze continuation resources, using the shared sponge
lifecycle template to emit ordinary component-specific C functions. The KMAC
template constructs both SP 800-185 bytepad prefixes and appends the requested
bit length before squeezing; the Erlang API measures lengths in bytes. This
is length-bound KMAC, so shorter tags must be computed at the requested length.
Its public and native bindings share generated specs, docs, and exports.

`nif.hash` and `nif.xof` are mappings from algorithm names to metadata. Each
entry gives its upstream context struct and operation symbols. XOF entries also
specify their API `group`. Fixed-output hashes
also specify `default_output_len` and `max_output_len` in bytes. Legacy Keccak entries give
their sponge rate. The schema rejects default lengths that exceed the maximum.

The XOF algorithms `keccak_xof_128` and `keccak_xof_256` use the original
Keccak padding (`0x01`) with capacities of 256 and 512 bits and rates of 168
and 136 bytes. Their `legacy_keccak_rate` generates custom initialization with
unlimited output; SHAKE keeps the FIPS 202 padding (`0x1f`). These parameters
follow the [Keccak reference, sections 1.3–1.4](https://keccak.team/files/Keccak-reference-3.0.pdf).

`cshake128` and `cshake256` set `cshake_rate` to 168 and 136 bytes. They use
SHAKE initialization when both additional strings are empty, or SP 800-185
`bytepad(encode_string(N) || encode_string(S), rate)` with padding `0x04`
otherwise. `xof_cshake/5` takes `(Type, Input, Length, FunctionName, Customization)`;
`xof_cshake_init/3` takes `(Type, FunctionName, Customization)`. Prefix absorption
uses the same yielding paths as message absorption, including during initialization.

`turboshake128` and `turboshake256` set `turbo_rate` to 168 and 136 bytes.
They use the last 12 Keccak-p rounds as specified in RFC 9861. `xof_turboshake/3`
and `xof_turboshake_init/1` use domain `0x1f`; `xof_turboshake/4`
and `xof_turboshake_init/2`
accept an explicit domain byte in `1..127`.

`kt128` and `kt256` set `kt_rate` to 168 and 136 bytes. The generated
`xof/xof_kt.c` implements RFC 9861 tree hashing with 8192-byte chunks,
32/64-byte chaining values, and two fixed-size sponge states. `xof_kt/4`
takes a customization string as its fourth argument for KT algorithms.
Incremental hashing uses `xof_kt_init/1`, `xof_kt_update/2`, and
`xof_kt_final/3`, which appends customization and its RFC length encoding.
`xof_kt/3` and `xof_kt_final/2` use empty customization.

The generated fixed-output C contains typed upstream adapters and an algorithm
table. Its shared `hash`, `hash_init`, `hash_update`, and `hash_final` entry points
are defined in `hash/hash.c`, and all fixed-output algorithms use one opaque
`hash_state()` type. Algorithm-specific hash wrappers are not generated.

Each XOF group generates one-shot, init, update, and final NIFs. XOF groups are
`xof_cshake`, `xof_keccak`, `xof_kt`, `xof_sha3` (SHAKE), and
`xof_turboshake`. An algorithm atom selects a variant during initialization
or one-shot hashing. Each group has its own opaque Erlang state type, and native
entry points reject algorithms and states from other groups. Resources retain
the selected algorithm, so updates and finalization need neither an extra
algorithm argument nor an Erlang record wrapper.
XOF entry points are defined and declared in `xof/xof_<group>.{c,h}`;
`libdecaf_nif.c` registers them.

Each XOF family owns its native state, resource destructor, absorb continuation,
and squeeze continuation. There is no cross-family state union or operation
table. cSHAKE prefix encoding, TurboSHAKE domain selection, and KT tree hashing
and customization live only in their respective implementations. The generator
expands `xof/lifecycle.c.inc` and `xof/entry_points.c.inc` into ordinary
C functions with family-specific names, so stack traces identify the family.
Absorption and output share a bounded reduction budget. Pending absorption
retains its input environment; pending output owns its binary. Destructors erase
the private state and release these allocations if the caller exits mid-call.

The cSHAKE group accepts function-name and customization iodata in
`xof_cshake/5` and `xof_cshake_init/3`. The TurboSHAKE group accepts an
integer domain in `xof_turboshake/4` and `xof_turboshake_init/2`.
KT accepts customization iodata in `xof_kt/4` and `xof_kt_final/3`.
Each group also provides an overload using its default parameters.

`templates0/src/libdecaf.erl.j2` generates the public Erlang API. Its fixed-output hash
functions delegate to the generic hash NIFs. Its grouped XOF functions, docs,
and specs use the same metadata as the NIF interface, and its state types alias
the corresponding native opaque types. The generic `xof`, `xof_init`,
`xof_update`, and `xof_final` APIs have been removed from both modules.

Dialyzer distinguishes the opaque state types and rejects calls that mix groups.
The current Eqwalizer treats these resource-backed opaque types structurally;
it checks algorithm atoms and parameter types, but does not distinguish the state
groups. Native checks enforce group isolation regardless of the static analyzer.
To run positive and deliberately invalid examples through both analyzers:

```sh
cd codegen
LIBDECAF_TYPECHECK=1 poetry run pytest tests/test_typecheck.py
```

This requires `gmake elp` and an installed Dialyzer. It builds a temporary OTP PLT;
set `LIBDECAF_TYPECHECK_PLT` to reuse an existing PLT for the current OTP version.
The regular Python test run leaves these integration checks disabled.

`templates0/src/libdecaf_nif.erl.j2` generates the Erlang NIF module, using
`src/erlang_libdecaf_codegen/context/functions.py` for native exports, specs, and
documentation. Module initialization is written directly in the template's final
internal section. Definitions, types, and exports are sorted by name and arity.
Function specs name every argument and the result, with their types collected
in a `when` clause. The same spec renderer serves the native and public bindings.
The codegen recipe formats C and Erlang output before applying content signatures.
Native Markdown documentation requires OTP 27 or later; CI exercises the latest
OTP 28 and OTP 29 releases.
