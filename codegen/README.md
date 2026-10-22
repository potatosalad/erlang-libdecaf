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

The first stage generates `c_src/nif/hash.{c,h}`, `c_src/nif/hash_xof.{c,h}`,
and the native registration table in `c_src/nif/libdecaf_nif.c`.

`nif.hash` and `nif.xof` are mappings from algorithm names to metadata. Each
entry gives its API `group`, upstream context struct, and operation symbols. Fixed-output hashes
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
otherwise. `hash_xof/5` takes `(Type, Input, Length, FunctionName, Customization)`;
`hash_xof_init/3` takes `(Type, FunctionName, Customization)`. Prefix absorption
uses the same yielding paths as message absorption, including during initialization.

`turboshake128` and `turboshake256` set `turbo_rate` to 168 and 136 bytes.
They use the last 12 Keccak-p rounds as specified in RFC 9861. `hash_xof/3`
and `hash_xof_init/1` use domain `0x1f`; `hash_xof/4` and `hash_xof_init/2`
accept an explicit domain byte in `1..127`.

`kt128` and `kt256` set `kt_rate` to 168 and 136 bytes. The generated
`hash_xof_kt.{c,h}` implements RFC 9861 tree hashing with 8192-byte chunks,
32/64-byte chaining values, and two fixed-size sponge states. `hash_xof/4`
takes a customization string as its fourth argument for KT algorithms.
Incremental hashing uses `hash_xof_init/1`, `hash_xof_update/2`, and
`hash_xof_final/3`, which appends customization and its RFC length encoding.
The existing `hash_xof/3` and `hash_xof_final/2` use empty customization.

The generated C contains typed upstream adapters, algorithm tables, resource
layouts, and lookups by atom or resource type. Each configured group generates
one-shot, init, update, and final NIFs. Fixed-output groups are `hash_keccak`,
`hash_sha2`, and `hash_sha3`; XOF groups are `hash_xof_cshake`, `hash_xof_keccak`,
`hash_xof_kt`, `hash_xof_sha3` (SHAKE), and `hash_xof_turboshake`.
An algorithm atom selects a variant during initialization or one-shot hashing.
Each group has its own opaque Erlang state type, and native entry points reject
algorithms and states from other groups. Resources retain the selected algorithm,
so updates and finalization need neither an extra algorithm argument nor an
Erlang record wrapper. The entry points are defined in `hash.c`/`hash_xof.c`
and declared in their corresponding headers; `libdecaf_nif.c` registers them.
Scheduling and immutable state copying remain in the shared native engines.

The cSHAKE group accepts function-name and customization iodata in
`hash_xof_cshake/5` and `hash_xof_cshake_init/3`. The TurboSHAKE group accepts an
integer domain in `hash_xof_turboshake/4` and `hash_xof_turboshake_init/2`.
KT accepts customization iodata in `hash_xof_kt/4` and `hash_xof_kt_final/3`.
Each group also provides an overload using its default parameters.

`templates0/src/libdecaf.erl.j2` generates the public Erlang API. Its hash
functions delegate directly to the generic NIFs. Algorithm types still come
from the same configuration; state types are opaque native resource handles.
These existing generic convenience APIs remain available alongside the grouped NIFs.

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
The codegen recipe formats C and Erlang output before applying content signatures.
Native Markdown documentation requires OTP 27 or later; CI exercises the latest
OTP 28 and OTP 29 releases.
