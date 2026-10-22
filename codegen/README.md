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
entry gives the upstream context struct and operation symbols. Fixed-output hashes
also specify `default_output_len` and `max_output_len` in bytes. Legacy Keccak entries give
their sponge rate. The schema rejects default lengths that exceed the maximum.

The generated C contains typed upstream adapters, algorithm tables, resource
layouts, and lookups by atom or resource type. Only the generic `hash`,
`hash_init`, `hash_update`, `hash_final`, and corresponding `hash_xof*` NIFs are
exported. Resources retain the selected algorithm, so updates and finalization
need neither an extra algorithm argument nor an Erlang record wrapper.
Scheduling and immutable state copying remain in the generated C implementation.

`templates0/src/libdecaf.erl.j2` generates the public Erlang API. Its hash
functions delegate directly to the generic NIFs. Algorithm types still come
from the same configuration; state types are opaque native resource handles.

`templates0/src/libdecaf_nif.erl.j2` generates the Erlang NIF module, using
`src/erlang_libdecaf_codegen/context/functions.py` for native exports, specs, and
documentation. Module initialization is written directly in the template's final
internal section. Definitions, types, and exports are sorted by name and arity.
The codegen recipe formats C and Erlang output before applying content signatures.
Native Markdown documentation requires OTP 27 or later; CI exercises the latest
OTP 28 and OTP 29 releases.
