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

The first stage also generates `c_src/nif/libdecaf_nif.c`. Its hash and XOF
declarations, wrappers, and NIF registrations come from `nif.hash` and
`nif.xof` in `config.yaml`. The committed C contains explicit functions and
registration entries, so debuggers and sanitizer reports can refer to each
wrapper's own source lines. Algorithm names also seed the atom table.

`templates0/src/libdecaf_nif.erl.j2` generates the Erlang NIF module. The codegen
recipe formats both C and Erlang output before applying content signatures.

`templates0/src/libdecaf.erl.j2` generates the public hash API from `nif.hash`.
The algorithm union, per-algorithm records and opaque state types, and all hash
operations share that list. Add or remove an algorithm there and regenerate;
the one-shot, init, update, final, and digest-size clauses stay in sync.

The Erlang module's native exports, entry points, documentation, and specs are
rendered from `src/erlang_libdecaf_codegen/context/functions.py`. Module
initialization is written directly in the Erlang template, in an internal section
below the native functions. Native API definitions and exports are sorted by
name and arity. Hash and SHAKE profiles use
the same singular `nif.hash` and `nif.xof` configuration as C. Keep
resource contracts and native argument/return behavior in sync when adding an
operation. Native Markdown documentation requires Erlang/OTP 27 or later;
CI exercises the latest OTP 28 and OTP 29 releases.
