~J{ macro implementation(group) }.
~J{ set module = 'libdecaf_' + group.name }.
~J{ set prefix = group.name + '_' }.
~J{ set native_functions = ctx.nif.functions | selectattr('group', 'equalto', group.title) | list }.
~J{ set names = ((native_functions | map(attribute='name') | list) + [prefix + 'scalar_random']) | sort }.
%%% % @format
-module(~J< module >.).
-moduledoc """
~J< group.title >. prime-order group arithmetic, backed directly by `m:libdecaf_nif`.

Implements the group operations and element derivation specified in
[RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html).
Points use the canonical ~J< group.encoding_bytes >.-byte ~J< group.title >. encoding. Scalars are
unsigned little-endian integers in exactly ~J< group.encoding_bytes >. bytes, strictly smaller
than the group order `l`:

~J{ if group.bits == 255 }.
    l = 2^252 + 27742317777372353535851937790883648493
~J{ else }.
    l = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885
~J{ endif }.

Point and scalar binaries have the same length but different meanings. Use
`point_is_valid/1` and `scalar_is_canonical/1` to validate untrusted inputs.
The Erlang binary types describe their size; native operations validate their
contents. Arithmetic accepts the identity point and scalar zero, and raises
`badarg` for invalid operands. `scalar_invert/1` returns `error` for zero.
These encodings are specific to this group; EdDSA and X25519/X448 keys use
different formats and cannot be substituted for group points or scalars.

Use `scalar_reduce/1` to encode an integer modulo `l`, or `scalar_random/0`
to generate a scalar with negligible reduction bias. Scalars are not clamped.
For example, multiplication by three agrees with repeated point addition:

```erlang
Three = ~J< module >.:scalar_reduce(<<3>>),
Base = ~J< module >.:base(),
Point = ~J< module >.:base_scalarmul(Three),
Point = ~J< module >.:point_add(Base, ~J< module >.:point_double(Base)).
```

`point_from_hash/1` consumes exactly ~J< group.encoding_bytes * 2 >. bytes of prepared input; it does
not hash a message itself. Use a protocol-defined, domain-separated hash/XOF
construction to derive those bytes. `point_from_hash_nonuniform/1` exposes
the single-map operation for protocols that specifically need it.

`precompute/1` creates an immutable native multiplication table for reuse with
`precomputed_scalarmul/2`. Tables belong to this group, can be shared between
processes, and are released automatically when no references remain. Ordinary
operations return canonical binaries and do not mutate their inputs.
""".
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

-export([
~J{ for name in names }.
~J{ if name == prefix + 'scalar_random' }.
    scalar_random/0,
~J{ else }.
~J{ set function = native_functions | selectattr('name', 'equalto', name) | first }.
    ~J< name.removeprefix(prefix) >./~J< function.arity >.~J< ',' if not loop.last else '' >.
~J{ endif }.
~J{ endfor }.
]).
-export_type([
    point/0,
    precomputed/0,
    scalar/0
]).

%%% Types

-doc """
A canonical ~J< group.encoding_bytes >.-byte ~J< group.title >. point encoding, including the identity.
Use `point_is_valid/1` to check the encoded contents at runtime.
""".
-type point() :: <<_:~J< group.encoding_bytes * 8 >.>>.

-doc """
An immutable native multiplication table for a ~J< group.title >. point.
Created by `precompute/1` and usable only with this group's `precomputed_scalarmul/2`.
""".
-opaque precomputed() :: erlang:nif_resource().

-doc """
A canonical ~J< group.encoding_bytes >.-byte unsigned little-endian integer smaller than `l`.
Zero is valid. Use `scalar_is_canonical/1` to validate an encoding or
`scalar_reduce/1` to reduce an integer into this field.
""".
-type scalar() :: <<_:~J< group.encoding_bytes * 8 >.>>.

%%%=============================================================================
%%% ~J< group.title >. API functions
%%%=============================================================================

~J{ for name in names }.
~J{ set operation = name.removeprefix(prefix) }.
~J{ if operation == 'scalar_random' }.
-doc """
Generate a canonical scalar using `crypto:strong_rand_bytes/1`.

Reduces ~J< group.encoding_bytes * 2 >. cryptographically random bytes modulo the group order. The
result has negligible reduction bias and can be zero. Protocols requiring a
nonzero scalar must retry when zero is returned. Random-source failures
propagate from `crypto`.

```erlang
Scalar = ~J< module >.:scalar_random(),
true = ~J< module >.:scalar_is_canonical(Scalar).
```
""".
-spec scalar_random() -> Scalar when Scalar :: scalar().
scalar_random() ->
    scalar_reduce(crypto:strong_rand_bytes(~J< group.encoding_bytes * 2 >.)).

~J{ else }.
~J{ set function = native_functions | selectattr('name', 'equalto', name) | first }.
-doc """
~J< function.doc >.
~J{ if operation == 'base_scalarmul' }.

```erlang
One = ~J< module >.:scalar_reduce(<<1>>),
Base = ~J< module >.:base(),
Base = ~J< module >.:base_scalarmul(One).
```
~J{ elif operation == 'point_from_hash' }.

For a random group element, prepare uniformly random input:

```erlang
UniformBytes = crypto:strong_rand_bytes(~J< group.encoding_bytes * 2 >.),
Point = ~J< module >.:point_from_hash(UniformBytes),
true = ~J< module >.:point_is_valid(Point).
```
~J{ elif operation == 'precompute' }.

```erlang
Point = ~J< module >.:point_double(~J< module >.:base()),
Table = ~J< module >.:precompute(Point),
Scalar = ~J< module >.:scalar_reduce(<<7>>),
Product = ~J< module >.:point_scalarmul(Point, Scalar),
Product = ~J< module >.:precomputed_scalarmul(Table, Scalar).
```
~J{ elif operation == 'scalar_halve' }.

```erlang
One = ~J< module >.:scalar_reduce(<<1>>),
Half = ~J< module >.:scalar_halve(One),
One = ~J< module >.:scalar_add(Half, Half).
```
~J{ elif operation == 'scalar_invert' }.

```erlang
Scalar = ~J< module >.:scalar_reduce(<<7>>),
Inverse = ~J< module >.:scalar_invert(Scalar),
One = ~J< module >.:scalar_reduce(<<1>>),
One = ~J< module >.:scalar_mul(Scalar, Inverse),
error = ~J< module >.:scalar_invert(~J< module >.:scalar_reduce(<<>>)).
```
~J{ elif operation == 'scalar_reduce' }.

```erlang
Scalar = ~J< module >.:scalar_reduce(<<1, 2>>),
513 = binary:decode_unsigned(Scalar, little),
true = ~J< module >.:scalar_is_canonical(Scalar).
```
~J{ endif }.
""".
-spec ~J< function.spec | replace(prefix, '') >..
~J< operation >.(~J< function.arguments | map(attribute='name') | join(', ') >.) ->
    libdecaf_nif:~J< name >.(~J< function.arguments | map(attribute='name') | join(', ') >.).

~J{ endif }.
~J{ endfor }.
~J{ endmacro }.
