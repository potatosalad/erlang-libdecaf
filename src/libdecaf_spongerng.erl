%%% % @format
-module(libdecaf_spongerng).
-moduledoc """
Generate pseudorandom bytes with the upstream Keccak sponge PRNG.

Initialize from seed bytes, a file, or the operating system's random source.
`next/2` and `stir/2` return new immutable states. Keep the returned state to
advance the generator; reusing an earlier deterministic state repeats its output.
The Erlang state keeps the existing `{spongerng, NativeState}` representation.

For reproducible output, pass `true` as `Deterministic` and use the same seed and
sequence of calls with the same library version. The requested length is part of
each generation operation: one 32-byte request differs from two 16-byte requests,
and even a zero-byte request advances the state.

```erlang
S0 = libdecaf_spongerng:init_from_buffer(<<>>, true),
{S1, First} = libdecaf_spongerng:next(S0, 16),
<<"2ED664354AA87699BE93C3B62715A256">> = binary:encode_hex(First),
{_S2, Second} = libdecaf_spongerng:next(S1, 16),
true = First =/= Second,
{_RepeatedState, First} = libdecaf_spongerng:next(S0, 16).
```

For random output, initialize with `init_from_dev_urandom/0`. Passing `false`
to the other initializers allows upstream to mix in platform-dependent CPU data;
the seed supplied to those initializers is still the caller's responsibility.
State resources are released and erased when no references remain.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2018-11-30", modified => "2026-10-24"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-compile(warn_missing_spec_all).

%% PRNG API
-export([
    init_from_buffer/2,
    init_from_file/3,
    init_from_dev_urandom/0,
    next/2,
    stir/2
]).

%% Types
-doc """
Whether to disable upstream's additional CPU data and produce reproducible output.
""".
-type deterministic() :: boolean().
-doc """
Seed or additional data accepted as iodata.
""".
-type seed() :: iodata().
-doc """
An immutable wrapped native PRNG state. Retain returned states to advance it.
""".
-opaque state() :: {spongerng, libdecaf_nif:spongerng_state()}.

-export_type([
    deterministic/0,
    seed/0,
    state/0
]).

%%%=============================================================================
%%% PRNG API functions
%%%=============================================================================

-doc """
Initialize from seed bytes, including an empty seed.
With `Deterministic = true`, the same seed and subsequent calls reproduce the
same output. With `false`, upstream can mix CPU data into generation operations.
This function does not read the operating system's random source.

```erlang
S0 = libdecaf_spongerng:init_from_buffer([<<"seed">>, <<" bytes">>], true),
{_S1, Bytes} = libdecaf_spongerng:next(S0, 32),
32 = byte_size(Bytes).
```
""".
-spec init_from_buffer(Seed, Deterministic) -> State when
    Seed :: seed(), Deterministic :: deterministic(), State :: state().
init_from_buffer(Seed, Deterministic) when is_boolean(Deterministic) ->
    {spongerng, libdecaf_nif:spongerng_csprng_init_from_buffer(Seed, Deterministic)}.

-doc """
Initialize by reading exactly `InputLength` bytes from the start of a file.
`Filename` is a nonempty path expressed as native filename bytes (iodata), and
`InputLength` must be positive. Failure to open or read enough bytes raises an
exception. `Deterministic` has the same meaning as in `init_from_buffer/2`.

```erlang
ok = file:write_file("sponge-seed.bin", <<"example seed">>),
S0 = libdecaf_spongerng:init_from_file("sponge-seed.bin", 12, true),
{_S1, Bytes} = libdecaf_spongerng:next(S0, 16),
16 = byte_size(Bytes),
ok = file:delete("sponge-seed.bin").
```
""".
-spec init_from_file(Filename, InputLength, Deterministic) -> State when
    Filename :: iodata(), InputLength :: pos_integer(), Deterministic :: deterministic(), State :: state().
init_from_file(Filename, InputLength, Deterministic) when is_boolean(Deterministic) ->
    {spongerng, libdecaf_nif:spongerng_csprng_init_from_file(Filename, InputLength, Deterministic)}.

-doc """
Initialize a nondeterministic PRNG from 64 bytes of operating-system randomness.
Upstream reads `/dev/urandom`, or uses its platform equivalent on Windows.
Failure to obtain the seed raises an exception.

```erlang
S0 = libdecaf_spongerng:init_from_dev_urandom(),
{_S1, Bytes} = libdecaf_spongerng:next(S0, 32),
32 = byte_size(Bytes).
```
""".
-spec init_from_dev_urandom() -> State when State :: state().
init_from_dev_urandom() ->
    {spongerng, libdecaf_nif:spongerng_csprng_init_from_dev_urandom()}.

-doc """
Generate `OutputLength` bytes and return the next state with the output.
The input state remains unchanged. Request lengths and call boundaries affect
future output; a zero-length request returns `<<>>` and still advances the state.

```erlang
S0 = libdecaf_spongerng:init_from_buffer(<<"seed">>, true),
{S1, First} = libdecaf_spongerng:next(S0, 16),
{_S2, Second} = libdecaf_spongerng:next(S1, 16),
16 = byte_size(First),
16 = byte_size(Second).
```
""".
-spec next(State, OutputLength) -> {NextState, Output} when
    State :: state(), OutputLength :: non_neg_integer(), NextState :: state(), Output :: binary().
next({spongerng, State}, OutputLength) ->
    {NextState, Output} = libdecaf_nif:spongerng_csprng_next(State, OutputLength),
    {{spongerng, NextState}, Output}.

-doc """
Mix additional seed bytes into a new state without returning output.
The input state remains unchanged. Stirring even an empty input changes the state.
The caller supplies any entropy in `Seed`.

```erlang
S0 = libdecaf_spongerng:init_from_buffer(<<"seed">>, true),
S1 = libdecaf_spongerng:stir(S0, [<<"additional">>, <<" seed">>]),
{_S2, Bytes} = libdecaf_spongerng:next(S1, 16),
16 = byte_size(Bytes).
```
""".
-spec stir(State, Seed) -> NextState when
    State :: state(), Seed :: seed(), NextState :: state().
stir({spongerng, State}, Seed) ->
    {spongerng, libdecaf_nif:spongerng_csprng_stir(State, Seed)}.
