~J{ macro implementation(module, title, hashes, created, xofs=()) }.
~J{ set algorithm = hashes[0] }.
~J{ set hash_migration = 'Use libdecaf hash family functions and hash_init/1, hash_update/2, hash_final/1 instead.' }.
~J{ set xof_migration = ' For SHAKE, use libdecaf:xof/3 and libdecaf:xof_init/1, xof_absorb/2, xof_squeeze/2.' if xofs else '' }.
%%% % @format
-module(~J< module >.).
-moduledoc """
Deprecated compatibility API for ~J< title >. with tagged, immutable states.

New code should use `libdecaf:hash/2,3`, `libdecaf:hash_init/1`,
`libdecaf:hash_update/2`, and `libdecaf:hash_final/1` directly.
~J{ if xofs }.
For SHAKE, use `libdecaf:xof/3`, `libdecaf:xof_init/1`,
`libdecaf:xof_absorb/2`, and `libdecaf:xof_squeeze/2`.
~J{ endif }.

This module retains the historical `{Algorithm, NativeState}` wrapper and
delegates directly to `m:libdecaf_nif`. Updates return a new wrapped state;
updating and finalizing leave the input state reusable. The replacement APIs
take the native state directly, without the algorithm tuple.

Fixed-output algorithms and their default digest lengths:

~J{ for name in hashes }.
* `~J< name >.`: ~J< ctx.schema.nif.hash[name].default_output_len >. bytes.
~J{ endfor }.
~J{ if xofs }.

SHAKE algorithms are `~J< xofs | join('`, `') >.`. They require an explicit
output length with `hash/3`, `xof/3`, or `final/2`; `hash/2` and `final/1`
accept only fixed-output hashes.
~J{ endif }.

Lengths are in bytes. Fixed-output hashes allow truncation from zero bytes
through the algorithm's maximum digest length. Input accepts iodata.
An unsupported selector or state wrapper raises `{badarg, Arguments}`;
invalid native states, data, and lengths raise a native argument error.

For example, the replacement incremental API needs no wrapper:

```erlang
State0 = libdecaf:hash_init(~J< algorithm >.),
State1 = libdecaf:hash_update(State0, [<<"a">>, <<"bc">>]),
Digest = libdecaf:hash_final(State1),
Digest = libdecaf:hash(~J< algorithm >., <<"abc">>).
```
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "~J< created >.", modified => "2026-10-23"}.
-moduledoc #{copyright => "Andrew Bennett"}.
-moduledoc #{deprecated => "~J< hash_migration >.~J< xof_migration >."}.
-compile(warn_missing_spec_all).
-deprecated(module).

%% Compatibility API
-export([
    final/1,
    final/2,
    hash/2,
    hash/3,
    init/1,
    update/2~J< ',' if xofs else '' >.
~J{ if xofs }.
    xof/3
~J{ endif }.
]).

%% Types

-doc """
Algorithms accepted by this compatibility module.
""".
-type algorithm() :: hash_algorithm()~J< ' | xof_algorithm()' if xofs else '' >..
-doc """
Fixed-output algorithms supported by this module.
""".
-type hash_algorithm() :: ~J< hashes | join(' | ') >..
-doc """
A legacy `{Algorithm, NativeState}` tuple for a fixed-output hash.
""".
-type hash_state() :: {hash_algorithm(), libdecaf_nif:hash_state()}.
-doc """
An immutable tagged hash~J< ' or SHAKE' if xofs else '' >. state returned by `init/1` or `update/2`.
""".
-type state() :: hash_state()~J< ' | xof_state()' if xofs else '' >..
~J{ if xofs }.
-doc """
SHAKE algorithms accepted by `hash/3`, `xof/3`, and `init/1`.
""".
-type xof_algorithm() :: ~J< xofs | join(' | ') >..
-doc """
A legacy `{Algorithm, NativeState}` tuple for SHAKE.
""".
-type xof_state() :: {xof_algorithm(), libdecaf_nif:xof_state()}.
~J{ endif }.

-export_type([
    algorithm/0,
    hash_algorithm/0,
    hash_state/0,
    state/0~J< ',' if xofs else '' >.
~J{ if xofs }.
    xof_algorithm/0,
    xof_state/0
~J{ endif }.
]).

%%%=============================================================================
%%% Compatibility API functions
%%%=============================================================================

-doc """
Return a fixed-output digest using the algorithm's default length.
The wrapped state remains reusable.
~J{ if xofs }.
SHAKE requires `final/2`.
~J{ endif }.
""".
-doc #{deprecated => "Use libdecaf:hash_final/1 with an unwrapped hash state."}.
-spec final(State) -> Digest when State :: hash_state(), Digest :: binary().
~J{ for name in hashes }.
final({~J< name >., State}) ->
    libdecaf_nif:hash_final(State);
~J{ endfor }.
final(State) ->
    erlang:error({badarg, [State]}).

-doc """
Return `Length` bytes without changing the wrapped state.
Fixed-output hashes return a digest prefix and reject lengths above their
maximum.
~J{ if xofs }.
SHAKE accepts any nonnegative output length.
~J{ endif }.
""".
-doc #{deprecated => "Use libdecaf:hash_final/1~J< ' or libdecaf:xof_squeeze/2' if xofs else '' >. with an unwrapped state."}.
-spec final(State, Length) -> Digest when State :: state(), Length :: non_neg_integer(), Digest :: binary().
~J{ for name in hashes }.
final({~J< name >., State}, Length) ->
    binary:part(libdecaf_nif:hash_final(State), 0, Length);
~J{ endfor }.
~J{ for name in xofs }.
final({~J< name >., State}, Length) ->
    element(2, libdecaf_nif:xof_squeeze(State, Length));
~J{ endfor }.
final(State, Length) ->
    erlang:error({badarg, [State, Length]}).

-doc """
Hash iodata using the algorithm's default digest length.
~J{ if xofs }.
SHAKE requires an explicit output length with `hash/3` or `xof/3`.
~J{ endif }.
""".
-doc #{deprecated => "Use libdecaf:hash/2."}.
-spec hash(Type, Data) -> Digest when Type :: hash_algorithm(), Data :: iodata(), Digest :: binary().
~J{ for name in hashes }.
hash(~J< name >., Data) ->
    libdecaf_nif:~J< name >.(Data, ~J< ctx.schema.nif.hash[name].default_output_len >.);
~J{ endfor }.
hash(Type, Data) ->
    erlang:error({badarg, [Type, Data]}).

-doc """
Hash iodata and return exactly `Length` bytes.
Fixed-output hashes allow truncation up to their maximum digest length.
~J{ if xofs }.
SHAKE produces the requested number of XOF bytes, including zero.
~J{ endif }.
""".
-doc #{deprecated => "Use libdecaf:hash/2~J< ' or libdecaf:xof/3 for SHAKE' if xofs else '' >.."}.
-spec hash(Type, Data, Length) -> Digest when
    Type :: algorithm(), Data :: iodata(), Length :: non_neg_integer(), Digest :: binary().
~J{ for name in hashes }.
hash(~J< name >., Data, Length) ->
    libdecaf_nif:~J< name >.(Data, Length);
~J{ endfor }.
~J{ for name in xofs }.
hash(~J< name >., Data, Length) ->
    libdecaf_nif:~J< name >.(Data, Length);
~J{ endfor }.
hash(Type, Data, Length) ->
    erlang:error({badarg, [Type, Data, Length]}).

-doc """
Initialize an immutable `{Type, NativeState}` tuple.
Pass the returned tuple to `update/2` and `final/1,2` in this module.
~J{ if xofs }.
SHAKE states can only be finalized with an explicit output length.
~J{ endif }.
""".
-doc #{deprecated => "Use libdecaf:hash_init/1~J< ' or libdecaf:xof_init/1' if xofs else '' >.; retain the unwrapped state."}.
-spec init(Type) -> State when Type :: algorithm(), State :: state().
~J{ for name in hashes }.
init(~J< name >.) ->
    {~J< name >., libdecaf_nif:hash_init(~J< name >.)};
~J{ endfor }.
~J{ for name in xofs }.
init(~J< name >.) ->
    {~J< name >., libdecaf_nif:~J< name >._xof_init()};
~J{ endfor }.
init(Type) ->
    erlang:error({badarg, [Type]}).

-doc """
Absorb iodata and return a new `{Algorithm, NativeState}` tuple.
The algorithm tag is preserved and the input tuple remains reusable.
""".
-doc #{deprecated => "Use libdecaf:hash_update/2~J< ' or libdecaf:xof_absorb/2' if xofs else '' >. with an unwrapped state."}.
-spec update(State, Data) -> NewState when State :: state(), Data :: iodata(), NewState :: state().
~J{ for name in hashes }.
update({~J< name >., State}, Data) ->
    {~J< name >., libdecaf_nif:hash_update(State, Data)};
~J{ endfor }.
~J{ for name in xofs }.
update({~J< name >., State}, Data) ->
    {~J< name >., libdecaf_nif:xof_absorb(State, Data)};
~J{ endfor }.
update(State, Data) ->
    erlang:error({badarg, [State, Data]}).
~J{ if xofs }.

-doc """
Return `Length` SHAKE bytes from iodata in one call.
This preserves the historical `xof/3` alias for SHAKE through `hash/3`.
""".
-doc #{deprecated => "Use libdecaf:xof/3."}.
-spec xof(Type, Data, Length) -> Output when
    Type :: xof_algorithm(), Data :: iodata(), Length :: non_neg_integer(), Output :: binary().
~J{ for name in xofs }.
xof(~J< name >., Data, Length) ->
    libdecaf_nif:~J< name >.(Data, Length);
~J{ endfor }.
xof(Type, Data, Length) ->
    erlang:error({badarg, [Type, Data, Length]}).
~J{ endif }.
~J{ endmacro }.
