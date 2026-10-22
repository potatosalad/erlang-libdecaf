%%% % @format
-module(libdecaf_spongerng).
-moduledoc """
Sponge-based pseudorandom byte generation.

Initialize from seed bytes, a file, or `/dev/urandom`. Operations return new
states; retain the returned state to advance the stream.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2018-11-30", modified => "2026-10-22"}.
-moduledoc #{copyright => "Andrew Bennett"}.

%% API
-export([
    init_from_buffer/2,
    init_from_file/3,
    init_from_dev_urandom/0,
    next/2,
    stir/2
]).

%% Macros
-define(WRAP_STATE(T, R),
    case R of
        {NewState, Result} when is_reference(NewState) ->
            {{T, NewState}, Result};
        NewState when is_reference(NewState) ->
            {T, NewState};
        Other ->
            Other
    end
).

%%%===================================================================
%%% API functions
%%%===================================================================

init_from_buffer(In, Deterministic) when is_boolean(Deterministic) ->
    ?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_buffer(In, Deterministic)).

init_from_file(Filename, Inlen, Deterministic) when is_boolean(Deterministic) ->
    ?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_file(Filename, Inlen, Deterministic)).

init_from_dev_urandom() ->
    ?WRAP_STATE(spongerng, libdecaf:spongerng_init_from_dev_urandom()).

next({spongerng, State}, Outlen) ->
    ?WRAP_STATE(spongerng, libdecaf:spongerng_next(State, Outlen)).

stir({spongerng, State}, In) ->
    ?WRAP_STATE(spongerng, libdecaf:spongerng_stir(State, In)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
