%%% % @format
-module(fips_testvector).
-compile(warn_missing_spec_all).
-moduledoc """
Parse cryptographic test-vector response files for the Common Test suites.
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2015-08-12", modified => "2026-10-22"}.
-moduledoc #{copyright => "Andrew Bennett"}.

%% API
-export([
    from_binary/1,
    from_file/1,
    to_binary/1,
    to_file/2
]).

%%====================================================================
%% API functions
%%====================================================================

-type entry() ::
    {flag, binary()}
    | {option, {binary(), binary()}}
    | {token, binary()}
    | {vector, {binary(), binary()}, hex | raw}
    | {vector, {binary(), integer()}, int}.
-export_type([
    entry/0
]).

-spec from_binary(Input) -> Result when Input :: binary(), Result :: [entry()].
from_binary(Binary) ->
    Lines = binary:split(Binary, [<<$\n>>, <<$\r>>], [global, trim]),
    parse_lines(Lines, []).

-spec from_file(File) -> Result when
    File :: file:filename_all(), Result :: [entry()] | {error, file:posix() | badarg | system_limit | terminated}.
from_file(File) ->
    case file:read_file(File) of
        {ok, Binary} ->
            from_binary(Binary);
        ReadError ->
            ReadError
    end.

-spec to_binary(Vectors) -> Result when Vectors :: [entry()], Result :: binary().
to_binary(Vectors) when is_list(Vectors) ->
    <<
        <<
            (case Vector of
                {flag, Flag} ->
                    <<$[, Flag/binary, $], $\n>>;
                {option, {Key, Val}} ->
                    <<$[, Key/binary, $\s, $=, $\s, Val/binary, $], $\n>>;
                {token, Token} ->
                    <<Token/binary, $\n>>;
                {vector, {Key, Val}, hex} ->
                    <<Key/binary, $\s, $=, $\s, (hex:bin_to_hex(Val))/binary, $\n>>;
                {vector, {Key, Val}, int} ->
                    <<Key/binary, $\s, $=, $\s, (integer_to_binary(Val))/binary, $\n>>;
                {vector, {Key, Val}, raw} ->
                    <<Key/binary, $\s, $=, $\s, Val/binary, $\n>>
            end)/binary
        >>
     || Vector <- Vectors
    >>.

-spec to_file(File, Vectors) -> Result when
    File :: file:filename_all(),
    Vectors :: [entry()],
    Result :: ok | {error, file:posix() | badarg | system_limit | terminated}.
to_file(File, Vectors) when is_list(Vectors) ->
    Binary = to_binary(Vectors),
    file:write_file(File, Binary).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
-spec parse_lines(Lines, Accumulator) -> Result when Lines :: [binary()], Accumulator :: [entry()], Result :: [entry()].
parse_lines([], Acc) ->
    lists:reverse(Acc);
parse_lines([Line | Lines], Acc) ->
    case parse_line(Line) of
        skip ->
            parse_lines(Lines, Acc);
        Term ->
            parse_lines(Lines, [Term | Acc])
    end.

%% @private
-spec parse_line(Line) -> Result when Line :: binary(), Result :: entry() | skip.
parse_line(<<$#, _/binary>>) ->
    skip;
parse_line(<<$\s, Rest/binary>>) ->
    parse_line(Rest);
parse_line(<<$\t, Rest/binary>>) ->
    parse_line(Rest);
parse_line(<<$[, Rest/binary>>) ->
    parse_option(Rest);
parse_line(<<>>) ->
    skip;
parse_line(Rest) ->
    parse_vector(Rest).

%% @private
-spec parse_option(Input) -> Result when Input :: binary(), Result :: entry().
parse_option(Rest) ->
    case binary:match(Rest, <<$]>>) of
        {OptionEndPos, 1} ->
            case binary:match(Rest, <<$=>>) of
                {EqualPos, 1} when EqualPos < OptionEndPos ->
                    Key = parse_option_key(binary:part(Rest, 0, EqualPos), <<>>),
                    Val = parse_option_val(binary:part(Rest, EqualPos + 1, OptionEndPos - EqualPos - 1), <<>>),
                    {option, {Key, Val}};
                _ ->
                    Flag = binary:part(Rest, 0, OptionEndPos),
                    {flag, Flag}
            end;
        _ ->
            erlang:error({badarg, [Rest]})
    end.

%% @private
-spec parse_option_key(Input, Key) -> Result when Input :: binary(), Key :: binary(), Result :: binary().
parse_option_key(<<$\s, Rest/binary>>, Key) ->
    parse_option_key(Rest, Key);
parse_option_key(<<$\t, Rest/binary>>, Key) ->
    parse_option_key(Rest, Key);
parse_option_key(<<C, Rest/binary>>, Key) ->
    parse_option_key(Rest, <<Key/binary, C>>);
parse_option_key(<<>>, Key) ->
    Key.

%% @private
-spec parse_option_val(Input, Value) -> Result when Input :: binary(), Value :: binary(), Result :: binary().
parse_option_val(<<$\s, Rest/binary>>, Val) ->
    parse_option_val(Rest, Val);
parse_option_val(<<$\t, Rest/binary>>, Val) ->
    parse_option_val(Rest, Val);
parse_option_val(<<C, Rest/binary>>, Val) ->
    parse_option_val(Rest, <<Val/binary, C>>);
parse_option_val(<<>>, Val) ->
    Val.

%% @private
-spec parse_vector(Input) -> Result when Input :: binary(), Result :: entry().
parse_vector(<<C, Rest/binary>>) when
    (C >= $A andalso C =< $Z) orelse
        (C >= $a andalso C =< $z) orelse
        (C >= $0 andalso C =< $9)
->
    parse_vector_key(Rest, <<C>>);
parse_vector(Rest) ->
    erlang:error({badarg, [Rest]}).

%% @private
-spec parse_vector_key(Input, Key) -> Result when Input :: binary(), Key :: binary(), Result :: entry().
parse_vector_key(<<$=, Rest/binary>>, Key) ->
    parse_vector_val(Rest, Key, <<>>, true);
parse_vector_key(<<$\s, Rest/binary>>, Key) ->
    parse_vector_key(Rest, Key);
parse_vector_key(<<$\t, Rest/binary>>, Key) ->
    parse_vector_key(Rest, Key);
parse_vector_key(<<C, Rest/binary>>, Key) when
    (C >= $A andalso C =< $Z) orelse
        (C >= $a andalso C =< $z) orelse
        (C >= $0 andalso C =< $9)
->
    parse_vector_key(Rest, <<Key/binary, C>>);
parse_vector_key(<<>>, Key) ->
    {token, Key};
parse_vector_key(Rest, Key) ->
    erlang:error({badarg, [Rest, Key]}).

%% @private
-spec parse_vector_val(Input, Key, Value, Hex) -> Result when
    Input :: binary(), Key :: binary(), Value :: binary(), Hex :: boolean(), Result :: entry().
parse_vector_val(<<$#, _/binary>>, Key = <<C, O, U, N, T>>, Bin, true) when
    (C =:= $C orelse C =:= $c) andalso
        (O =:= $O orelse O =:= $o) andalso
        (U =:= $U orelse U =:= $u) andalso
        (N =:= $N orelse N =:= $n) andalso
        (T =:= $T orelse T =:= $t)
->
    Val = binary_to_integer(Bin),
    {vector, {Key, Val}, int};
parse_vector_val(<<$#, _/binary>>, Key, Hex, true) ->
    Val = hex:hex_to_bin(Hex),
    {vector, {Key, Val}, hex};
parse_vector_val(<<$#, _/binary>>, Key, Val, false) ->
    {vector, {Key, Val}, raw};
parse_vector_val(<<$\s, Rest/binary>>, Key, Val, true) ->
    parse_vector_val(Rest, Key, Val, true);
parse_vector_val(<<$\t, Rest/binary>>, Key, Val, true) ->
    parse_vector_val(Rest, Key, Val, true);
parse_vector_val(<<C, Rest/binary>>, Key, Val, true) when
    (C >= $A andalso C =< $F) orelse
        (C >= $a andalso C =< $f) orelse
        (C >= $0 andalso C =< $9)
->
    parse_vector_val(Rest, Key, <<Val/binary, C>>, true);
parse_vector_val(<<C, Rest/binary>>, Key, Val, _Hex) ->
    parse_vector_val(Rest, Key, <<Val/binary, C>>, false);
parse_vector_val(<<>>, Key = <<C, O, U, N, T>>, Bin, true) when
    (C =:= $C orelse C =:= $c) andalso
        (O =:= $O orelse O =:= $o) andalso
        (U =:= $U orelse U =:= $u) andalso
        (N =:= $N orelse N =:= $n) andalso
        (T =:= $T orelse T =:= $t)
->
    Val = binary_to_integer(Bin),
    {vector, {Key, Val}, int};
parse_vector_val(<<>>, Key = <<L, E, N>>, Bin, true) when
    (L =:= $L orelse L =:= $l) andalso
        (E =:= $E orelse E =:= $e) andalso
        (N =:= $N orelse N =:= $n)
->
    Val = binary_to_integer(Bin),
    {vector, {Key, Val}, int};
parse_vector_val(<<>>, Key, Hex, true) ->
    Val = hex:hex_to_bin(Hex),
    {vector, {Key, Val}, hex};
parse_vector_val(<<>>, Key, Val, false) ->
    {vector, {Key, Val}, raw};
parse_vector_val(Rest, Key, Val, Hex) ->
    erlang:error({badarg, [Rest, Key, Val, Hex]}).
