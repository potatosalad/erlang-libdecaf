-module(eddsa_stream_SUITE).
-include_lib("common_test/include/ct.hrl").
-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([empty_message/1, large_input/1, immutable_states/1, rejects_changes/1, invalid_arguments/1, curve_helpers/1]).

all() -> [empty_message, large_input, immutable_states, rejects_changes, invalid_arguments, curve_helpers].
init_per_suite(Config) -> {ok, _} = application:ensure_all_started(libdecaf), Config.
end_per_suite(_) -> ok.

keys(ed25519ph) -> keys(libdecaf_curve25519, 32);
keys(ed448ph) -> keys(libdecaf_curve448, 57).
keys(Curve, Bytes) ->
	Key = Curve:keypair_derive(binary:copy(<<7>>, Bytes)),
	{Key, Curve:keypair_extract_public_key(Key)}.

one_shot(ed25519ph, Message, Key, Context) -> libdecaf_curve25519:ed25519ph_keypair_sign(Message, Key, Context);
one_shot(ed448ph, Message, Key, Context) -> libdecaf_curve448:ed448ph_keypair_sign(Message, Key, Context).

each(F) -> lists:foreach(F, [ed25519ph, ed448ph]).

empty_message(_) -> each(fun(A) ->
	{Key, Public} = keys(A),
	S = libdecaf_eddsa:sign_init(A, Key),
	Signature = one_shot(A, <<>>, Key, <<>>),
	Signature = libdecaf_eddsa:sign_final(S),
	Signature = libdecaf_eddsa:sign_final(libdecaf_eddsa:sign_update(S, [])),
	true = libdecaf_eddsa:verify_final(libdecaf_eddsa:verify_init(A, Signature, Public))
end).

large_input(_) -> each(fun(A) ->
	{Key, Public} = keys(A),
	Chunks = [binary:copy(<<42>>, 20001), [<<1>>, binary:copy(<<3>>, 17013)], <<"tail">>],
	Message = iolist_to_binary(Chunks), Context = binary:copy(<<9>>, 255),
	Expected = one_shot(A, Message, Key, Context),
	S = lists:foldl(fun(Chunk, State) -> libdecaf_eddsa:sign_update(State, Chunk) end,
		libdecaf_eddsa:sign_init(A, Key, Context), Chunks),
	Expected = libdecaf_eddsa:sign_final(S),
	V = lists:foldl(fun(Chunk, State) -> libdecaf_eddsa:verify_update(State, Chunk) end,
		libdecaf_eddsa:verify_init(A, Expected, Public, Context), Chunks),
	true = libdecaf_eddsa:verify_final(V)
end).

immutable_states(_) -> each(fun(A) ->
	{Key, Public} = keys(A),
	S0 = libdecaf_eddsa:sign_init(A, Key),
	S1 = libdecaf_eddsa:sign_update(S0, <<"one">>),
	S2 = libdecaf_eddsa:sign_update(S0, <<"two">>),
	Empty = one_shot(A, <<>>, Key, <<>>), Empty = libdecaf_eddsa:sign_final(S0),
	One = one_shot(A, <<"one">>, Key, <<>>), One = libdecaf_eddsa:sign_final(S1),
	Two = one_shot(A, <<"two">>, Key, <<>>), Two = libdecaf_eddsa:sign_final(S2),
	V0 = libdecaf_eddsa:verify_init(A, One, Public),
	false = libdecaf_eddsa:verify_final(V0),
	V1 = libdecaf_eddsa:verify_update(V0, <<"one">>),
	true = libdecaf_eddsa:verify_final(V1), true = libdecaf_eddsa:verify_final(V1),
	Parent = self(),
	{Pid, Ref} = spawn_monitor(fun() -> Parent ! {self(), libdecaf_eddsa:sign_final(S1)} end),
	receive {Pid, One} -> ok after 5000 -> ct:fail(stream_timeout) end,
	receive {'DOWN', Ref, process, Pid, normal} -> ok after 5000 -> ct:fail(stream_process) end
end).

rejects_changes(_) -> each(fun(A) ->
	{Key, Public} = keys(A), Signature = one_shot(A, <<"message">>, Key, <<"context">>),
	V0 = libdecaf_eddsa:verify_init(A, Signature, Public, <<"context">>),
	false = libdecaf_eddsa:verify_final(libdecaf_eddsa:verify_update(V0, <<"changed">>)),
	V1 = libdecaf_eddsa:verify_init(A, Signature, Public, <<"changed">>),
	false = libdecaf_eddsa:verify_final(libdecaf_eddsa:verify_update(V1, <<"message">>)),
	<<First, Rest/binary>> = Signature, Altered = <<(First bxor 1), Rest/binary>>,
	V2 = libdecaf_eddsa:verify_init(A, Altered, Public, <<"context">>),
	false = libdecaf_eddsa:verify_final(libdecaf_eddsa:verify_update(V2, <<"message">>))
end).

invalid_arguments(_) ->
	{K255, P255} = keys(ed25519ph), {K448, _} = keys(ed448ph),
	S = libdecaf_eddsa:sign_init(ed25519ph, K255),
	lists:foreach(fun badarg/1, [
		fun() -> libdecaf_eddsa:sign_init(ed25519, K255) end,
		fun() -> libdecaf_eddsa:sign_init(ed25519ph, K448) end,
		fun() -> libdecaf_eddsa:sign_init(ed448ph, K255) end,
		fun() -> libdecaf_eddsa:sign_init(ed25519ph, make_ref()) end,
		fun() -> libdecaf_eddsa:sign_init(ed25519ph, K255, binary:copy(<<0>>, 256)) end,
		fun() -> libdecaf_eddsa:sign_init(ed25519ph, K255, no_context) end,
		fun() -> libdecaf_eddsa:verify_init(ed25519ph, <<>>, P255) end,
		fun() -> libdecaf_eddsa:verify_init(ed25519ph, <<0:512>>, <<>>) end,
		fun() -> libdecaf_eddsa:verify_init(ed25519ph, <<0:512>>, P255, binary:copy(<<0>>, 256)) end,
		fun() -> libdecaf_eddsa:sign_update(S, [256]) end,
		fun() -> libdecaf_eddsa:sign_final(not_a_state) end,
		fun() -> libdecaf_eddsa:verify_update(S, <<>>) end,
		fun() -> libdecaf_eddsa:verify_final(S) end]),
	ok.

curve_helpers(_) ->
	{K255, P255} = keys(ed25519ph),
	S255 = libdecaf_curve25519:ed25519ph_sign_update(libdecaf_curve25519:ed25519ph_sign_init(K255), <<"abc">>),
	Sig255 = libdecaf_curve25519:ed25519ph_sign_final(S255),
	V255 = libdecaf_curve25519:ed25519ph_verify_update(libdecaf_curve25519:ed25519ph_verify_init(Sig255, P255), <<"abc">>),
	true = libdecaf_curve25519:ed25519ph_verify_final(V255),
	{K448, P448} = keys(ed448ph),
	S448 = libdecaf_curve448:ed448ph_sign_update(libdecaf_curve448:ed448ph_sign_init(K448, <<"c">>), <<"abc">>),
	Sig448 = libdecaf_curve448:ed448ph_sign_final(S448),
	V448 = libdecaf_curve448:ed448ph_verify_update(libdecaf_curve448:ed448ph_verify_init(Sig448, P448, <<"c">>), <<"abc">>),
	true = libdecaf_curve448:ed448ph_verify_final(V448),
	ok.

badarg(F) ->
	try F() of Value -> ct:fail({expected_badarg, Value})
	catch error:badarg -> ok; error:{badarg, _, _} -> ok end.
