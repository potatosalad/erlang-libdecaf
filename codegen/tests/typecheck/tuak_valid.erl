%%% % @format
-module(tuak_valid).
-typing([eqwalizer]).
-export([
    authentication/0,
    prng/0
]).

-spec authentication() -> Outputs when Outputs :: {libdecaf_tuak:mac(), libdecaf_tuak:res(), libdecaf_tuak:ak()}.
authentication() ->
    Key = <<0:128>>,
    TOPc = libdecaf_tuak:topc(Key, <<0:256>>, #{iterations => 2}),
    MAC = libdecaf_tuak:f1(Key, TOPc, <<0:128>>, <<0:48>>, <<0:16>>, #{mac_length => 16, iterations => 2}),
    {RES, _CK, _IK, AK} = libdecaf_tuak:f2345(Key, TOPc, <<0:128>>, #{
        res_length => 16, ck_length => 32, iterations => 2
    }),
    {MAC, RES, AK}.

-spec prng() -> Output when Output :: binary().
prng() ->
    Initial = libdecaf_spongerng:init_from_buffer([<<"seed">>], true),
    State = libdecaf_spongerng:stir(Initial, <<"more seed">>),
    {_Next, Output} = libdecaf_spongerng:next(State, 32),
    Output.
