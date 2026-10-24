%%% % @format
-module(tuak_invalid).
-typing([eqwalizer]).
-export([
    invalid_mac_length/0,
    invalid_mac_type/0,
    invalid_iterations/0
]).

-spec invalid_mac_length() -> MAC when MAC :: libdecaf_tuak:mac().
invalid_mac_length() ->
    libdecaf_tuak:f1(<<0:128>>, <<0:256>>, <<0:128>>, <<0:48>>, <<0:16>>, #{mac_length => 4}).

-spec invalid_iterations() -> TOPc when TOPc :: libdecaf_tuak:topc().
invalid_iterations() ->
    libdecaf_nif:tuak_topc(<<0:128>>, <<0:256>>, #{iterations => <<2>>}).

-spec invalid_mac_type() -> MAC when MAC :: libdecaf_tuak:mac().
invalid_mac_type() ->
    libdecaf_tuak:f1(<<0:128>>, <<0:256>>, <<0:128>>, <<0:48>>, <<0:16>>, #{mac_length => <<8>>}).
