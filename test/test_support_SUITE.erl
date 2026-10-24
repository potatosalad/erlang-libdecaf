%%% % @format
-module(test_support_SUITE).
-moduledoc "Round-trip coverage for the response-file helpers used by the vector suites.".
-compile(warn_missing_spec_all).

-export([
    all/0,
    response_file_roundtrip/1
]).

-spec all() -> TestCases when TestCases :: [ct_suite:ct_test_def()].
all() -> [response_file_roundtrip].

-spec response_file_roundtrip(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
response_file_roundtrip(Config) ->
    Vectors = [
        {flag, <<"SHA-3">>},
        {option, {<<"L">>, <<"32">>}},
        {token, <<"BEGIN">>},
        {vector, {<<"COUNT">>, 3}, int},
        {vector, {<<"Msg">>, <<0, 1, 254, 255>>}, hex},
        {vector, {<<"Label">>, <<"not-hex">>}, raw}
    ],
    Encoded = fips_testvector:to_binary(Vectors),
    Vectors = fips_testvector:from_binary(Encoded),
    Directory = proplists:get_value(priv_dir, Config),
    true = is_list(Directory),
    File = filename:join(Directory, "roundtrip.rsp"),
    ok = fips_testvector:to_file(File, Vectors),
    {ok, Encoded} = file:read_file(File),
    Vectors = fips_testvector:from_file(File),
    ok.
