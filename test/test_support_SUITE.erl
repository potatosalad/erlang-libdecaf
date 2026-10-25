%%% % @format
-module(test_support_SUITE).
-moduledoc "Coverage for Common Test failure reporting and vector response-file helpers.".
-compile(warn_missing_spec_all).

-export([
    all/0,
    cleanup_failure_exit_status/1,
    response_file_roundtrip/1
]).

-spec all() -> TestCases when TestCases :: [ct_suite:ct_test_def()].
all() -> [cleanup_failure_exit_status, response_file_roundtrip].

-spec cleanup_failure_exit_status(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
cleanup_failure_exit_status(Config) ->
    Directory = filename:join(proplists:get_value(priv_dir, Config), "cleanup_failure"),
    Source = filename:join(Directory, "ct_cleanup_failure_SUITE.erl"),
    ok = filelib:ensure_dir(Source),
    %% Reproduce CT's false success: init_per_suite exists, end_per_suite does not.
    ok = file:write_file(Source, <<
        "-module(ct_cleanup_failure_SUITE).\n"
        "-export([all/0, init_per_suite/1, passes/1]).\n"
        "all() -> [passes].\n"
        "init_per_suite(Config) -> Config.\n"
        "passes(_) -> ok.\n"
    >>),
    {ok, ct_cleanup_failure_SUITE} = compile:file(Source, [{outdir, Directory}]),
    LogDir = filename:join(Directory, "logs"),
    ok = file:make_dir(LogDir),
    Report = filename:join(LogDir, "junit_report.xml"),
    HookOptions = lists:flatten(io_lib:format("~tp", [[{path, Report}]])),
    Helper = code:which(libdecaf_ct),
    true = is_list(Helper),
    Executable = os:find_executable("ct_run"),
    true = is_list(Executable),
    Port = open_port({spawn_executable, Executable}, [
        binary,
        exit_status,
        stderr_to_stdout,
        use_stdio,
        {args, [
            "-no_auto_compile",
            "-noinput",
            "-sname",
            "ct_cleanup_" ++ os:getpid(),
            "-pa",
            filename:dirname(Helper),
            Directory,
            "-dir",
            Directory,
            "-logdir",
            LogDir,
            "-suite",
            "ct_cleanup_failure_SUITE",
            "-ct_hooks",
            "cth_surefire",
            HookOptions,
            "-halt_with",
            "libdecaf_ct",
            "halt"
        ]}
    ]),
    case collect_output(Port, <<>>) of
        {1, Output} ->
            {_, _} = binary:match(Output, <<"Common Test recorded 1 failures">>),
            ok;
        Unexpected ->
            ct:fail({cleanup_failure_exit_status, Unexpected})
    end.

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

-spec collect_output(Port, Output) -> Result when
    Port :: port(), Output :: binary(), Result :: {non_neg_integer(), binary()}.
collect_output(Port, Output) ->
    receive
        {Port, {data, Data}} ->
            collect_output(Port, <<Output/binary, Data/binary>>);
        {Port, {exit_status, Status}} ->
            {Status, Output}
    after 30000 ->
        port_close(Port),
        ct:fail(cleanup_failure_timeout)
    end.
