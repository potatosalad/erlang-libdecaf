%%% % @format
-module(fetch).
-compile(warn_missing_spec_all).
-moduledoc """
Download test-vector archives over HTTP, HTTPS, or FTP.

Based on [`core_http_get.erl`][erlang-mk].

[erlang-mk]: https://github.com/ninenines/erlang.mk/blob/0eb54a71605a955df14c5df793ebe676c86259f9/core/core.mk
""".
-moduledoc #{author => ["Andrew Bennett <potatosaladx@gmail.com>"]}.
-moduledoc #{created => "2015-08-13", modified => "2026-10-22"}.
-moduledoc #{copyright => "Andrew Bennett"}.

%% API
-export([
    fetch/2
]).

%%====================================================================
%% API functions
%%====================================================================

-spec fetch(URL, OutputFile) -> Result when
    URL :: string(), OutputFile :: file:filename_all(), Result :: ok | {error, term()}.
fetch(URL = "ftp" ++ _, OutputFile) ->
    % OTP's FTP client is deprecated. Curl is already used by the build tools.
    case os:find_executable("curl") of
        false ->
            {error, curl_not_found};
        Curl ->
            Port = open_port({spawn_executable, Curl}, [
                binary,
                exit_status,
                use_stdio,
                stderr_to_stdout,
                {args, ["--fail", "--location", "--silent", "--show-error", "--output", OutputFile, URL]}
            ]),
            curl_result(Port, [])
    end;
fetch(URL = "http" ++ _, File) ->
    ssl:start(),
    inets:start(),
    case httpc:request(get, {URL, []}, [{autoredirect, true}], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            file:write_file(File, Body);
        {error, Reason} ->
            {error, Reason};
        Response ->
            {error, {unexpected_http_response, Response}}
    end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

-spec curl_result(Port, Output) -> Result when
    Port :: port(), Output :: [binary()], Result :: ok | {error, term()}.
curl_result(Port, Output) ->
    receive
        {Port, {data, Data}} -> curl_result(Port, [Data | Output]);
        {Port, {exit_status, 0}} -> ok;
        {Port, {exit_status, Status}} -> {error, {curl, Status, iolist_to_binary(lists:reverse(Output))}}
    end.
