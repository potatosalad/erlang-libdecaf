%%% % @format
-module(legacy_keccak_SUITE).
-compile(warn_missing_spec_all).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([
    all/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

%% Tests.
-export([
    legacy_keccak/1
]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
    case erlang:apply(M, F, A) of
        E ->
            ok;
        T ->
            ct:fail({{M, F, A}, {expected, E}, {got, T}})
    end
).

-spec all() -> Result when Result :: [ct_suite:ct_test_def()].
all() ->
    [
        {group, 'keccaktestvectors'}
    ].

-spec groups() -> Result when Result :: [ct_suite:ct_group_def()].
groups() ->
    [
        {'keccaktestvectors', [], [
            legacy_keccak
        ]}
    ].

-spec init_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_suite(Config) ->
    _ = application:ensure_all_started(libdecaf),
    data_setup(Config).

-spec end_per_suite(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
end_per_suite(_Config) ->
    _ = application:stop(libdecaf),
    ok.

-spec init_per_group(Group, Config) -> Result when
    Group :: ct_suite:ct_groupname(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
init_per_group(G = 'keccaktestvectors', Config) ->
    Folder = data_file("keccaktestvectors", Config),
    {ok, Entries} = file:list_dir(Folder),
    Files = [filename:join([Folder, Entry]) || Entry <- Entries],
    [{test_data_files, Files} | libdecaf_ct:start(G, Config)].

-spec end_per_group(Group, Config) -> Result when
    Group :: ct_suite:ct_groupname(), Config :: ct_suite:ct_config(), Result :: ok.
end_per_group(_Group, Config) ->
    libdecaf_ct:stop(Config),
    ok.

%%====================================================================
%% Tests
%%====================================================================

-spec legacy_keccak(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ok.
legacy_keccak(Config) ->
    Files = [File || File <- ?config(test_data_files, Config)],
    lists:foreach(fun(File) -> legacy_keccak(File, Config) end, Files),
    ok.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
-spec data_file(File, Config) -> Result when
    File :: file:filename(), Config :: ct_suite:ct_config(), Result :: file:filename().
data_file(File, Config) ->
    filename:join([?config(data_dir, Config), File]).

%% @private
-spec data_setup(Config) -> Result when Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
data_setup(Config) ->
    lists:foldl(
        fun(F, C) ->
            io:format(user, "\e[0;36m[FETCH] ~s\e[0m", [F]),
            {ok, Progress} = libdecaf_ct:progress_start(),
            NewC = data_setup(F, C),
            ok = libdecaf_ct:progress_stop(Progress),
            NewC
        end,
        Config,
        [
            "keccaktestvectors"
        ]
    ).

%% @private
-spec data_setup(Archive, Config) -> Result when
    Archive :: string(), Config :: ct_suite:ct_config(), Result :: ct_suite:ct_config().
data_setup(F = "keccaktestvectors", Config) ->
    ArchiveURL = "https://keccak.team/obsolete/KeccakKAT-3.zip",

    Files = [
        "ShortMsgKAT_224.txt",
        "ShortMsgKAT_256.txt",
        "ShortMsgKAT_384.txt",
        "ShortMsgKAT_512.txt"
    ],

    TempDirectory = data_file("temp", Config),
    ArchiveFile = filename:join(TempDirectory, "KeccakKAT-3.zip"),
    ok = download_archive(ArchiveURL, TempDirectory, ArchiveFile),
    FileList = [filename:join("KeccakKAT", File) || File <- Files],
    UnzipOpts = [{file_list, FileList}, {cwd, TempDirectory}, keep_old_files],
    {ok, ExtractedFileList} = zip:unzip(ArchiveFile, UnzipOpts),

    Directory = data_file(F, Config),
    ok = copy_files_to_dir(ExtractedFileList, Directory),

    Config.

%% @private
-spec download_archive(URL, Directory, Archive) -> Result when
    URL :: string(), Directory :: file:filename(), Archive :: file:filename_all(), Result :: ok.
download_archive(ArchiveURL, Directory, ArchiveFile) ->
    mkdir_p(Directory),
    case filelib:is_file(ArchiveFile) of
        true ->
            ok;
        false ->
            ok = fetch:fetch(ArchiveURL, ArchiveFile)
    end.

%% @private
-spec mkdir_p(Directory) -> Result when Directory :: file:filename(), Result :: ok.
mkdir_p(Directory) ->
    case filelib:is_dir(Directory) of
        true ->
            ok;
        false ->
            ok = file:make_dir(Directory)
    end.

%% @private
-spec copy_files_to_dir(Files, Directory) -> Result when
    Files :: [file:name() | {file:name(), binary()}], Directory :: file:filename(), Result :: ok.
copy_files_to_dir([File | FileList], Directory) when is_list(File) ->
    mkdir_p(Directory),
    Flat = filename:flatten(File),
    true = is_list(Flat),
    Destination = filename:join(Directory, filename:basename(Flat)),
    case filelib:is_file(Destination) of
        true ->
            ok;
        false ->
            {ok, _} = file:copy(File, Destination)
    end,
    copy_files_to_dir(FileList, Directory);
copy_files_to_dir([], _Directory) ->
    ok.

%% @private
-spec legacy_keccak(File, Config) -> Result when
    File :: file:filename_all(), Config :: ct_suite:ct_config(), Result :: ok.
legacy_keccak(File, Config) ->
    <<"ShortMsgKAT_", BitsBin:3/binary, _/binary>> = iolist_to_binary(filename:basename(File)),
    Bits = binary_to_integer(BitsBin),
    Bytes = (Bits + 7) div 8,
    Type =
        case Bits of
            224 -> keccak_224;
            256 -> keccak_256;
            384 -> keccak_384;
            512 -> keccak_512
        end,
    Arity = 1,

    Options = {Type, Arity, Bytes},
    Vectors = fips_testvector:from_file(File),
    true = is_list(Vectors),
    io:format("~s", [filename:basename(File)]),
    legacy_keccak(Vectors, Options, Config).

%% @private
-spec legacy_keccak(Vectors, Options, Config) -> Result when
    Vectors :: [fips_testvector:entry()],
    Options :: {libdecaf_keccak_sha3:algorithm(), 1 | 2, non_neg_integer()},
    Config :: ct_suite:ct_config(),
    Result :: ok.
legacy_keccak(
    [
        {vector, {<<"Len">>, Len}, int},
        {vector, {<<"Msg">>, Msg}, hex},
        {vector, {<<"MD">>, MD}, _}
        | Vectors
    ],
    {Type, Arity = 1, OutputByteLen},
    Config
) when Len rem 8 =:= 0 ->
    InputBytes = binary:part(Msg, 0, Len div 8),
    ?tv_ok(T0, libdecaf_keccak_sha3, hash, [Type, InputBytes], MD),
    Sponge0 = libdecaf_keccak_sha3:init(Type),
    Sponge1 = libdecaf_keccak_sha3:update(Sponge0, InputBytes),
    ?tv_ok(T1, libdecaf_keccak_sha3, final, [Sponge1], MD),
    legacy_keccak(Vectors, {Type, Arity, OutputByteLen}, Config);
legacy_keccak(
    [
        {vector, {<<"Len">>, _Len}, _},
        {vector, {<<"Msg">>, _Msg}, _},
        {vector, {<<"MD">>, _MD}, _}
        | Vectors
    ],
    Options,
    Config
) ->
    legacy_keccak(Vectors, Options, Config);
legacy_keccak([], _Opts, _Config) ->
    ok.
