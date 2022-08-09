-module(legacy_keccak_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([legacy_keccak/1]).

%% Macros.
-define(tv_ok(T, M, F, A, E),
	case erlang:apply(M, F, A) of
		E ->
			ok;
		T ->
			ct:fail({{M, F, A}, {expected, E}, {got, T}})
	end).

all() ->
	[
		{group, 'keccaktestvectors'}
	].

groups() ->
	[
		{'keccaktestvectors', [], [
			legacy_keccak
		]}
	].

init_per_suite(Config) ->
	_ = application:ensure_all_started(libdecaf),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(libdecaf),
	ok.

init_per_group(G='keccaktestvectors', Config) ->
	Folder = data_file("keccaktestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{test_data_files, Files} | libdecaf_ct:start(G, Config)].

end_per_group(_Group, Config) ->
	libdecaf_ct:stop(Config),
	ok.

%%====================================================================
%% Tests
%%====================================================================

legacy_keccak(Config) ->
	Files = [File || File <- ?config(test_data_files, Config)],
	lists:foldl(fun legacy_keccak/2, Config, Files).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	lists:foldl(fun(F, C) ->
		io:format(user, "\e[0;36m[FETCH] ~s\e[0m", [F]),
		{ok, Progress} = libdecaf_ct:progress_start(),
		NewC = data_setup(F, C),
		ok = libdecaf_ct:progress_stop(Progress),
		NewC
	end, Config, [
		"keccaktestvectors"
	]).

%% @private
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
download_archive(ArchiveURL, Directory, ArchiveFile) ->
	mkdir_p(Directory),
	case filelib:is_file(ArchiveFile) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(ArchiveURL, ArchiveFile)
	end.

%% @private
mkdir_p(Directory) ->
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end.

%% @private
copy_files_to_dir([File | FileList], Directory) ->
	mkdir_p(Directory),
	Destination = filename:join(Directory, filename:basename(File)),
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
legacy_keccak(File, Config) ->
	<< "ShortMsgKAT_", BitsBin:3/binary, _/binary >> = iolist_to_binary(filename:basename(File)),
	Bits = binary_to_integer(BitsBin),
	Bytes = (Bits + 7) div 8,
	Type = list_to_atom("keccak_" ++ integer_to_list(Bits)),
	Arity = 1,

	Options = {Type, Arity, Bytes},
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [filename:basename(File)]),
	legacy_keccak(Vectors, Options, Config).

%% @private
legacy_keccak([
			{vector, {<<"Len">>, Len}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"MD">>, MD}, _}
			| Vectors
		], {Type, Arity=1, OutputByteLen}, Config) when Len rem 8 =:= 0 ->
	InputBytes = binary:part(Msg, 0, Len div 8),
	?tv_ok(T0, libdecaf_sha3, hash, [Type, InputBytes], MD),
	Sponge0 = libdecaf_sha3:init(Type),
	Sponge1 = libdecaf_sha3:update(Sponge0, InputBytes),
	?tv_ok(T1, libdecaf_sha3, final, [Sponge1], MD),
	legacy_keccak(Vectors, {Type, Arity, OutputByteLen}, Config);
legacy_keccak([
			{vector, {<<"Len">>, _Len}, _},
			{vector, {<<"Msg">>, _Msg}, _},
			{vector, {<<"MD">>, _MD}, _}
			| Vectors
		], Options, Config) ->
	legacy_keccak(Vectors, Options, Config);
legacy_keccak([], _Opts, _Config) ->
	ok.
