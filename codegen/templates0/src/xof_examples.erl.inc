~J{ macro xof_squeeze_example(function) }.
~J{ set group = function.name.removesuffix('_squeeze') }.
Continue with each returned state to read successive output chunks:

```erlang
~J{ if group == 'xof_kmac' }.
Key = list_to_binary(lists:seq(16#40, 16#5F)),
Initial = libdecaf:~J< group >._init(~J< function.algorithms[0] >., Key),
~J{ elif group == 'xof_parallelhash' }.
Initial = libdecaf:~J< group >._init(~J< function.algorithms[0] >., 8),
~J{ else }.
Initial = libdecaf:~J< group >._init(~J< function.algorithms[0] >.),
~J{ endif }.
State = libdecaf:~J< group >._absorb(Initial, <<"abc">>),
{Next, First} = libdecaf:~J< group >._squeeze(State, 16~J< ', <<"example">>' if function.arity == 3 else '' >.),
{_, Second} = libdecaf:~J< group >._squeeze(Next, 16),
~J{ if group == 'xof_kmac' }.
Whole = libdecaf:~J< group >.(~J< function.algorithms[0] >., Key, <<"abc">>, 32),
~J{ elif group == 'xof_parallelhash' }.
Whole = libdecaf:~J< group >.(~J< function.algorithms[0] >., <<"abc">>, 8, 32),
~J{ elif group == 'xof_tuplehash' }.
Whole = libdecaf:~J< group >.(~J< function.algorithms[0] >., [<<"abc">>], 32),
~J{ else }.
Whole = libdecaf:~J< group >.(~J< function.algorithms[0] >., <<"abc">>, 32~J< ', <<"example">>' if function.arity == 3 else '' >.),
~J{ endif }.
Whole = <<First/binary, Second/binary>>.
```
~J{ endmacro }.

~J{ macro xof_example(function) }.
~J{ set key = (function.name, function.arity) }.
~J{ if key == ('xof_cshake', 3) }.
The function-name and customization strings are empty in this overload, so the
output equals SHAKE with the same capacity and output length.

```erlang
Output = libdecaf:xof_cshake(cshake128, <<"abc">>, 32),
<<"5881092DD818BF5CF8A3DDB793FBCBA74097D5C526A6D35F97B83351940F2CC8">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_cshake', 5) }.
Leave `FunctionName` empty for ordinary customized hashing. This SP 800-185
example hashes four input bytes with the customization `Email Signature`.
`Length` specifies the output length in bytes.

```erlang
Output = libdecaf:xof_cshake(
    cshake128, <<0, 1, 2, 3>>, 32, <<>>, <<"Email Signature">>
),
<<"C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_cshake_init', 1) }.
This overload uses empty function-name and customization strings. Feed each
returned state to the next update, then request the desired output length.

```erlang
S0 = libdecaf:xof_cshake_init(cshake128),
S1 = libdecaf:xof_cshake_update(S0, <<"a">>),
S2 = libdecaf:xof_cshake_update(S1, [<<"b">>, <<"c">>]),
Output = libdecaf:xof_cshake_final(S2, 32),
<<"5881092DD818BF5CF8A3DDB793FBCBA74097D5C526A6D35F97B83351940F2CC8">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_cshake_init', 3) }.
Supply the function-name and customization strings during initialization. The
following incremental example produces the same output as `xof_cshake/5`
with the message `<<0, 1, 2, 3>>` and customization `Email Signature`.

```erlang
S0 = libdecaf:xof_cshake_init(cshake128, <<>>, <<"Email Signature">>),
S1 = libdecaf:xof_cshake_update(S0, <<0, 1>>),
S2 = libdecaf:xof_cshake_update(S1, <<2, 3>>),
Output = libdecaf:xof_cshake_final(S2, 32),
<<"C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_keccak', 3) }.
Use `keccak_xof_128` or `keccak_xof_256` for the original Keccak padding.
`Length` is measured in bytes.

```erlang
Output = libdecaf:xof_keccak(keccak_xof_128, [<<"a">>, <<"bc">>], 32),
<<"ED992674A628509BB2DCE176B7C03672EE73B2DE6D7FCEA0B1BC94729D4E75F9">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_keccak_init', 1) }.
Absorb message chunks in order, passing each returned state to the next update.
The output below matches `xof_keccak(keccak_xof_128, <<"abc">>, 32)`.

```erlang
S0 = libdecaf:xof_keccak_init(keccak_xof_128),
S1 = libdecaf:xof_keccak_update(S0, <<"a">>),
S2 = libdecaf:xof_keccak_update(S1, <<"bc">>),
Output = libdecaf:xof_keccak_final(S2, 32),
<<"ED992674A628509BB2DCE176B7C03672EE73B2DE6D7FCEA0B1BC94729D4E75F9">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_kt', 3) }.
This overload uses empty customization. Use `xof_kt/4` to supply a
customization string. `Length` is measured in bytes.

```erlang
Output = libdecaf:xof_kt(kt128, <<"abc">>, 32),
<<"AB174F328C55A5510B0B209791BF8B60E801A7CFC2AA42042DCB8F547FBE3A7D">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_kt', 4) }.
The fourth argument is customization iodata. KT appends this string after the
message with the framing required by RFC 9861.

```erlang
Output = libdecaf:xof_kt(kt128, <<"abc">>, 32, <<"my protocol">>),
<<"C82E4E0FF24626ACABC8A8E73CC1F2CDBAF289CE61E985EB4D8429F3B05D0836">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_kt_init', 1) }.
Initialize KT, absorb the message chunks, then finalize for the required number
of bytes. `xof_kt_final/2` uses empty customization; supply customization
to `xof_kt_final/3` after the last message update.

```erlang
S0 = libdecaf:xof_kt_init(kt128),
S1 = libdecaf:xof_kt_update(S0, <<"a">>),
S2 = libdecaf:xof_kt_update(S1, <<"bc">>),
Output = libdecaf:xof_kt_final(S2, 32),
<<"AB174F328C55A5510B0B209791BF8B60E801A7CFC2AA42042DCB8F547FBE3A7D">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_kt_final', 3) }.
Provide customization here after all message updates. This produces the same
output as `xof_kt(kt128, <<"abc">>, 32, <<"my protocol">>)`.
The input state can also be finalized again with a different customization.

```erlang
S0 = libdecaf:xof_kt_init(kt128),
S1 = libdecaf:xof_kt_update(S0, <<"abc">>),
Output = libdecaf:xof_kt_final(S1, 32, <<"my protocol">>),
<<"C82E4E0FF24626ACABC8A8E73CC1F2CDBAF289CE61E985EB4D8429F3B05D0836">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_sha3', 3) }.
Select `shake128` or `shake256` and request an output length in bytes.

```erlang
Output = libdecaf:xof_sha3(shake128, <<"abc">>, 32),
<<"5881092DD818BF5CF8A3DDB793FBCBA74097D5C526A6D35F97B83351940F2CC8">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_sha3_init', 1) }.
Select the SHAKE variant during initialization, absorb each message chunk, then
request the output length at finalization. Repeated finalization of the same
state starts at the same output position.

```erlang
S0 = libdecaf:xof_sha3_init(shake128),
S1 = libdecaf:xof_sha3_update(S0, <<"a">>),
S2 = libdecaf:xof_sha3_update(S1, <<"bc">>),
Output = libdecaf:xof_sha3_final(S2, 32),
<<"5881092DD818BF5CF8A3DDB793FBCBA74097D5C526A6D35F97B83351940F2CC8">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_turboshake', 3) }.
This overload uses the default domain byte `16#1F`. Use `xof_turboshake/4`
to supply a different domain. `Length` is measured in bytes.

```erlang
Output = libdecaf:xof_turboshake(turboshake128, <<"abc">>, 32),
<<"DCF1646DFE993A8EB6B782D1FAACA6D82416A5DCF1DE98EE3C6DBC5E1DC63018">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_turboshake', 4) }.
`Domain` is an integer in `1..127`. The example uses domain byte `16#07` and
requests 32 output bytes.

```erlang
Output = libdecaf:xof_turboshake(turboshake128, <<"abc">>, 32, 16#07),
<<"06E280DE6645094E5C71141811A8FC7F55E5F80F5F32A414D621941ADF59FE66">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_turboshake_init', 1) }.
This overload selects domain byte `16#1F`. Continue with the state returned by
each update; the resulting output matches `xof_turboshake/3`.

```erlang
S0 = libdecaf:xof_turboshake_init(turboshake128),
S1 = libdecaf:xof_turboshake_update(S0, <<"a">>),
S2 = libdecaf:xof_turboshake_update(S1, <<"bc">>),
Output = libdecaf:xof_turboshake_final(S2, 32),
<<"DCF1646DFE993A8EB6B782D1FAACA6D82416A5DCF1DE98EE3C6DBC5E1DC63018">> = binary:encode_hex(Output).
```
~J{ elif key == ('xof_turboshake_init', 2) }.
Supply the integer domain byte during initialization. It remains part of the
state through every update and finalization. This example matches
`xof_turboshake(turboshake128, <<"abc">>, 32, 16#07)`.

```erlang
S0 = libdecaf:xof_turboshake_init(turboshake128, 16#07),
S1 = libdecaf:xof_turboshake_update(S0, <<"a">>),
S2 = libdecaf:xof_turboshake_update(S1, <<"bc">>),
Output = libdecaf:xof_turboshake_final(S2, 32),
<<"06E280DE6645094E5C71141811A8FC7F55E5F80F5F32A414D621941ADF59FE66">> = binary:encode_hex(Output).
```
~J{ endif }.
~J{ endmacro }.
