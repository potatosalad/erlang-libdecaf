# Hashes and XOFs

`libdecaf:hash/2` computes a digest or authentication tag in one call.
`libdecaf:xof/3` returns a requested number of XOF bytes. Both have streaming
interfaces for inputs that arrive in pieces.

cSHAKE128, cSHAKE256, KMAC128, KMAC256, KMACXOF128, KMACXOF256,
TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256, ParallelHash128,
ParallelHash256, ParallelHashXOF128, and ParallelHashXOF256 follow
[SP 800-185r1](https://csrc.nist.gov/pubs/sp/800/185/r1/ipd).
Its streaming XOF interface initializes, absorbs input, and squeezes output.
One-shot results remain compatible with the previous edition's published vectors.

## Hash parameters

Initialize with `libdecaf:hash_init/1`, add input with `libdecaf:hash_update/2`,
and finish with `libdecaf:hash_final/1`. The output length is chosen at initialization.

| Algorithms | Parameters |
| --- | --- |
| SHA-512, SHA-3, fixed Keccak | `Algorithm` or `{Algorithm, Length}` |
| SHAKE, Keccak XOF | `{Algorithm, Length}` |
| cSHAKE | `{Algorithm, Length}` or `{Algorithm, Length, FunctionName, Customization}` |
| KMAC, HopMAC | `{Algorithm, Length, Key}` or `{Algorithm, Length, Key, Customization}` |
| KT | `Algorithm`, `{Algorithm, Length}`, or `{Algorithm, Length, Customization}` |
| TurboSHAKE | `Algorithm`, `{Algorithm, Length}`, or `{Algorithm, Length, Domain}` |
| TupleHash128, TupleHash256 | `{Algorithm, Length}` or `{Algorithm, Length, Customization}` |
| ParallelHash128, ParallelHash256 | `{Algorithm, Length, BlockSize}` or `{Algorithm, Length, BlockSize, Customization}` |

Lengths and block sizes are in bytes. Message data, keys, function names, and
customization strings accept iodata. Omitted customization and function names
are empty. TurboSHAKE's domain is an integer in `1..127`, defaulting to `16#1F`.
KT and TurboSHAKE default to 32-byte output at strength 128 and 64 at strength 256.

```erlang
Parameters = {parallelhash128, 32, 8192, <<"orders/v1">>},
H0 = libdecaf:hash_init(Parameters),
H1 = libdecaf:hash_update(H0, [<<"invoice-">>, <<"42">>]),
Digest = libdecaf:hash_final(H1),
Digest = libdecaf:hash(Parameters, <<"invoice-42">>).
```

SHA-512, SHA-3, and fixed Keccak allow digest prefixes up to their full length.
KMAC, TupleHash, and ParallelHash encode the chosen output length into their
computation: request the desired length rather than truncating a longer result.
KMACXOF128, KMACXOF256, TupleHashXOF128, TupleHashXOF256, ParallelHashXOF128,
and ParallelHashXOF256 use different framing and produce different output.

## XOF parameters

Initialize with `libdecaf:xof_init/1`, absorb input with `libdecaf:xof_absorb/2`,
and read output with `libdecaf:xof_squeeze/2`.

| Algorithms | Initialization parameters |
| --- | --- |
| `shake128`, `shake256`, `keccakxof_128`, `keccakxof_256` | `Algorithm` |
| `cshake128`, `cshake256` | `Algorithm` or `{Algorithm, FunctionName, Customization}` |
| `kmacxof128`, `kmacxof256`, `hopmac128`, `hopmac256` | `{Algorithm, Key}` or `{Algorithm, Key, Customization}` |
| KT128 (`kt128`), KT256 (`kt256`), TupleHashXOF128 (`tuplehashxof128`), TupleHashXOF256 (`tuplehashxof256`) | `Algorithm` or `{Algorithm, Customization}` |
| `turboshake128`, `turboshake256` | `Algorithm` or `{Algorithm, Domain}` |
| ParallelHashXOF128 (`parallelhashxof128`), ParallelHashXOF256 (`parallelhashxof256`) | `{Algorithm, BlockSize}` or `{Algorithm, BlockSize, Customization}` |

```erlang
Parameters = {cshake128, <<>>, <<"orders/v1">>},
X0 = libdecaf:xof_init(Parameters),
X1 = libdecaf:xof_absorb(X0, <<"invoice-42">>),
{X2, First} = libdecaf:xof_squeeze(X1, 16),
{_X3, Second} = libdecaf:xof_squeeze(X2, 16),
Output = <<First/binary, Second/binary>>,
Output = libdecaf:xof(Parameters, <<"invoice-42">>, 32).
```

The returned squeezing state can keep producing output but cannot absorb more
input. Hash and XOF states are separate types and cannot be interchanged.
All states are immutable: reusing an earlier state repeats or branches its
computation. Keep keyed states private, just like the original key.

SHAKE, cSHAKE, Keccak XOF, TurboSHAKE, KT, and HopMAC produce the same output
prefix through the Hash and XOF interfaces. Empty function-name and customization
strings make cSHAKE equivalent to SHAKE.

## TupleHash128, TupleHash256, TupleHashXOF128, and TupleHashXOF256

TupleHash hashes a sequence of distinct elements. A one-shot call takes a list
of elements; each streaming update or absorb adds one complete element:

```erlang
Digest = libdecaf:hash({tuplehash128, 32}, [<<"a">>, <<"bc">>]),
H0 = libdecaf:hash_init({tuplehash128, 32}),
H1 = libdecaf:hash_update(H0, <<"a">>),
H2 = libdecaf:hash_update(H1, <<"bc">>),
Digest = libdecaf:hash_final(H2),
Different = libdecaf:hash({tuplehash128, 32}, [<<"ab">>, <<"c">>]),
true = Digest =/= Different.
```

## ParallelHash128, ParallelHash256, ParallelHashXOF128, and ParallelHashXOF256

ParallelHash splits message bytes into fixed-size blocks. Its block size is
part of the algorithm parameters and changes the result; update boundaries do
not. The ordinary Hash/XOF APIs process blocks serially with bounded memory.

## Parallel hashing

KT128, KT256, HopMAC128, HopMAC256, ParallelHash128, and ParallelHash256 support
parallel hashing. For parallel XOFs, use KT128, KT256, HopMAC128, HopMAC256,
ParallelHashXOF128, or ParallelHashXOF256.
Start the application to enable its worker pool:

```erlang
{ok, _} = libdecaf:start(),
Input = binary:copy(<<"abc">>, 10000),
H0 = libdecaf:parallel_hash_init(kt128),
H1 = libdecaf:parallel_hash_update(H0, Input),
Digest = libdecaf:parallel_hash_final(H1),
Digest = libdecaf:hash(kt128, Input).
```

`libdecaf:parallel_hash/2` and `libdecaf:parallel_xof/3` are the one-shot forms.
Streaming XOFs use `libdecaf:parallel_xof_init/1`,
`libdecaf:parallel_xof_absorb/2`, and `libdecaf:parallel_xof_squeeze/2`.
Their parameters and output match the ordinary APIs. Other algorithms use the
ordinary Hash/XOF APIs.

Larger updates amortize scheduling overhead; the dedicated parallel benchmarks
use 64 MiB updates. Small messages usually suit the ordinary API better.

Application configuration:

```erlang
{libdecaf, [
    {parallel, true},
    {parallel_absorb_rounds, 100}
]}.
```

`parallel` controls whether the worker pool starts. `parallel_absorb_rounds`
limits leaves processed per worker call; zero drains until idle. Without a pool,
parallel operations still work on the caller's dirty scheduler.

## Native bindings

`libdecaf_nif` exposes algorithm-specific one-shot functions and constructors,
such as `libdecaf_nif:cshake128/4`, `libdecaf_nif:kt128_hash_init/2`, and
`libdecaf_nif:kt128_xof_init/1`. Streaming states use the generic native
`hash_update/2`, `hash_final/1`, `xof_absorb/2`, and `xof_squeeze/2` functions.
Most applications can use `libdecaf` throughout.
