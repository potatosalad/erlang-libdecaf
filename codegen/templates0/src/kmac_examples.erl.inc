~J{ macro kmac_example(name, arity) }.
~J{ if name == 'kmac' or name == 'kmac_init' }.

NIST SP 800-185 sample ~J< '2' if arity in (3, 5) else '1' >.:

```erlang
Key = list_to_binary(lists:seq(16#40, 16#5F)),
~J{ if name == 'kmac' }.
Tag = libdecaf:kmac(kmac128, Key, <<0, 1, 2, 3>>, 32~J< ', <<"My Tagged Application">>' if arity == 5 else '' >.),
~J{ else }.
Initial = libdecaf:kmac_init(kmac128, Key~J< ', <<"My Tagged Application">>' if arity == 3 else '' >.),
First = libdecaf:kmac_update(Initial, <<0, 1>>),
State = libdecaf:kmac_update(First, <<2, 3>>),
Tag = libdecaf:kmac_final(State, 32),
~J{ endif }.
~J{ if arity in (3, 5) }.
<<"3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5">> = binary:encode_hex(Tag).
~J{ else }.
<<"E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E">> = binary:encode_hex(Tag).
~J{ endif }.
```
~J{ elif name == 'kmac_final' }.

Request each required tag length explicitly:

```erlang
Key = list_to_binary(lists:seq(16#40, 16#5F)),
State = libdecaf:kmac_update(libdecaf:kmac_init(kmac128, Key), <<0, 1, 2, 3>>),
Long = libdecaf:kmac_final(State, 32),
Short = libdecaf:kmac_final(State, 16),
Short = libdecaf:kmac(kmac128, Key, <<0, 1, 2, 3>>, 16),
true = Short =/= binary:part(Long, 0, 16).
```
~J{ endif }.
~J{ endmacro }.
