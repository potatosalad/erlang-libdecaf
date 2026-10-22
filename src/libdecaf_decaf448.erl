%% Prime-order group operations. Points and scalars use canonical little-endian
%% encodings. point_from_hash/1 consumes 112 uniformly distributed bytes,
%% rather than hashing a message. Invalid arithmetic operands raise badarg.
-module(libdecaf_decaf448).
-export([
	identity/0,
	base/0,
	point_is_valid/1,
	point_eq/2,
	point_add/2,
	point_sub/2,
	point_negate/1,
	point_double/1,
	point_scalarmul/2,
	base_scalarmul/1,
	point_double_scalarmul/4,
	point_from_hash/1,
	point_from_hash_nonuniform/1,
	precompute/1,
	precomputed_scalarmul/2,
	scalar_is_canonical/1,
	scalar_reduce/1,
	scalar_add/2,
	scalar_sub/2,
	scalar_mul/2,
	scalar_negate/1,
	scalar_halve/1,
	scalar_invert/1,
	scalar_random/0
]).
-export_type([point/0, scalar/0, precomputed/0]).
-type point() :: <<_:448>>.
-type scalar() :: <<_:448>>.
-opaque precomputed() :: reference().

-spec identity() -> point().
identity() ->
	libdecaf:decaf448_identity().

-spec base() -> point().
base() ->
	libdecaf:decaf448_base().

-spec point_is_valid(term()) -> boolean().
point_is_valid(Point) ->
	libdecaf:decaf448_point_is_valid(Point).

-spec point_eq(point(), point()) -> boolean().
point_eq(Left, Right) ->
	libdecaf:decaf448_point_eq(Left, Right).

-spec point_add(point(), point()) -> point().
point_add(Left, Right) ->
	libdecaf:decaf448_point_add(Left, Right).

-spec point_sub(point(), point()) -> point().
point_sub(Left, Right) ->
	libdecaf:decaf448_point_sub(Left, Right).

-spec point_negate(point()) -> point().
point_negate(Point) ->
	libdecaf:decaf448_point_negate(Point).

-spec point_double(point()) -> point().
point_double(Point) ->
	libdecaf:decaf448_point_double(Point).

-spec point_scalarmul(point(), scalar()) -> point().
point_scalarmul(Point, Scalar) ->
	libdecaf:decaf448_point_scalarmul(Point, Scalar).

-spec base_scalarmul(scalar()) -> point().
base_scalarmul(Scalar) ->
	libdecaf:decaf448_base_scalarmul(Scalar).

-spec point_double_scalarmul(point(), scalar(), point(), scalar()) -> point().
point_double_scalarmul(Point1, Scalar1, Point2, Scalar2) ->
	libdecaf:decaf448_point_double_scalarmul(Point1, Scalar1, Point2, Scalar2).

-spec point_from_hash(binary()) -> point().
point_from_hash(UniformBytes) ->
	libdecaf:decaf448_point_from_hash(UniformBytes).

-spec point_from_hash_nonuniform(binary()) -> point().
point_from_hash_nonuniform(Bytes) ->
	libdecaf:decaf448_point_from_hash_nonuniform(Bytes).

-spec precompute(point()) -> precomputed().
precompute(Point) ->
	libdecaf:decaf448_precompute(Point).

-spec precomputed_scalarmul(precomputed(), scalar()) -> point().
precomputed_scalarmul(Precomputed, Scalar) ->
	libdecaf:decaf448_precomputed_scalarmul(Precomputed, Scalar).

-spec scalar_is_canonical(term()) -> boolean().
scalar_is_canonical(Scalar) ->
	libdecaf:decaf448_scalar_is_canonical(Scalar).

-spec scalar_reduce(binary()) -> scalar().
scalar_reduce(Bytes) ->
	libdecaf:decaf448_scalar_reduce(Bytes).

-spec scalar_add(scalar(), scalar()) -> scalar().
scalar_add(Left, Right) ->
	libdecaf:decaf448_scalar_add(Left, Right).

-spec scalar_sub(scalar(), scalar()) -> scalar().
scalar_sub(Left, Right) ->
	libdecaf:decaf448_scalar_sub(Left, Right).

-spec scalar_mul(scalar(), scalar()) -> scalar().
scalar_mul(Left, Right) ->
	libdecaf:decaf448_scalar_mul(Left, Right).

-spec scalar_negate(scalar()) -> scalar().
scalar_negate(Scalar) ->
	libdecaf:decaf448_scalar_negate(Scalar).

-spec scalar_halve(scalar()) -> scalar().
scalar_halve(Scalar) ->
	libdecaf:decaf448_scalar_halve(Scalar).

-spec scalar_invert(scalar()) -> scalar() | error.
scalar_invert(Scalar) ->
	libdecaf:decaf448_scalar_invert(Scalar).

%% Reduce a wide random integer; arithmetic operations accept canonical scalars.
-spec scalar_random() -> scalar().
scalar_random() ->
	scalar_reduce(crypto:strong_rand_bytes(112)).
