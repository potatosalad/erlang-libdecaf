############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################
# p25519 field
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=field --guard=p25519/f_field.h --item=p25519 -o ${GSOURCE_PATH}/c/p25519/f_field.h ${PROJECT_SOURCE_DIR}/src/per_field/f_field.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_field/f_field.tmpl.h
    OUTPUT ${GSOURCE_PATH}/c/p25519/f_field.h
    COMMENT "Generating code for p25519/f_field.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=field --guard=p25519/f_generic.c --item=p25519 -o ${GSOURCE_PATH}/c/p25519/f_generic.c ${PROJECT_SOURCE_DIR}/src/per_field/f_generic.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_field/f_generic.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/p25519/f_generic.c
    COMMENT "Generating code for p25519/f_generic.c"
)

add_custom_target(generatorP25519 DEPENDS
	generatorCommonCode
	${GSOURCE_PATH}/c/p25519/f_field.h
	${GSOURCE_PATH}/c/p25519/f_generic.c
	)

# curve25519
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=curve25519/scalar.c -o ${GSOURCE_PATH}/c/curve25519/scalar.c ${PROJECT_SOURCE_DIR}/src/per_curve/scalar.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/scalar.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/curve25519/scalar.c
    COMMENT "Generating code for curve25519/scalar.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=curve25519/decaf.c -o ${GSOURCE_PATH}/c/curve25519/decaf.c ${PROJECT_SOURCE_DIR}/src/per_curve/decaf.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/decaf.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/curve25519/decaf.c
    COMMENT "Generating code for curve25519/decaf.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=curve25519/elligator.c -o ${GSOURCE_PATH}/c/curve25519/elligator.c ${PROJECT_SOURCE_DIR}/src/per_curve/elligator.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/elligator.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/curve25519/elligator.c
    COMMENT "Generating code for curve25519/elligator.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=curve25519/eddsa.c -o ${GSOURCE_PATH}/c/curve25519/eddsa.c ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/curve25519/eddsa.c
    COMMENT "Generating code for curve25519/eddsa.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=curve25519/decaf_gen_tables.c -o ${GSOURCE_PATH}/c/curve25519/decaf_gen_tables.c ${PROJECT_SOURCE_DIR}/src/per_curve/decaf_gen_tables.tmpl.c
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/decaf_gen_tables.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/curve25519/decaf_gen_tables.c
    COMMENT "Generating code for curve25519/decaf_gen_tables.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=decaf/point_255.hxx -o ${GSOURCE_PATH}/include/decaf/point_255.hxx ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/point_255.hxx
    COMMENT "Generating code for include/decaf/point_255.hxx"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=decaf/ed255.hxx -o ${GSOURCE_PATH}/include/decaf/ed255.hxx ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/ed255.hxx
    COMMENT "Generating code for include/decaf/ed255.hxx"
)

add_custom_target(genC25519nTab DEPENDS
			${GSOURCE_PATH}/c/curve25519/decaf.c
			${GSOURCE_PATH}/c/curve25519/scalar.c
			)
add_custom_target(generatorCurve25519 DEPENDS
			generatorP25519
			genC25519nTab
       			${GSOURCE_PATH}/c/curve25519/elligator.c
       			${GSOURCE_PATH}/c/curve25519/eddsa.c
			${GSOURCE_PATH}/include/decaf/point_255.hxx
			${GSOURCE_PATH}/include/decaf/ed255.hxx
			)
include_directories(
	${PROJECT_SOURCE_DIR}/src/p25519
	${GSOURCE_PATH}/c/p25519
	${PROJECT_SOURCE_DIR}/src/p25519/${TARGET_ARCH_DIR_P25519}
)

add_executable(decaf_gen_tables_curve25519 EXCLUDE_FROM_ALL ${GSOURCE_PATH}/c/curve25519/decaf_gen_tables.c
			${GSOURCE_PATH}/c/curve25519/decaf.c
			${GSOURCE_PATH}/c/curve25519/scalar.c
			${PROJECT_SOURCE_DIR}/src/utils.c
			$<TARGET_OBJECTS:p25519>)
add_dependencies(decaf_gen_tables_curve25519 genC25519nTab)

add_custom_target(decaf_tables_curve25519
	COMMAND decaf_gen_tables_curve25519 > ${PROJECT_SOURCE_DIR}/src/curve25519/decaf_tables.c
	DEPENDS decaf_gen_tables_curve25519
	COMMENT "Generating code for curve25519/decaf_tables.c"
)
