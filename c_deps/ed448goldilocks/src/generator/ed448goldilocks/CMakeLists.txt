############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################
# p448 field
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=field --guard=p448/f_field.h --item=p448 -o ${GSOURCE_PATH}/c/p448/f_field.h ${PROJECT_SOURCE_DIR}/src/per_field/f_field.tmpl.h

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_field/f_field.tmpl.h
    OUTPUT ${GSOURCE_PATH}/c/p448/f_field.h
    COMMENT "Generating code for p448/f_field.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=field --guard=p448/f_generic.c --item=p448 -o ${GSOURCE_PATH}/c/p448/f_generic.c ${PROJECT_SOURCE_DIR}/src/per_field/f_generic.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_field/f_generic.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/p448/f_generic.c
    COMMENT "Generating code for p448/f_generic.c"
)

add_custom_target(generatorP448 DEPENDS
	generatorCommonCode
	${GSOURCE_PATH}/c/p448/f_field.h
	${GSOURCE_PATH}/c/p448/f_generic.c
	)

# ed448goldilocks
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=ed448goldilocks/scalar.c -o ${GSOURCE_PATH}/c/ed448goldilocks/scalar.c ${PROJECT_SOURCE_DIR}/src/per_curve/scalar.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/scalar.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/ed448goldilocks/scalar.c
    COMMENT "Generating code for ed448goldilocks/scalar.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=ed448goldilocks/decaf.c -o ${GSOURCE_PATH}/c/ed448goldilocks/decaf.c ${PROJECT_SOURCE_DIR}/src/per_curve/decaf.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/decaf.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/ed448goldilocks/decaf.c
    COMMENT "Generating code for ed448goldilocks/decaf.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=ed448goldilocks/elligator.c -o ${GSOURCE_PATH}/c/ed448goldilocks/elligator.c ${PROJECT_SOURCE_DIR}/src/per_curve/elligator.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/elligator.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/ed448goldilocks/elligator.c
    COMMENT "Generating code for ed448goldilocks/elligator.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=ed448goldilocks/eddsa.c -o ${GSOURCE_PATH}/c/ed448goldilocks/eddsa.c ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/ed448goldilocks/eddsa.c
    COMMENT "Generating code for ed448goldilocks/eddsa.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=ed448goldilocks/decaf_gen_tables.c -o ${GSOURCE_PATH}/c/ed448goldilocks/decaf_gen_tables.c ${PROJECT_SOURCE_DIR}/src/per_curve/decaf_gen_tables.tmpl.c

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/decaf_gen_tables.tmpl.c
    OUTPUT ${GSOURCE_PATH}/c/ed448goldilocks/decaf_gen_tables.c
    COMMENT "Generating code for ed448goldilocks/decaf_gen_tables.c"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=decaf/point_448.hxx -o ${GSOURCE_PATH}/include/decaf/point_448.hxx ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/point_448.hxx
    COMMENT "Generating code for include/decaf/point_448.hxx"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=decaf/ed448.hxx -o ${GSOURCE_PATH}/include/decaf/ed448.hxx ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/ed448.hxx
    COMMENT "Generating code for include/decaf/ed448.hxx"
)

add_custom_target(genEd448nTab DEPENDS
			${GSOURCE_PATH}/c/ed448goldilocks/scalar.c
			${GSOURCE_PATH}/c/ed448goldilocks/decaf.c
			)
add_custom_target(generatorEd448goldilocks DEPENDS
			generatorP448
			genEd448nTab
       			${GSOURCE_PATH}/c/ed448goldilocks/elligator.c
       			${GSOURCE_PATH}/c/ed448goldilocks/eddsa.c
			${GSOURCE_PATH}/include/decaf/point_448.hxx
			${GSOURCE_PATH}/include/decaf/ed448.hxx
			)
include_directories(
	${PROJECT_SOURCE_DIR}/src/p448
	${GSOURCE_PATH}/c/p448
	${PROJECT_SOURCE_DIR}/src/p448/${TARGET_ARCH_DIR_P448}
)

add_executable(decaf_gen_tables_ed448goldilocks EXCLUDE_FROM_ALL ${GSOURCE_PATH}/c/ed448goldilocks/decaf_gen_tables.c
       			${GSOURCE_PATH}/c/ed448goldilocks/decaf.c
			${GSOURCE_PATH}/c/ed448goldilocks/scalar.c
			${PROJECT_SOURCE_DIR}/src/utils.c
			$<TARGET_OBJECTS:p448>)
add_dependencies(decaf_gen_tables_ed448goldilocks genEd448nTab)

add_custom_target(decaf_tables_ed448goldilocks
	COMMAND decaf_gen_tables_ed448goldilocks > ${PROJECT_SOURCE_DIR}/src/ed448goldilocks/decaf_tables.c
	DEPENDS decaf_gen_tables_ed448goldilocks
	COMMENT "Generating code for ed448goldilocks/decaf_tables.c"
)
