############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################
# global include files
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=global --guard=decaf.h -o ${GSOURCE_PATH}/include/decaf.h ${PROJECT_SOURCE_DIR}/src/public_include/decaf.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/public_include/decaf.tmpl.h
    OUTPUT ${GSOURCE_PATH}/include/decaf.h
    COMMENT "Generating code for include/decaf.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=global --guard=decaf/eddsa.hxx -o ${GSOURCE_PATH}/include/decaf/eddsa.hxx ${PROJECT_SOURCE_DIR}/src/public_include/decaf/eddsa.tmpl.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/public_include/decaf/eddsa.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/eddsa.hxx
    COMMENT "Generating code for include/decaf/eddsa.hxx"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=global --guard=decaf.hxx -o ${GSOURCE_PATH}/include/decaf.hxx ${PROJECT_SOURCE_DIR}/src/public_include/decaf.tmpl.hxx

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/public_include/decaf.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf.hxx
    COMMENT "Generating code for include/decaf.hxx"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=global --guard=decaf/crypto.hxx -o ${GSOURCE_PATH}/c/decaf/crypto.hxx ${PROJECT_SOURCE_DIR}/src/include/decaf/crypto.tmpl.hxx

    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/include/decaf/crypto.tmpl.hxx
    OUTPUT ${GSOURCE_PATH}/c/decaf/crypto.hxx
    COMMENT "Generating code for decaf/crypto.hxx"
)

# copying
add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/common.h
    ${GSOURCE_PATH}/include/decaf/common.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/common.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/common.h
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/sha512.hxx
    ${GSOURCE_PATH}/include/decaf/sha512.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/sha512.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/sha512.hxx
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/spongerng.h
    ${GSOURCE_PATH}/include/decaf/spongerng.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/spongerng.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/spongerng.h
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/shake.hxx
    ${GSOURCE_PATH}/include/decaf/shake.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/shake.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/shake.hxx
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/shake.h
    ${GSOURCE_PATH}/include/decaf/shake.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/shake.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/shake.h
)

add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/spongerng.hxx
    ${GSOURCE_PATH}/include/decaf/spongerng.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/spongerng.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/spongerng.hxx
)
add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/secure_buffer.hxx
    ${GSOURCE_PATH}/include/decaf/secure_buffer.hxx
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/secure_buffer.hxx
    OUTPUT ${GSOURCE_PATH}/include/decaf/secure_buffer.hxx
)
add_custom_command(
    COMMAND ${CMAKE_COMMAND} -E copy
    ${PROJECT_SOURCE_DIR}/src/public_include/decaf/sha512.h
    ${GSOURCE_PATH}/include/decaf/sha512.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/public_include/decaf/sha512.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/sha512.h
)


#these files shall be part of generatorCurve25519 and generatorEd448goldilocks targets but they are both included through decaf.h in a source file
add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=decaf/point_255.h -o ${GSOURCE_PATH}/include/decaf/point_255.h ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/point_255.h
    COMMENT "Generating code for decaf/point_255.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=curve25519 --guard=decaf/ed255.h -o ${GSOURCE_PATH}/include/decaf/ed255.h ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/ed255.h
    COMMENT "Generating code for decaf/ed255.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=decaf/point_448.h -o ${GSOURCE_PATH}/include/decaf/point_448.h ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/point.tmpl.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/point_448.h
    COMMENT "Generating code for decaf/point_448.h"
)

add_custom_command(
    COMMAND ${PYTHON_EXECUTABLE} ${PROJECT_SOURCE_DIR}/src/generator/template.py --per=curve --item=ed448goldilocks --guard=decaf/ed448.h -o ${GSOURCE_PATH}/include/decaf/ed448.h ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.h
    DEPENDS ${PROJECT_SOURCE_DIR}/src/generator/template.py ${PROJECT_SOURCE_DIR}/src/per_curve/eddsa.tmpl.h
    OUTPUT ${GSOURCE_PATH}/include/decaf/ed448.h
    COMMENT "Generating code for decaf/ed448.h"
)



add_custom_target(generatorCommonCode DEPENDS
	${GSOURCE_PATH}/include/decaf.h
	${GSOURCE_PATH}/include/decaf/eddsa.hxx
	${GSOURCE_PATH}/include/decaf.hxx
	${GSOURCE_PATH}/c/decaf/crypto.hxx
	${GSOURCE_PATH}/include/decaf/common.h
	${GSOURCE_PATH}/include/decaf/sha512.hxx
	${GSOURCE_PATH}/include/decaf/sha512.h
	${GSOURCE_PATH}/include/decaf/shake.hxx
	${GSOURCE_PATH}/include/decaf/shake.h
	${GSOURCE_PATH}/include/decaf/spongerng.hxx
	${GSOURCE_PATH}/include/decaf/spongerng.h
	${GSOURCE_PATH}/include/decaf/secure_buffer.hxx
	#these files shall be part of curve25519 and ed448goldilocks targets but they are included through decaf.h in common *.c
	${GSOURCE_PATH}/include/decaf/point_255.h
	${GSOURCE_PATH}/include/decaf/point_448.h
	${GSOURCE_PATH}/include/decaf/ed255.h
	${GSOURCE_PATH}/include/decaf/ed448.h
	)

add_subdirectory(curve25519)
add_subdirectory(ed448goldilocks)

add_custom_target(decaf_tables DEPENDS
	decaf_tables_curve25519
	decaf_tables_ed448goldilocks
	)

add_custom_target(generatedCode DEPENDS 
	generatorCommonCode
	generatorEd448goldilocks
	generatorCurve25519
	)
