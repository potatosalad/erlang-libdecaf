############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################

include_directories(
	${PROJECT_SOURCE_DIR}/src/p25519
	${GSOURCE_PATH}/c/p25519
	${PROJECT_SOURCE_DIR}/src/p25519/${TARGET_ARCH_DIR_P25519}
)

set(CURVE25519_SOURCE_FILES_C
	${GSOURCE_PATH}/c/curve25519/decaf.c
	${GSOURCE_PATH}/c/curve25519/elligator.c
	${GSOURCE_PATH}/c/curve25519/scalar.c
	${GSOURCE_PATH}/c/curve25519/eddsa.c
	${PROJECT_SOURCE_DIR}/src/curve25519/decaf_tables.c
)

SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/curve25519/decaf.c PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/curve25519/elligator.c PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/curve25519/scalar.c PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/curve25519/eddsa.c PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/curve25519/decaf_tables.c PROPERTIES GENERATED 1)

add_library(CURVE25519 OBJECT ${CURVE25519_SOURCE_FILES_C})
add_dependencies(CURVE25519 generatedCode p25519)
set_target_properties(CURVE25519 PROPERTIES POSITION_INDEPENDENT_CODE True)
