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

set(P25519_HEADER_FILES
	${GSOURCE_PATH}/c/p25519/f_field.h
	${TARGET_ARCH_DIR_P25519}/f_impl.h
)
set(P25519_SOURCE_FILES_C
	${TARGET_ARCH_DIR_P25519}/f_impl.c
	f_arithmetic.c
	${GSOURCE_PATH}/c/p25519/f_generic.c
)

SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/p25519/f_field.h PROPERTIES GENERATED 1)
SET_SOURCE_FILES_PROPERTIES(${GSOURCE_PATH}/c/p25519/f_generic.c PROPERTIES GENERATED 1)

add_library(p25519 OBJECT ${P25519_HEADER_FILES} ${P25519_SOURCE_FILES_C})
add_dependencies(p25519 generatorP25519)

set_target_properties(p25519 PROPERTIES POSITION_INDEPENDENT_CODE True)
