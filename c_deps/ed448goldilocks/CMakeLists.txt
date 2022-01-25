############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################

cmake_minimum_required(VERSION 3.0)
project(DECAF VERSION 1.0 LANGUAGES C CXX)

set(DECAF_SO_VERSION "0")

find_package(PythonInterp 3 REQUIRED)

option(ENABLE_SHARED "Build shared library." ON)
option(ENABLE_STATIC "Build static library." ON)
option(ENABLE_STRICT "Build with strict compile options." YES)
option(ENABLE_TESTS  "Enable compilation of tests." OFF)
option(GENERATED_SOURCE_PATH "Where the generated source code is stored, default in the building tree" OFF)
if (CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -nostdlib")
endif()

if (GENERATED_SOURCE_PATH)
	set(GSOURCE_PATH ${GENERATED_SOURCE_PATH})
else()
	set(GSOURCE_PATH ${PROJECT_BINARY_DIR}/src/GENERATED)
endif()
message("Generated source code in ${GSOURCE_PATH}")

if(NOT CPACK_GENERATOR AND NOT CMAKE_INSTALL_RPATH AND CMAKE_INSTALL_PREFIX)
	set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_FULL_LIBDIR})
	message(STATUS "Setting install rpath to ${CMAKE_INSTALL_RPATH}")
endif()

include(GNUInstallDirs)
include(CheckSymbolExists)
include(CMakePushCheckState)

include_directories(
	${GSOURCE_PATH}/include/
	src/include/
	src/
	${CMAKE_CURRENT_BINARY_DIR}
)

set(STRICT_OPTIONS_CPP )
set(STRICT_OPTIONS_C )
set(STRICT_OPTIONS_CXX )
if(MSVC)
	if(ENABLE_STRICT)
		set(STRICT_OPTIONS_CPP "${STRICT_OPTIONS_CPP} /WX /Zc:__cplusplus")
	endif()
else()
	set(STRICT_OPTIONS_CXX "${STRICT_OPTIONS_CXX} -std=c++14 -O2")
	set(STRICT_OPTIONS_CPP "${STRICT_OPTIONS_CPP} -Wall -Wuninitialized -Wno-deprecated-declarations -Wno-missing-field-initializers")
	set(STRICT_OPTIONS_C "${STRICT_OPTIONS_C} -std=c99 -O2 -Wstrict-prototypes -Wno-error=strict-prototypes -fvisibility=hidden -Wno-error=implicit-function-declaration -Wno-error=attributes")
	if(CMAKE_C_COMPILER_ID MATCHES "Clang")
		set(STRICT_OPTIONS_CPP "${STRICT_OPTIONS_CPP} -Wno-error=unknown-warning-option -Qunused-arguments -Wno-tautological-compare")
		set(STRICT_OPTIONS_CPP "${STRICT_OPTIONS_CPP} -Wno-unused-function -Wno-pass-failed")
	endif()
	if(ENABLE_STRICT)
		set(STRICT_OPTIONS_CPP "${STRICT_OPTIONS_CPP} -Werror -Wextra -Wno-unused-parameter -fno-strict-aliasing")
	endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${STRICT_OPTIONS_C} ${STRICT_OPTIONS_CPP}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${STRICT_OPTIONS_CXX} ${STRICT_OPTIONS_CPP}")

add_subdirectory(src)

if(ENABLE_TESTS)
	enable_testing()
	add_subdirectory(test)
endif()

include(CMakePackageConfigHelpers)
set(ConfigPackageLocation share/decaf/cmake)
export(EXPORT ${EXPORT_TARGETS_NAME}Targets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/DecafTargets.cmake"
)
configure_package_config_file(cmake/DecafConfig.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/DecafConfig.cmake"
	INSTALL_DESTINATION ${ConfigPackageLocation}
	NO_SET_AND_CHECK_MACRO
)

install(EXPORT ${EXPORT_TARGETS_NAME}Targets
	FILE DecafTargets.cmake
	DESTINATION ${ConfigPackageLocation}
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/DecafConfig.cmake"
	DESTINATION ${ConfigPackageLocation}
)

# Doxygen
find_package(Doxygen)
if (DOXYGEN_FOUND)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
	add_custom_target(doc
		${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		DEPENDS generatedCode
		COMMENT "Generating API documentation with Doxygen" VERBATIM
)
endif()

# CPack settings
set(CPACK_PACKAGE_NAME "decaf")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_IGnore_FILES
        "^${CMAKE_BINARY_DIR}"
        "/\\\\..+"
)

include(CPack)
