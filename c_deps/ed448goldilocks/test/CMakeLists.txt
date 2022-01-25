############################################################################
# CMakeLists.txt
#
#    Released under the MIT License.  See LICENSE.txt for license information.
#
############################################################################
if(ENABLE_SHARED)
	set(DECAF_LIBRARIES_FOR_TESTER decaf)
else()
	set(DECAF_LIBRARIES_FOR_TESTER decaf-static)
endif()

add_executable(decaf_tester test_decaf.cxx)
set_target_properties(decaf_tester PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(decaf_tester ${DECAF_LIBRARIES_FOR_TESTER})

add_executable(ristretto_tester ristretto.cxx)
set_target_properties(ristretto_tester PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(ristretto_tester ${DECAF_LIBRARIES_FOR_TESTER})

add_executable(shakesum_tester shakesum.c)
set_target_properties(shakesum_tester PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(shakesum_tester ${DECAF_LIBRARIES_FOR_TESTER})

add_executable(bench bench_decaf.cxx)
set_target_properties(bench PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(bench ${DECAF_LIBRARIES_FOR_TESTER})

add_test(NAME decaf COMMAND decaf_tester)
add_test(NAME bench COMMAND bench)

