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

add_executable(keccak_tester keccak.c)
# The permutation hooks are intentionally internal (hidden in shared builds).
# Link their objects into the differential tester as well as the public library.
target_link_libraries(keccak_tester decaf-keccak-adapter decaf-keccak-plain ${DECAF_LIBRARIES_FOR_TESTER})
foreach(backend decaf-keccak-arm-pair decaf-keccak-k12 decaf-keccak-sha3 decaf-keccak-x86 decaf-keccak-ssse3 decaf-keccak-avx2 decaf-keccak-avx512)
    if(TARGET ${backend})
        target_link_libraries(keccak_tester ${backend})
    endif()
endforeach()
add_test(NAME keccak COMMAND keccak_tester)
add_executable(spongerng_parallel_tester spongerng_parallel.c)
target_link_libraries(spongerng_parallel_tester ${DECAF_LIBRARIES_FOR_TESTER})
add_test(NAME spongerng_parallel COMMAND spongerng_parallel_tester)
add_executable(keccak_batch_tester keccak_batch.c)
target_link_libraries(keccak_batch_tester ${DECAF_LIBRARIES_FOR_TESTER})
add_test(NAME keccak_batch COMMAND keccak_batch_tester)

add_test(NAME decaf COMMAND decaf_tester)
add_test(NAME bench COMMAND bench)

