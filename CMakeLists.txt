cmake_minimum_required(VERSION 3.16)
project(dataseal_forgery LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(DSF_WITH_OPENFHE "Build the OpenFHE-backed components" OFF)

add_library(dsf_plain
  src/field.cpp
  src/matrix.cpp
  src/rng.cpp
  src/dataseal.cpp
  src/attacks.cpp
  src/sketch.cpp
  src/sketch_program.cpp
  src/judge.cpp)
target_include_directories(dsf_plain PUBLIC include)
target_compile_options(dsf_plain PRIVATE -Wall -Wextra -Wpedantic -Werror)

enable_testing()

foreach(t field dataseal attacks sketch sketch_program)
  add_executable(test_${t} tests/test_${t}.cpp)
  target_link_libraries(test_${t} PRIVATE dsf_plain)
  target_compile_options(test_${t} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  add_test(NAME plain.${t} COMMAND test_${t})
endforeach()

add_executable(dsf_phase2_audit src/tools/phase2_audit.cpp)
target_link_libraries(dsf_phase2_audit PRIVATE dsf_plain)
target_compile_options(dsf_phase2_audit PRIVATE -Wall -Wextra -Wpedantic -Werror)

if(DSF_WITH_OPENFHE)
  find_package(OpenFHE 1.6.1 CONFIG REQUIRED)
  message(STATUS "OpenFHE ${BASE_OPENFHE_VERSION} at ${OpenFHE_LIBDIR}, backend ${OpenFHE_BACKEND}")

  add_library(dsf_he src/he.cpp src/he_io.cpp src/he_rowmajor.cpp src/sketch_he.cpp src/he_attacks.cpp)
  target_include_directories(dsf_he SYSTEM PUBLIC
    ${OPENMP_INCLUDES}
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/third-party/include
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe)
  target_compile_definitions(dsf_he PUBLIC MATHBACKEND=${OpenFHE_BACKEND}
    DSF_OPENFHE_VERSION="${BASE_OPENFHE_VERSION}")
  target_compile_options(dsf_he PUBLIC -Xpreprocessor -fopenmp)
  target_compile_options(dsf_he PRIVATE -Wall -Wextra -Werror)
  target_link_directories(dsf_he PUBLIC ${OpenFHE_LIBDIR} ${OPENMP_LIBRARIES})
  target_link_libraries(dsf_he PUBLIC dsf_plain OPENFHEpke OPENFHEcore OPENFHEbinfhe)
  set(CMAKE_BUILD_RPATH ${OpenFHE_LIBDIR})

  add_executable(dsf_sketch_server_worker src/tools/sketch_server_worker.cpp)
  target_link_libraries(dsf_sketch_server_worker PRIVATE dsf_he)
  target_compile_options(dsf_sketch_server_worker PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_sketch_server_worker PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})

  foreach(t he he_io he_rowmajor sketch_he he_attacks he_public_matmul phase2_unified)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE dsf_he)
    target_compile_options(test_${t} PRIVATE -Wall -Wextra -Werror)
    set_target_properties(test_${t} PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
    add_test(NAME he.${t} COMMAND test_${t})
  endforeach()
  set_tests_properties(he.he_io PROPERTIES ENVIRONMENT "DSF_TMP=${CMAKE_BINARY_DIR}/tmp")
  set_tests_properties(he.sketch_he PROPERTIES ENVIRONMENT
    "DSF_TMP=${CMAKE_BINARY_DIR}/tmp;DSF_WORKER=$<TARGET_FILE:dsf_sketch_server_worker>")

  add_executable(dsf_he_manifest src/tools/he_manifest.cpp)
  target_link_libraries(dsf_he_manifest PRIVATE dsf_he)
  target_compile_options(dsf_he_manifest PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_he_manifest PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
  add_executable(dsf_rowmajor_manifest src/tools/rowmajor_manifest.cpp)
  target_link_libraries(dsf_rowmajor_manifest PRIVATE dsf_he)
  target_compile_options(dsf_rowmajor_manifest PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_rowmajor_manifest PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
  add_executable(dsf_attack_server_worker src/tools/attack_server_worker.cpp)
  target_link_libraries(dsf_attack_server_worker PRIVATE dsf_he)
  target_compile_options(dsf_attack_server_worker PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_attack_server_worker PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
  add_executable(dsf_attack_runner src/tools/attack_runner.cpp)
  target_link_libraries(dsf_attack_runner PRIVATE dsf_he)
  target_compile_options(dsf_attack_runner PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_attack_runner PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
  add_executable(dsf_phase2_bench src/tools/phase2_bench.cpp)
  target_link_libraries(dsf_phase2_bench PRIVATE dsf_he)
  target_compile_options(dsf_phase2_bench PRIVATE -Wall -Wextra -Werror)
  set_target_properties(dsf_phase2_bench PROPERTIES BUILD_RPATH ${OpenFHE_LIBDIR})
  add_test(NAME he.attack_runner
    COMMAND dsf_attack_runner ${CMAKE_BINARY_DIR}/tmp/attack_run $<TARGET_FILE:dsf_attack_server_worker>)
endif()
