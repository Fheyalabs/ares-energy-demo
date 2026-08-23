cmake_minimum_required(VERSION 3.18)
project(ares_privacy_core LANGUAGES CXX)

if(NOT DEFINED ARES_WRAPPER_SOURCE OR NOT EXISTS "${ARES_WRAPPER_SOURCE}")
    message(FATAL_ERROR "ARES_WRAPPER_SOURCE must name the canonical pkg/ares/crypto/cgo/openfhe_wrapper.cpp")
endif()
if(NOT DEFINED OPENFHE_PREFIX OR NOT IS_DIRECTORY "${OPENFHE_PREFIX}/include/openfhe")
    message(FATAL_ERROR "OPENFHE_PREFIX must name an installed OpenFHE prefix")
endif()

add_library(ares_privacy_core STATIC "${ARES_WRAPPER_SOURCE}")
target_compile_features(ares_privacy_core PRIVATE cxx_std_17)
target_include_directories(ares_privacy_core PRIVATE
    "${OPENFHE_PREFIX}/include/openfhe"
    "${OPENFHE_PREFIX}/include/openfhe/pke"
    "${OPENFHE_PREFIX}/include/openfhe/core"
    "${OPENFHE_PREFIX}/include/openfhe/cereal"
    "${OPENFHE_PREFIX}/include/openfhe/binfhe")
set_target_properties(ares_privacy_core PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
