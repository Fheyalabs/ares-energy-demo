cmake_minimum_required(VERSION 3.18)
project(ares_fhe_jni LANGUAGES CXX)

foreach(required ARES_JNI_SOURCE ARES_WRAPPER_SOURCE OPENFHE_PREFIX ARES_JNI_INCLUDE_DIR)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()
if(NOT EXISTS "${ARES_JNI_SOURCE}")
    message(FATAL_ERROR "ARES_JNI_SOURCE does not exist: ${ARES_JNI_SOURCE}")
endif()
if(NOT EXISTS "${ARES_WRAPPER_SOURCE}")
    message(FATAL_ERROR "ARES_WRAPPER_SOURCE must name pkg/ares/crypto/cgo/openfhe_wrapper.cpp: ${ARES_WRAPPER_SOURCE}")
endif()
if(NOT EXISTS "${ARES_JNI_INCLUDE_DIR}/jni.h")
    message(FATAL_ERROR "ARES_JNI_INCLUDE_DIR does not contain target jni.h: ${ARES_JNI_INCLUDE_DIR}")
endif()
if(NOT IS_DIRECTORY "${OPENFHE_PREFIX}/include/openfhe" OR NOT IS_DIRECTORY "${OPENFHE_PREFIX}/lib")
    message(FATAL_ERROR "OPENFHE_PREFIX must name an installed OpenFHE prefix")
endif()

add_library(ares_fhe_jni SHARED "${ARES_JNI_SOURCE}" "${ARES_WRAPPER_SOURCE}")
target_compile_features(ares_fhe_jni PRIVATE cxx_std_17)
target_include_directories(ares_fhe_jni PRIVATE
    "${ARES_JNI_INCLUDE_DIR}"
    "${OPENFHE_PREFIX}/include/openfhe"
    "${OPENFHE_PREFIX}/include/openfhe/pke"
    "${OPENFHE_PREFIX}/include/openfhe/core"
    "${OPENFHE_PREFIX}/include/openfhe/cereal"
    "${OPENFHE_PREFIX}/include/openfhe/binfhe")
target_link_directories(ares_fhe_jni PRIVATE "${OPENFHE_PREFIX}/lib")
target_link_libraries(ares_fhe_jni PRIVATE OPENFHEpke OPENFHEbinfhe OPENFHEcore)
if(ANDROID)
    target_link_options(ares_fhe_jni PRIVATE "-Wl,-rpath,\$ORIGIN")
endif()
set_target_properties(ares_fhe_jni PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
