cmake_minimum_required(VERSION 3.18)
project(ares_fhe_jni CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Detect JDK for JNI headers. On modern JDKs the flat include layout puts
# jni.h and jni_md.h in the same directory. Prefer JAVA_HOME; fall back to
# common macOS locations.
if(DEFINED ENV{JAVA_HOME})
    set(JNI_ROOT "$ENV{JAVA_HOME}")
elseif(EXISTS /opt/homebrew/opt/openjdk)
    set(JNI_ROOT /opt/homebrew/opt/openjdk)
else()
    file(GLOB JDK_HOMES /Library/Java/JavaVirtualMachines/*/Contents/Home)
    list(GET JDK_HOMES 0 JNI_ROOT)
endif()
set(JNI_INCLUDE_DIRS "${JNI_ROOT}/include")
if(EXISTS "${JNI_ROOT}/include/darwin")
    list(APPEND JNI_INCLUDE_DIRS "${JNI_ROOT}/include/darwin")
endif()

add_library(ares_fhe_jni SHARED jni_openfhe.cpp openfhe_wrapper.cpp)
target_compile_definitions(ares_fhe_jni PRIVATE OPENFHE_VERSION=v1.5.1)
target_include_directories(ares_fhe_jni PRIVATE
    ${JNI_INCLUDE_DIRS}
    /usr/local/include/openfhe
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/cereal
    /usr/local/include/openfhe/binfhe
    /opt/homebrew/include/openfhe
    /opt/homebrew/include/openfhe/pke
    /opt/homebrew/include/openfhe/core
    /opt/homebrew/include/openfhe/cereal
    /opt/homebrew/include/openfhe/binfhe)
target_link_directories(ares_fhe_jni PRIVATE /usr/local/lib /opt/homebrew/lib)
target_link_libraries(ares_fhe_jni PRIVATE OPENFHEpke OPENFHEbinfhe OPENFHEcore)
set_target_properties(ares_fhe_jni PROPERTIES
    BUILD_RPATH "/usr/local/lib;/opt/homebrew/lib"
    INSTALL_RPATH "/usr/local/lib;/opt/homebrew/lib")
