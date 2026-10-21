cmake_minimum_required(VERSION 3.25)
project(warden_server VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WARDEN_SERVER_BUILD_TESTS "Build warden-server tests" ${PROJECT_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Dependencies)

# warden-core's own tests are not part of this build.
set(WARDEN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(external/warden-core)

# Later tasks append their source files here.
set(WARDEN_SERVER_SOURCES
    src/version.cpp
)

add_library(warden_server_lib STATIC ${WARDEN_SERVER_SOURCES})
target_include_directories(warden_server_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(warden_server_lib PUBLIC cxx_std_17)
target_compile_definitions(warden_server_lib PRIVATE WARDEN_SERVER_VERSION="${PROJECT_VERSION}")
target_link_libraries(warden_server_lib
    PUBLIC warden::core nlohmann_json::nlohmann_json httplib::httplib OpenSSL::SSL OpenSSL::Crypto
    PRIVATE warden_warnings)

add_executable(warden-server src/main.cpp)
target_include_directories(warden-server PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(warden-server PRIVATE warden_server_lib warden_warnings)

if(WARDEN_SERVER_BUILD_TESTS)
    enable_testing()
    include(GoogleTest)
    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.cpp")
    add_executable(warden_tests ${TEST_SOURCES})
    target_include_directories(warden_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(warden_tests PRIVATE warden_server_lib warden_warnings GTest::gtest_main)
    gtest_discover_tests(warden_tests PROPERTIES TIMEOUT 20)
endif()
