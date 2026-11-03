cmake_minimum_required(VERSION 3.25)
project(guardian_server VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(GUARDIAN_SERVER_BUILD_TESTS "Build guardian-server tests" ${PROJECT_IS_TOP_LEVEL})

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(Warnings)
include(Dependencies)

# guardian-core's own tests are not part of this build.
set(GUARDIAN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(external/guardian-core)

# Later tasks append their source files here.
set(GUARDIAN_SERVER_SOURCES
    src/admin_routes.cpp
    src/agent_routes.cpp
    src/agent_store.cpp
    src/api.cpp
    src/auth.cpp
    src/cli.cpp
    src/config.cpp
    src/crypto.cpp
    src/event.cpp
    src/file_event_store.cpp
    src/file_policy_store.cpp
    src/fs_util.cpp
    src/http_server.cpp
    src/policy_service.cpp
    src/static_files.cpp
    src/timeutil.cpp
    src/version.cpp
)

add_library(guardian_server_lib STATIC ${GUARDIAN_SERVER_SOURCES})
target_include_directories(guardian_server_lib PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_features(guardian_server_lib PUBLIC cxx_std_17)
target_compile_definitions(guardian_server_lib PRIVATE GUARDIAN_SERVER_VERSION="${PROJECT_VERSION}")
target_link_libraries(guardian_server_lib
    PUBLIC guardian::core nlohmann_json::nlohmann_json httplib::httplib OpenSSL::SSL OpenSSL::Crypto
    PRIVATE guardian_warnings)

add_executable(guardian-server src/main.cpp)
target_include_directories(guardian-server PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(guardian-server PRIVATE guardian_server_lib guardian_warnings)

if(GUARDIAN_SERVER_BUILD_TESTS)
    enable_testing()
    include(GoogleTest)
    file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_test.cpp")
    add_executable(guardian_tests ${TEST_SOURCES})
    target_compile_definitions(guardian_tests PRIVATE
        GUARDIAN_SERVER_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    target_include_directories(guardian_tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(guardian_tests PRIVATE guardian_server_lib guardian_warnings GTest::gtest_main)
    gtest_discover_tests(guardian_tests DISCOVERY_TIMEOUT 60 PROPERTIES TIMEOUT 20)
endif()
