# Included before external/warden-core, whose include(Dependencies) resolves to this
# file as well; the guard makes that second include a no-op.
include_guard(GLOBAL)

include(FetchContent)

set(FETCHCONTENT_QUIET OFF)

# Declared before external/warden-core so that warden-core's own identical
# declarations are ignored (first declaration wins).
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
    GIT_SHALLOW TRUE
    SYSTEM
)

if(WARDEN_SERVER_BUILD_TESTS)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        GIT_SHALLOW TRUE
        SYSTEM
    )
endif()

find_package(OpenSSL 3 REQUIRED)

set(HTTPLIB_REQUIRE_OPENSSL ON CACHE BOOL "" FORCE)
set(HTTPLIB_COMPILE OFF CACHE BOOL "" FORCE)
# Keep optional compression libraries out so builds do not depend on what the host has.
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.60.0
    GIT_SHALLOW TRUE
    SYSTEM
)

FetchContent_MakeAvailable(nlohmann_json httplib)
if(WARDEN_SERVER_BUILD_TESTS)
    FetchContent_MakeAvailable(googletest)
endif()
