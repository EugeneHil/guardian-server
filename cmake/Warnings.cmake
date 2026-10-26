# Shared with guardian-core: its include(Warnings) resolves to this file, so the guard
# keeps the target from being created twice.
include_guard(GLOBAL)

# Warnings are errors in every build.
add_library(guardian_warnings INTERFACE)
if(MSVC)
    target_compile_options(guardian_warnings INTERFACE /W4 /WX)
else()
    target_compile_options(guardian_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Werror)
endif()
