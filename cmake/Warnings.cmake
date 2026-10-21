# Shared with warden-core: its include(Warnings) resolves to this file, so the guard
# keeps the target from being created twice.
include_guard(GLOBAL)

# Warnings are errors in every build.
add_library(warden_warnings INTERFACE)
if(MSVC)
    target_compile_options(warden_warnings INTERFACE /W4 /WX)
else()
    target_compile_options(warden_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Werror)
endif()
