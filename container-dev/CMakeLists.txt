cmake_minimum_required(VERSION 3.5)
project(hello_plugin)

find_package(PkgConfig REQUIRED)
pkg_check_modules(WIRESHARK REQUIRED wireshark)

add_library(hello SHARED hello.c)

# Include directories from Wireshark
target_include_directories(hello PRIVATE ${WIRESHARK_INCLUDE_DIRS})

# Link libraries directly from pkg-config output
target_link_libraries(hello PRIVATE ${WIRESHARK_LIBRARIES})

# Set RPATH based on platform
if(APPLE)
    set_target_properties(hello PROPERTIES INSTALL_RPATH "@loader_path")
elseif(UNIX)
    set_target_properties(hello PROPERTIES INSTALL_RPATH "$ORIGIN")
endif()

# Optional: Add the library directory in case the linker needs it
link_directories(${WIRESHARK_LIBRARY_DIRS})

