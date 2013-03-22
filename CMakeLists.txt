cmake_minimum_required(VERSION 2.6)

project(bns C)

# update directories
set(PROJECT_BINARY_DIR bin)
set(PROJECT_SOURCE_DIR src)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})

# removes generated files
add_custom_target(clean-all
   COMMAND ${CMAKE_BUILD_TOOL} clean
   COMMAND ${CMAKE_COMMAND} -P scripts/clean-all.cmake
)

add_definitions( -DDEBUG )

# CFlags
set(CMAKE_CXX_FLAGS "-Wall -Werror -O2")

# The version number.
set (BNS_VERSION_MAJOR 2)
set (BNS_VERSION_MINOR 0)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "scripts/bns_config.h.in"
  "${PROJECT_SOURCE_DIR}/bns_config.h"
)

include_directories("${PROJECT_SOURCE_DIR}")

set(bns_src ${PROJECT_SOURCE_DIR}/bns.c ${PROJECT_SOURCE_DIR}/bns_utils.c ${PROJECT_SOURCE_DIR}/bns_packet.c)

add_executable(bns ${bns_src})
