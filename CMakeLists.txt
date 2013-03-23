cmake_minimum_required(VERSION 2.6)

project(bns C)

# update directories
set(BNS_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(BNS_SRC_BIN_DIR ${CMAKE_SOURCE_DIR}/src/binary)
set(BNS_SRC_LIB_DIR ${CMAKE_SOURCE_DIR}/src/library)
set(BNS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(EXECUTABLE_OUTPUT_PATH ${BNS_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${BNS_BINARY_DIR})

# global config
include_directories("${BNS_INCLUDE_DIR}")
link_directories("${LIBRARY_OUTPUT_PATH}")

# removes generated files
add_custom_target(clean-all
   COMMAND ${CMAKE_BUILD_TOOL} clean
   COMMAND ${CMAKE_COMMAND} -P scripts/clean-all.cmake
)



# The version number.
set (BNS_VERSION_MAJOR 2)
set (BNS_VERSION_MINOR 1)

# CFlags Release
set(CMAKE_C_FLAGS "-Wall -Werror -O2")
# CFlags Debug
# set(CMAKE_C_FLAGS "-Wall -Werror -O0 -g")

add_subdirectory(${BNS_SRC_LIB_DIR})
add_subdirectory(${BNS_SRC_BIN_DIR})
