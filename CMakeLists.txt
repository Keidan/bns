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


# To produce xscale binaries
if("${CMAKE_BUILD_TYPE}" MATCHES "xscale")
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_VERSION 1)

  set(CMAKE_X_HOME /usr/local/arm-linux-4.4.2-v4)
  # specify the cross compiler
  set(CMAKE_C_COMPILER ${CMAKE_X_HOME}/bin/xscale-none-linux-gnueabi-gcc)
  set(CMAKE_CXX_COMPILER ${CMAKE_X_HOME}/bin/xscale-none-linux-gnueabi-g++)
   
  # where is the target environment 
  set(CMAKE_FIND_ROOT_PATH  ${CMAKE_X_HOME})

  # search for programs in the build host directories
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  # for libraries and headers in the target directories
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

  add_definitions(-DTARGET_BIGENDIAN)
endif()

add_subdirectory(${BNS_SRC_LIB_DIR})
add_subdirectory(${BNS_SRC_BIN_DIR})
