cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

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

# To produce x86_64 binaries
if("${CMAKE_BUILD_TYPE}" MATCHES "x86_64")
  # the name of the target operating system
  set(CMAKE_SYSTEM_NAME Linux)

  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")

  set(BNS_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin/x86_64)
  set(EXECUTABLE_OUTPUT_PATH ${BNS_BINARY_DIR})
  set(LIBRARY_OUTPUT_PATH ${BNS_BINARY_DIR})
  file(MAKE_DIRECTORY ${BNS_BINARY_DIR})
# To produce x86 binaries
elseif("${CMAKE_BUILD_TYPE}" MATCHES "x86")
  # the name of the target operating system
  set(CMAKE_SYSTEM_NAME Linux)
 
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")

  set(BNS_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin/x86)
  set(EXECUTABLE_OUTPUT_PATH ${BNS_BINARY_DIR})
  set(LIBRARY_OUTPUT_PATH ${BNS_BINARY_DIR})
  file(MAKE_DIRECTORY ${BNS_BINARY_DIR})
# To produce xscale binaries
elseif("${CMAKE_BUILD_TYPE}" MATCHES "xscale")
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_VERSION 1)

  set(CMAKE_X_HOME /usr/local/arm-linux-4.4.2-v4)
  # specify the cross compiler
  set(CMAKE_C_COMPILER ${CMAKE_X_HOME}/bin/xscale-none-linux-gnueabi-gcc)
   
  # where is the target environment 
  set(CMAKE_FIND_ROOT_PATH  ${CMAKE_X_HOME})

  # search for programs in the build host directories
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  # for libraries and headers in the target directories
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

  add_definitions(-DTARGET_BIGENDIAN)

  set(BNS_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin/xscale)
  set(EXECUTABLE_OUTPUT_PATH ${BNS_BINARY_DIR})
  set(LIBRARY_OUTPUT_PATH ${BNS_BINARY_DIR})
  file(MAKE_DIRECTORY ${BNS_BINARY_DIR})

else()
  message(FATAL_ERROR "Invalid usage please use: cmake -DCMAKE_BUILD_TYPE=[x86|x86_64|xscale]")
endif()

add_subdirectory(${BNS_SRC_LIB_DIR})
add_subdirectory(${BNS_SRC_BIN_DIR})
