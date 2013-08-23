# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "bns_config.h.in"
  "bns_config.h"
)


set(bin_src 
  ${BNS_SRC_DIR}/bns_output.c 
  ${BNS_SRC_DIR}/bns_input.c 
  ${BNS_SRC_DIR}/bns.c
)
add_executable(bns ${bin_src})
target_link_libraries(bns tk)
