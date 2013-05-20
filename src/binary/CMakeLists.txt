
# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${BNS_SRC_BIN_DIR}/bns_config.h.in"
  "${BNS_SRC_BIN_DIR}/bns_config.h"
)


set(bin_src ${BNS_SRC_BIN_DIR}/bns_output.c ${BNS_SRC_BIN_DIR}/bns_input.c ${BNS_SRC_BIN_DIR}/bns.c)
add_executable(bns ${bin_src})
target_link_libraries(bns lbns)
