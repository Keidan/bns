
set(lib_src ${BNS_SRC_LIB_DIR}/bns_header.c ${BNS_SRC_LIB_DIR}/bns_utils.c)
add_library(lbns SHARED ${lib_src})
target_link_libraries(lbns m)
