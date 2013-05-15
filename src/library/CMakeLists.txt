
set(lib_src ${BNS_SRC_LIB_DIR}/bns_packet.c ${BNS_SRC_LIB_DIR}/bns_utils.c ${BNS_SRC_LIB_DIR}/bns_pcap.c)
add_library(lbns SHARED ${lib_src})
