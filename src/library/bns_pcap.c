/**
 *******************************************************************************
 * @file bns_pcap.c
 * @author Keidan
 * @date 05/13/2013
 * @par Project
 * bns
 *
 * @par Copyright
 * Copyright 2011-2013 Keidan, all right reserved
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY.
 *
 * Licence summary : 
 *    You can modify and redistribute the sources code and binaries.
 *    You can send me the bug-fix
 *
 * Term of the licence in in the file licence.txt.
 *
 *******************************************************************************
 */

#include <bns/bns_pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>



pcap_hdr_t bns_pcap_global_hdr(void) {
  pcap_hdr_t hdr;
  memset(&hdr, 0, sizeof(pcap_hdr_t));
  hdr.magic_number = BNS_PCAP_MAGIC_NATIVE;
  hdr.version_major = BNS_PCAP_VERSION_MAJOR;
  hdr.version_minor = BNS_PCAP_VERSION_MINOR;  
  tzset(); /* force le set de la variable timezone */
  hdr.thiszone = timezone;
  hdr.sigfigs = 0;
  hdr.snaplen = BNS_PCAP_SNAPLEN;
  hdr.network = BNS_PCAP_LINKTYPE_ETHERNET;
  return hdr;
}

pcaprec_hdr_t bns_pcap_packet_hdr(__u32 incl_len, __u32 ori_len) {
  pcaprec_hdr_t hdr;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  hdr.ts_sec = tv.tv_sec;
  hdr.ts_usec = tv.tv_usec;
  hdr.incl_len = incl_len;
  hdr.orig_len = ori_len;
  return hdr;
}
