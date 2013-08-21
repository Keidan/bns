/**
*******************************************************************************
* @file bns_input.c
* @author Keidan
* @date 03/01/2013
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
#include "bns_common.h"


/**
 * @fn int bns_input(FILE* input, struct ntools_filter_s filter, _Bool payload_only, _Bool raw)
 * @brief Manageent of the input mode.
 * @param input Input file.
 * @param filter Filter.
 * @param payload_only Exctract only the payload.
 * @param raw Display the payload in raw.
 * @return 0 on success else -1.
 */
int bns_input(FILE* input, struct ntools_filter_s filter, _Bool payload_only, _Bool raw) {
  struct ntools_headers_s net;
  net_buffer_t buffer = NULL;
  int plen = 0;
  __u32 i, reads, offset;
  _Bool b_ghdr = 0, b_phdr = 0;
  pcap_hdr_t ghdr;
  pcaprec_hdr_t phdr;

  /* Parse all lines */
  while(!feof(input)){
    if(!b_ghdr) {
      reads = fread(&ghdr, 1, sizeof(pcap_hdr_t), input);
      reads = 0; /* rem warning */
      printf("Magic: %s\n", ntools_pcap_magic_str(ghdr.magic_number));
      printf("Version: %d.%d\n", ghdr.version_major, ghdr.version_minor);
      printf("GMT correction: %d\n", ghdr.thiszone);
      printf("Accuracy timestamps: %d\n", ghdr.sigfigs);
      printf("Length: %d\n", ghdr.snaplen);
      printf("Link: %d\n", ghdr.network);
      printf("\n");
      b_ghdr = 1;
    } 
    if(!b_phdr) {
      reads = fread(&phdr, 1, sizeof(pcaprec_hdr_t), input);
      reads = 0; /* rem warning */
      b_phdr = 1;
    } else {   
      b_phdr = 0;
      printf("Timestamp seconds: %d\n", phdr.ts_sec);
      printf("Timestamps microseconds: %d\n", phdr.ts_usec);
      printf("Include length: %d\n", phdr.incl_len);
      printf("Origin length: %d\n", phdr.orig_len);
      printf("----\n");
      /* Buffer alloc */
      if((buffer = (net_buffer_t)malloc(phdr.incl_len)) == NULL) {
	logger(LOG_ERR, "FATAL: Unable to alloc memory (length:%d)\n", phdr.incl_len);
	return EXIT_FAILURE;
      }
      /* RAZ the buffer. */
      bzero(buffer, phdr.incl_len);
      offset = 0;
      while(offset < phdr.incl_len) {
	reads = fread(buffer + offset, 1, phdr.incl_len - offset, input);
	offset += reads;
      }
      /* decode all headers */
      if((plen = ntools_decode_buffer(buffer, offset, &net, NTOOLS_CONVERT_NET2HOST)) == -1) {
    	free(buffer);
    	logger(LOG_ERR, "FATAL: DECODE FAILED\n");
    	exit(EXIT_FAILURE); /* fatal error */
      }

      if(ntools_match_from_simple_filter(&net, filter)) {
        if(payload_only) {
    	  if(!raw)
    	    ntools_print_hex(stdout, buffer + plen, offset - plen, 0);
    	  else
    	    for(i = 0; i < (offset - plen); i++)
    	      printf("%c", (buffer+plen)[i]);
	  printf("\n");
        } else
    	  nprint_print_headers(buffer, offset, net);
      }
      ntools_release_buffer(&net);
      /* release the buffer */
      free(buffer), buffer = NULL;
    }
  }
  return EXIT_SUCCESS;
}

