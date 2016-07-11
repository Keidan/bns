/**
 *******************************************************************************
 * @file bns_output.c
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


#define SIZE_1MB 1048576

/**
 * @fn static void bns_output_err_clean(struct nettools_headers_s *net, htable_tifaces, net_buffer_t buffer)
 * @brief Cleanup on error.
 * @param net Headers.
 * @param ifaces List of interfaces.
 * @param buffer Buffer datas.
 */
static void bns_output_err_clean(struct nettools_headers_s *net, htable_t ifaces, net_buffer_t buffer) {
  if(net) nettools_release_buffer(net);
  if(ifaces) netiface_list_delete(ifaces);
  if(buffer) free(buffer);
}

  /**
   * @fn int bns_output(FILE* output, char* outputname, struct nettools_filter_s filter, unsigned int size, unsigned int count, int *packets, __u32 link, usage_fct usage)
   * @brief Management of the output and console modes.
   * @param output Output file else NULL for the console mode.
   * @param outputname Output file name.
   * @param filter Filter.
   * @param size File size in Mb.
   * @param count Maximum of files.
   * @param packets Packets numbers.
   * @param link Link type.
   * @param usage Usage function.
   * @return 0 on success else -1.
   */
int bns_output(FILE* output, char* outputname, struct nettools_filter_s filter, unsigned int size, unsigned int count, int *packets, __u32 link, usage_fct usage) {
  htable_t ifaces;
  netiface_t iface = NULL;
  net_buffer_t buffer;
  struct netiface_info_s info;
  int maxfd = 0, kcount, i, fd;
  fd_set rset;
  struct nettools_headers_s net;
  unsigned int current = 0;
  _Bool first = 1;
  char** keys = NULL;
  if(getuid()) usage(EXIT_FAILURE);

  *packets = 0;
  /* RAZ FD */
  FD_ZERO(&rset);

  /* Prepares the interface(s). */
  if(nettools_prepare_ifaces(&ifaces, &maxfd, &rset, filter.iface) != 0) {
    bns_output_err_clean(NULL, ifaces, NULL);/* Cleanup and close all opened sockets. */
    return EXIT_FAILURE;
  }
  /* prepare the ifaces keys */
  kcount = htable_get_keys(ifaces, &keys);
  while(1) {
    /* Wait for the next packet. */
    if (select(maxfd + 1, &rset, NULL, NULL, NULL) != -1) {
      /* retrieve the good one iface. */
      for(i = 0; i < kcount; i++) {
	iface = htable_lookup(ifaces, keys[i]);
	if(iface) {
	  netiface_get_fd(iface, &fd);
	  if(FD_ISSET(fd, &rset)) {
	    if(!netiface_read(iface, &info)) break;
	    else {
	      iface = NULL;
	      break;
	    }
	  }
	  iface = NULL;
	}
      }
      
      /* the interface must be up. */
      if(!iface || !IFACE_IS_UP(info.flags)) continue;
	
      /* Get the available datas to read */
      __u32 len = netiface_datas_available(iface);
      /* The size is valid ? */
      if(!len) {
	logger(LOG_ERR, "%s: Zero length o_O ?\n", info.name);
	continue;
      }
      /* buffer alloc */
      buffer = (net_buffer_t)malloc(len);
      if(!buffer) {
	/* A failure at this point is very critical. */
	bns_output_err_clean(NULL, ifaces, NULL);
	logger(LOG_ERR, "%s: Malloc failed!\n", info.name);
	return EXIT_FAILURE;
      }
      /* Reads the packet */
      int ret = recvfrom(fd, buffer, len, 0, NULL, NULL);
      /* If the read fails, we go to the next packet */
      if (ret < 0) {
	free(buffer);
	bns_output_err_clean(NULL, NULL, buffer);
	logger(LOG_ERR, "%s: recvfrom failed: (%d) %s.\n", info.name, errno, strerror(errno));
	continue;
      }

      /* decode all headers */
      if(nettools_decode_buffer(buffer, ret, &net, NETTOOLS_CONVERT_NET2HOST) == -1) {
	bns_output_err_clean(NULL, ifaces, buffer);
	logger(LOG_ERR, "FATAL: DECODE FAILED\n");
	exit(EXIT_FAILURE); /* fatal error. */
      }
      /* A rule is applied ? */
      if(!nettools_match_from_simple_filter(&net, filter)) {
	bns_output_err_clean(&net, NULL, buffer);
	continue;
      } 
      /* output case */
      if(output) {
	/* test the size */
	if(size) {
	  /* current is greater than to count, we leave... */
	  if(count && (count == current || current > BNS_OUTPUT_MAX_FILES)) {
	    fprintf(stderr, "Max files (%d/%d) reached.", current, count);
	    bns_output_err_clean(&net, ifaces, buffer);
	    exit(0);
	  } 
	  /* get the file size */
	  long fsize = file_fsize(output);
	  long rsize = SIZE_1MB * size;
	  /* if the file size + the packet length is greater than the desired size. */
	  if(fsize+ret >= rsize) {
	    /* close the revious file */
	    fclose(output);
	    /* Allocate the new name */
	    char* tmp = malloc(strlen(outputname) + 5); /* name '.' 3 digits + '\0' */
	    if(!tmp) {
	      logger(LOG_ERR, "Unable to alloc memory for file name '%s.%d'.", outputname, current);
	      bns_output_err_clean(&net, ifaces, buffer);
	      return EXIT_FAILURE;
	    }
	    /* name set */
	    sprintf(tmp, "%s.%03d", outputname, current++);
	    /* file rename */
	    if(rename(outputname , tmp) == -1) {
	      free(tmp);
	      free(outputname);
	      logger(LOG_ERR, "Error renaming file: (%d) %s", errno, strerror(errno));
	      bns_output_err_clean(&net, ifaces, buffer);
	      return EXIT_FAILURE;
	    }
	    free(tmp);
	    /* reopen the file */
	    output = fopen(outputname, "w+");
	    if(!output) {
	      free(outputname);
	      logger(LOG_ERR, "Unable to open file '%s': (%d) %s\n", outputname, errno, strerror(errno));
	      bns_output_err_clean(&net, ifaces, buffer);
	      return EXIT_FAILURE;
	    }
	    first = 0;
	  }
	}
	/* decoding + display parts */
	nettools_write_pcap_packet(output, link, buffer, len, ret, &first);
      } else {
	printf("iFace name: %s (%d bytes)\n", info.name, ret);
	/* headers display */
	netprint_print_headers(buffer, ret, net);
      }
      /* release the buffer */
      free(buffer);
      (*packets)++;
      /* release the headers */
      nettools_release_buffer(&net);
    } /* select */
  } /* while */

  /* release all resources ; maybe unreachable */
  netiface_list_delete(ifaces);
  return EXIT_SUCCESS;
}
