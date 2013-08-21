/**
 *******************************************************************************
 * @file bns_common.h
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
#ifndef __BNS_COMMON_H__
  #define __BNS_COMMON_H__

  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <errno.h>
  #include <string.h>
  #include <tk/sys/log.h>
  #include <tk/sys/stools.h>
  #include <tk/io/net/net.h>
  #include <tk/text/string.h>

  #define BNS_OUTPUT_MAX_FILES 999

  typedef void(*usage_fct)(int);

  /**
   * @fn int bns_input(FILE* input, struct ntools_filter_s filter, _Bool payload_only, _Bool raw)
   * @brief Manageent of the input mode.
   * @param input Input file.
   * @param filter Filter.
   * @param payload_only Exctract only the payload.
   * @param raw Display the payload in raw.
   * @return 0 on success else -1.
   */
  int bns_input(FILE* input, struct ntools_filter_s filter, _Bool payload_only, _Bool raw);

  /**
   * @fn int bns_output(FILE* output, char* outputname, struct ntools_filter_s filter, unsigned int size, unsigned int count, int *packets, __u32 link, usage_fct usage)
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
  int bns_output(FILE* output, char* outputname, struct ntools_filter_s filter, unsigned int size, unsigned int count, int *packets, __u32 link, usage_fct usage);

#endif /* __BNS_COMMON_H__ */
