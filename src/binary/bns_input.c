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

/* 19 = espaces + \r\n ; * 2 pour le texte */
#define BUFFER_LENGTH ((PRINT_HEX_MAX_PER_LINES + 19) * 2)

static char input_buffer[BUFFER_LENGTH];

int bns_input(FILE* input, _Bool payload_only) {
  //struct bns_network_s net;


  bzero(input_buffer, BUFFER_LENGTH);

  /* TODO a finir */
  fprintf(stdout, "Input mode...\n");
  _Bool block_start = 0, block_end=1;
  while(fgets(input_buffer, BUFFER_LENGTH, input) != NULL){
    if(strncmp(input_buffer, "---b", 4) == 0) {
      printf("Parse block number: %s", input_buffer+4);
      block_end=!(block_start=1);
    } else if(strncmp(input_buffer, "---e", 4) == 0) {
      block_start=!(block_end=1);
    }
    //if(extract) payload only
    printf("\tpayload_only:%d, %s", payload_only, input_buffer);
    bzero(input_buffer, BUFFER_LENGTH);
  }
  return EXIT_SUCCESS;
}

