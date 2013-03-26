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

#define BUFFER_LENGTH ((PRINT_HEX_MAX_PER_LINES * 2) + 3)

static char input_buffer[BUFFER_LENGTH];

int bns_input(FILE* input, struct bns_filter_s filter, _Bool payload_only, _Bool raw) {
  struct bns_network_s net;
  __u32 length = 0, current = 0, lines = 0, ilen, i;
  char* buffer = NULL;
  int plen = 0;
  _Bool display = 0, name_matches = 0;
  bzero(input_buffer, BUFFER_LENGTH);
  char iname[IF_NAMESIZE];

  fprintf(stdout, "Input mode...\n");
  /* Parse toutes les lignes du fichier */
  while(fgets(input_buffer, BUFFER_LENGTH, input) != NULL){
    lines++;
    /* Bloc de debut. */
    if(strncmp(input_buffer, "---b", 4) == 0) {
      if(buffer) { /* Si on passe par la c'est qu'il y a un problème avec l'algo/fichier. */
	logger("FATAL: Buffer already allocated (line:%d)!!!\n", lines);
	return EXIT_FAILURE;
      }
      name_matches = 0;
      /* Exctraction de la taille. */
      sscanf(input_buffer+4, "%d,%s\n", &length, iname);
      if(strlen(filter.iface) && strcmp(filter.iface, iname) != 0) {
        length = 0;
        continue;
      }
      name_matches = 1;
      fprintf(stderr, "Parse block length: %d\n", length);
      /* RAZ de l'input. */
      bzero(input_buffer, BUFFER_LENGTH);
      if(length) {
	/* Allocation du buffer. */
	if((buffer = (char*)malloc(length + 1)) == NULL) {
	  logger("FATAL: Unable to alloc memory (length:%d) (line:%d)\n", length, lines);
	  return EXIT_FAILURE;
	}
	/* RAZ du buffer. */
	bzero(buffer, length);
      }
      continue;
    }
    if(!name_matches) continue;
    /* Si la taille vaut 0 il y a un pb. */
    if(!length) {
      fprintf(stderr, "Invalid paquet length (line:%d)\n", lines);
      bzero(input_buffer, BUFFER_LENGTH);
      continue;
    }
    if(current != length) {
      /* Ajustement de la taille de l'input */
      ilen = strlen(input_buffer);
      if(input_buffer[0] == '\n') continue;
      else if(input_buffer[ilen - 1] == '\n') {
	input_buffer[ilen - 1] = '\0';
	ilen = strlen(input_buffer);
      }
      /* Restoration du buffer */
      for(i = 0; i < ilen; i+=2) {
	char temp[2] = { input_buffer[i], input_buffer[i+1]};
	buffer[current++] = (char)strtol(temp, NULL, 16);
      }
    }
    /* Fin du bloc */
    if(current == length) {
      /* decodage des differentes entetes */
      if((plen = decode_network_buffer(buffer, length, &net, BNS_PACKET_CONVERT_NET2HOST)) == -1) {
	free(buffer);
	logger("FATAL: DECODE FAILED (line:%d)\n", lines);
	exit(EXIT_FAILURE); /* pas besoin de continuer... */
      }
      display = 0;
      /* si un regle est appliquee */
      if(filter.ip || filter.port) {
        /* test de cette derniere */
        if(match_from_simple_filter(&net, filter)) display = 1;
      } else display = 1;
      if(display) {
        if(payload_only) {
	  if(!raw)
	    bns_utils_print_hex(stdout, buffer + plen, length - plen, 0);
	  else
	    for(i = 0; i < (length - plen); i++)
	      printf("%c", (buffer+plen)[i]);
	        printf("\n");
        } else
	  bns_header_print_headers(buffer, length, net);
      }
      release_network_buffer(&net);
      /* Liberation du buffer et RAZ des index. */
      length = current = 0;
      free(buffer), buffer = NULL;
    }
    /* RAZ du buffer. */
    bzero(input_buffer, BUFFER_LENGTH);
  }
  return EXIT_SUCCESS;
}

