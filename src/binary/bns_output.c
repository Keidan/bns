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
 * @fn int bns_output(FILE* output, char* outputname, struct bns_filter_s filter, unsigned int size, unsigned int count, _Bool pcap, int *packets, usage_fct usage)
 * @brief Fonction gerant le mode output et console.
 * @param output Fichier output ou NULL pour le mode console.
 * @param filter Filtre.
 * @param size Taille du fichier en Mb.
 * @param count Nombre max de fichiers.
 * @param pcap Use pcap format.
 * @param packets Nombre de paquets.
 * @param usage Fonction usage.
 * @return 0 si succes sinon -1.
 */

int bns_output(FILE* output, char* outputname, struct bns_filter_s filter, unsigned int size, unsigned int count, _Bool pcap, int *packets, usage_fct usage) {
  struct iface_s ifaces;
  struct iface_s* iter;
  char* buffer;
  int maxfd = 0;
  fd_set rset;
  struct bns_network_s net;
  unsigned int current = 0;
  _Bool first = 0;
  
  if(getuid()) usage(EXIT_FAILURE);

  if(output)
    fprintf(stdout, "Ouput mode [file:'%s'][filter{%s:%d:%d}]...\n", outputname, filter.iface, filter.ip, filter.port);
  else 
    fprintf(stdout, "Console mode [filter{%s:%d:%d}]...\n", filter.iface, filter.ip, filter.port);

  *packets = 0;
  /* RAZ du FD */
  FD_ZERO(&rset);

  /* Preparation de la liste d'interfaces disponibles. */
  if(bns_utils_prepare_ifaces(&ifaces, &maxfd, &rset, filter.iface) != 0) {
    bns_utils_clear_ifaces(&ifaces); /* force le clear pour fermer les sockets deja ouverts */
    return EXIT_FAILURE;
  }
    
  while(1) {
    /* Attente du prochain message */
    if (select(maxfd + 1, &rset, NULL, NULL, NULL) != -1) {
      /* liste les interfaces pour savoir si le packet est pour nous ou pas */
      list_for_each_entry(iter,&ifaces.list, list) {
	/* le packet doit être pour nous et l'interface doit etre up */
	if(!FD_ISSET(iter->fd, &rset) || !bns_utils_device_is_up(iter->fd, iter->name)) continue;
	
	/* Recuperation de la taille a lire */
	__u32 len = bns_utils_datas_available(iter->fd);
	/* La taille a lire est valide ? */
	if(!len) {
	  logger("%s: Zero length o_O ?\n", iter->name);
	  continue;
	}
	/* alloc du buffer */
	buffer = (char*)malloc(len);
	if(!buffer) {
	  /* un failed ici est critique donc exit */
	  bns_utils_clear_ifaces(&ifaces);
	  logger("%s: Malloc failed!\n", iter->name);
	  return EXIT_FAILURE;
	}
	/* Lecture du packet */
	int ret = recvfrom(iter->fd, buffer, len, 0, NULL, NULL);
	/* Si la lecture a echouee on passe au suivant */
	if (ret < 0) {
	  free(buffer);
	  logger("%s: recvfrom failed: (%d) %s.\n", iter->name, errno, strerror(errno));
	  continue;
	}

	/* decodage des differentes entetes */
	if(bns_header_decode_buffer(buffer, ret, &net, BNS_PACKET_CONVERT_NET2HOST) == -1) {
	  free(buffer);
	  bns_utils_clear_ifaces(&ifaces);
	  logger("FATAL: DECODE FAILED\n");
	  exit(EXIT_FAILURE); /* pas besoin de continuer... */
	}
        /* si un regle est appliquee */
	if(filter.ip || filter.port)
	  /* test de cette derniere */
          if(!bns_header_match_from_simple_filter(&net, filter)) {
	    bns_header_release_buffer(&net);
	    free(buffer);
	    continue;
	  } 
	/* output case */
	if(output) {
	  /* test de la taille */
	  if(size) {
	    /* current depasse count on leave */
	    if(count && (count == current || current > BNS_OUTPUT_MAX_FILES)) {
	      fprintf(stderr, "Max files (%d/%d) reached.", current, count);
	      bns_header_release_buffer(&net);
	      bns_utils_clear_ifaces(&ifaces);
	      free(buffer);
	      exit(0);
	    } 
	    /* recuperation de la taille du fichier */
	    long fsize = bns_utils_fsize(output);
	    long rsize = SIZE_1MB * size;
	    /* si la taille du fichier + le packet depasse la taille voulue */
	    if(fsize+ret >= rsize) {
	      /* close du precedant fichier */
	      fclose(output);
	      /* allocation du nouveau nom */
	      char* tmp = malloc(strlen(outputname) + 5); /* name '.' 3 digits + '\0' */
	      if(!tmp) {
		logger("Unable to alloc memory for file name '%s.%d'.", outputname, current);
		bns_header_release_buffer(&net);
		bns_utils_clear_ifaces(&ifaces);
		free(buffer);
		return EXIT_FAILURE;
	      }
	      /* set du nom */
	      sprintf(tmp, "%s.%03d", outputname, current++);
	      /* rename du fichier */
	      if(rename(outputname , tmp) == -1) {
		free(tmp);
		free(outputname);
		logger("Error renaming file: (%d) %s", errno, strerror(errno));
		bns_header_release_buffer(&net);
		bns_utils_clear_ifaces(&ifaces);
		free(buffer);
		return EXIT_FAILURE;
	      }
	      free(tmp);
	      /* reouvre le fichier */
	      output = fopen(outputname, "w+");
	      if(!output) {
		free(outputname);
		logger("Unable to open file '%s': (%d) %s\n", optarg, errno, strerror(errno));
		bns_header_release_buffer(&net);
		bns_utils_clear_ifaces(&ifaces);
		free(buffer);
		return EXIT_FAILURE;
	      }
	      first = 0;
	    }
	  }
	  if(!pcap) {
	    /* Ecriture du buffer */
	    fprintf(output, "---b%d,%s\n", ret, iter->name);
	    bns_utils_print_hex(output, buffer, ret, 1);
	    fflush(output);
	  } else
	    bns_utils_write_pcap_packet(output, buffer, len, ret, &first);
	} else {
	  /* partie decodage + display */
	  printf("iFace name: %s (%d bytes)\n", iter->name, ret);

	  /* affichage des headers */
	  bns_header_print_headers(buffer, ret, net);

	  /* plus besoin du buffer */
	  free(buffer);
	}
	(*packets)++;
	/* liberation des entetes */
	bns_header_release_buffer(&net);
      }
    }
  }

  /* liberation des resources ; bien que dans ce cas unreachable */
  bns_utils_clear_ifaces(&ifaces);
  return EXIT_SUCCESS;
}
