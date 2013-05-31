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


static void bns_output_err_clean(struct netutils_headers_s *net, struct iface_s *ifaces, char* buffer) {
  if(net) netutils_release_buffer(net);
  if(ifaces) netutils_clear_ifaces(ifaces);
  if(buffer) free(buffer);
}

/**
 * @fn int bns_output(FILE* output, char* outputname, struct netutils_filter_s filter, unsigned int size, unsigned int count, _Bool pcap, int *packets, usage_fct usage)
 * @brief Fonction gerant le mode output et console.
 * @param output Fichier output ou NULL pour le mode console.
 * @param filter Filtre.
 * @param size Taille du fichier en Mb.
 * @param count Nombre max de fichiers.
 * @param packets Nombre de paquets.
 * @param usage Fonction usage.
 * @return 0 si succes sinon -1.
 */
int bns_output(FILE* output, char* outputname, struct netutils_filter_s filter, unsigned int size, unsigned int count, int *packets, usage_fct usage) {
  struct iface_s ifaces;
  struct iface_s* iter;
  char* buffer;
  int maxfd = 0;
  fd_set rset;
  struct netutils_headers_s net;
  unsigned int current = 0;
  _Bool first = 0;
  
  if(getuid()) usage(EXIT_FAILURE);

  *packets = 0;
  /* RAZ du FD */
  FD_ZERO(&rset);

  /* Preparation de la liste d'interfaces disponibles. */
  if(netutils_prepare_ifaces(&ifaces, &maxfd, &rset, filter.iface) != 0) {
    bns_output_err_clean(NULL, &ifaces, NULL);/* force le clear pour fermer les sockets deja ouverts */
    return EXIT_FAILURE;
  }
    
  while(1) {
    /* Attente du prochain message */
    if (select(maxfd + 1, &rset, NULL, NULL, NULL) != -1) {
      /* liste les interfaces pour savoir si le packet est pour nous ou pas */
      list_for_each_entry(iter,&ifaces.list, list) {
	/* le packet doit être pour nous et l'interface doit etre up */
	if(!FD_ISSET(iter->fd, &rset) || !netutils_device_is_up(iter->fd, iter->name)) continue;
	
	/* Recuperation de la taille a lire */
	__u32 len = netutils_datas_available(iter->fd);
	/* La taille a lire est valide ? */
	if(!len) {
	  logger(LOG_ERR, "%s: Zero length o_O ?\n", iter->name);
	  continue;
	}
	/* alloc du buffer */
	buffer = (char*)malloc(len);
	if(!buffer) {
	  /* un failed ici est critique donc exit */
	  netutils_clear_ifaces(&ifaces);
	  bns_output_err_clean(NULL, &ifaces, NULL);
	  logger(LOG_ERR, "%s: Malloc failed!\n", iter->name);
	  return EXIT_FAILURE;
	}
	/* Lecture du packet */
	int ret = recvfrom(iter->fd, buffer, len, 0, NULL, NULL);
	/* Si la lecture a echouee on passe au suivant */
	if (ret < 0) {
	  free(buffer);
	  bns_output_err_clean(NULL, NULL, buffer);
	  logger(LOG_ERR, "%s: recvfrom failed: (%d) %s.\n", iter->name, errno, strerror(errno));
	  continue;
	}

	/* decodage des differentes entetes */
	if(netutils_decode_buffer(buffer, ret, &net, NETUTILS_CONVERT_NET2HOST) == -1) {
	  bns_output_err_clean(NULL, &ifaces, buffer);
	  logger(LOG_ERR, "FATAL: DECODE FAILED\n");
	  exit(EXIT_FAILURE); /* pas besoin de continuer... */
	}
        /* si un regle est appliquee */
	if(filter.ip || filter.port)
	  /* test de cette derniere */
          if(!netutils_match_from_simple_filter(&net, filter)) {
	    bns_output_err_clean(&net, NULL, buffer);
	    continue;
	  } 
	/* output case */
	if(output) {
	  /* test de la taille */
	  if(size) {
	    /* current depasse count on leave */
	    if(count && (count == current || current > BNS_OUTPUT_MAX_FILES)) {
	      fprintf(stderr, "Max files (%d/%d) reached.", current, count);
	      bns_output_err_clean(&net, &ifaces, buffer);
	      exit(0);
	    } 
	    /* recuperation de la taille du fichier */
	    long fsize = sysutils_fsize(output);
	    long rsize = SIZE_1MB * size;
	    /* si la taille du fichier + le packet depasse la taille voulue */
	    if(fsize+ret >= rsize) {
	      /* close du precedant fichier */
	      fclose(output);
	      /* allocation du nouveau nom */
	      char* tmp = malloc(strlen(outputname) + 5); /* name '.' 3 digits + '\0' */
	      if(!tmp) {
		logger(LOG_ERR, "Unable to alloc memory for file name '%s.%d'.", outputname, current);
		bns_output_err_clean(&net, &ifaces, buffer);
		return EXIT_FAILURE;
	      }
	      /* set du nom */
	      sprintf(tmp, "%s.%03d", outputname, current++);
	      /* rename du fichier */
	      if(rename(outputname , tmp) == -1) {
		free(tmp);
		free(outputname);
		logger(LOG_ERR, "Error renaming file: (%d) %s", errno, strerror(errno));
		bns_output_err_clean(&net, &ifaces, buffer);
		return EXIT_FAILURE;
	      }
	      free(tmp);
	      /* reouvre le fichier */
	      output = fopen(outputname, "w+");
	      if(!output) {
		free(outputname);
		logger(LOG_ERR, "Unable to open file '%s': (%d) %s\n", optarg, errno, strerror(errno));
		bns_output_err_clean(&net, &ifaces, buffer);
		return EXIT_FAILURE;
	      }
	      first = 0;
	    }
	  }
	  netutils_write_pcap_packet(output, buffer, len, ret, &first);
	} else {
	  /* partie decodage + display */
	  printf("iFace name: %s (%d bytes)\n", iter->name, ret);

	  /* affichage des headers */
	  netprint_print_headers(buffer, ret, net);
	}
	/* plus besoin du buffer */
	free(buffer);
	(*packets)++;
	/* liberation des entetes */
	netutils_release_buffer(&net);
      } /* foreach */
    } /* select */
  } /* while */

  /* liberation des resources ; bien que dans ce cas unreachable */
  netutils_clear_ifaces(&ifaces);
  return EXIT_SUCCESS;
}
