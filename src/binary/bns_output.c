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


int bns_output(FILE* output, char iname[IF_NAMESIZE], struct bns_filter_s filter, usage_fct usage) {
  struct iface_s ifaces;
  struct iface_s* iter;
  char* buffer;
  int maxfd = 0;
  fd_set rset;
  struct bns_network_s net;

  if(output)
    fprintf(stdout, "Ouput mode...\n");
  else 
    fprintf(stdout, "Console mode...\n");
  
  if(getuid())
    usage(EXIT_FAILURE);

  /* RAZ du FD */
  FD_ZERO(&rset);

  /* Preparation de la liste d'interfaces disponibles. */
  if(bns_utils_prepare_ifaces(&ifaces, &maxfd, &rset, iname) != 0) {
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
	if(decode_network_buffer(buffer, ret, &net) == -1) {
	  free(buffer);
	  bns_utils_clear_ifaces(&ifaces);
	  logger("FATAL: DECODE FAILED\n");
	  exit(EXIT_FAILURE); /* pas besoin de continuer... */
	}
        /* si un regle est appliquee */
	if(filter.ip || filter.port)
	  /* test de cette derniere */
          if(!match_from_simple_filter(&net, filter)) {
	    release_network_buffer(&net);
	    free(buffer);
	    continue;
	  } 
	if(output) {
	  /* Ecriture du buffer */
	  fprintf(output, "---b%d\n", ret);
	  bns_utils_print_hex(output, buffer, ret);
	  fprintf(output, "---e\n");
	  fflush(output);
	} else {
	  /* partie decodage + display */
	  printf("iFace name: %s (%d bytes)\n", iter->name, ret);
	  /* affichage de l'entete ethernet */
	  bns_header_print_eth(net.eth);
	
	  /* Si le paquet contient un header IP v4/v6 on decode */
	  if(net.ipv4) {
	    /* affichage de l'entete IP */
	    bns_header_print_ip(net.ipv4);
	    if(net.tcp) {
	      /* affichage de l'entete TCP */
	      bns_header_print_tcp(net.tcp);
	    } else if(net.udp) {
	      /* affichage de l'entete UDP */
	      bns_header_print_upd(net.udp);
	    }
	    /* Si le paquet contient un header ARP */
	  } else if(net.arp) {
	    /* affichage de l'entete ARP */
	    bns_header_print_arp(net.arp);

	  } /* le paquet ne contient pas de header ip ni arp ; non gere ici*/

	  printf("\n");/* mise en page */
	  /* affichage du buffer */
	  bns_utils_print_hex(stdout, buffer, ret);

	  /* plus besoin du buffer */
	  free(buffer);
	}
	/* liberation des entetes */
	release_network_buffer(&net);
      }
    }
  }

  /* liberation des resources ; bien que dans ce cas unreachable */
  bns_utils_clear_ifaces(&ifaces);
  return EXIT_SUCCESS;
}

