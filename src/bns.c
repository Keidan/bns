/**
 *******************************************************************************
 * @file bns.c
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "bns_utils.h"
#include "bns_header.h"


int main(int argc, char** argv) {
  struct iface_s ifaces;
  struct iface_s* iter;
  char* buffer;
  int maxfd = 0;
  fd_set rset;
  
  fprintf(stdout, "Basic network sniffer is a FREE software.\nCopyright 2011-2013 By kei\nLicense GPL.\n);

  FD_ZERO(&rset);

  /* Preparation de la liste d'interfaces disponibles. */
  if(bns_utils_prepare_ifaces(&ifaces, &maxfd, &rset) != 0) {
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
	  fprintf(stderr, "%s: Zero length o_O ?\n", iter->name);
	  continue;
	}
	/* alloc du buffer */
	buffer = (char*)malloc(len);
	if(!buffer) {
	  /* un failed ici est critique donc exit */
	  bns_utils_clear_ifaces(&ifaces);
	  fprintf(stderr, "%s: Malloc failed!\n", iter->name);
	  return EXIT_FAILURE;
	}
	/* Lecture du packet */
	int ret = recvfrom(iter->fd, buffer, len, 0, NULL, NULL);
	/* Si la lecture a echouee on passe au suivant */
	if (ret < 0) {
	  free(buffer);
	  fprintf(stderr, "%s: recvfrom failed: (%d) %s.\n", iter->name, errno, strerror(errno));
	  continue;
	}
	/* init */
	__u32 hoffset = 0;
	/* partie decodage + display */
	printf("iFace name: %s (%d bytes)\n", iter->name, ret);
	/* Decodage + affichage de l'entete ethernet */
	__be16 hproto = bns_header_print_eth(buffer, ret, &hoffset);
	
	/* Si le paquet contient un header IP v4/v6 on decode */
	if(hproto == ETH_P_IP || hproto == ETH_P_IPV6) {
	  /* Decodage + affichage de l'entete IP */
	  __u8 ip_proto = bns_header_print_ip(buffer, ret, &hoffset);
	  if(ip_proto == IPPROTO_TCP) {
	  /* Decodage + affichage de l'entete TCP */
	    bns_header_print_tcp(buffer, ret, &hoffset);
	  } else if(ip_proto == IPPROTO_UDP) {
	  /* Decodage + affichage de l'entete UDP */
	    bns_header_print_upd(buffer, ret, &hoffset);
	  } else if(ip_proto == IPPROTO_ICMP) {
	    printf("***ICMPv4 UNSUPPORTED ***\n");
	  } else if(ip_proto == IPPROTO_ICMPV6) {
	    printf("***ICMPv6 UNSUPPORTED ***\n");
	  }  else /* Le header est d'un autre type qu'UDP, TCP */
	    printf("***Unsupported IP protocol: %d***\n", ip_proto);

	  /* Si le paquet contient un header ARP */
	} else if(hproto == ETH_P_ARP) {
	  /* Decodage + affichage de l'entete ARP */
	  bns_header_print_arp(buffer, ret, &hoffset);

	} /* le paquet ne contient pas de header ip ni arp ; non gere ici*/

	printf("\n");/* mise en page */
	/* affichage du buffer */
	bns_utils_print_hex(buffer, ret);
	/* plus besoin du buffer */
	free(buffer);
      }
    }
  }

  /* liberation des resources ; bien que dans ce cas unreachable */
  bns_utils_clear_ifaces(&ifaces);
  return EXIT_SUCCESS;
}



