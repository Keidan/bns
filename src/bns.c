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
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "bns_utils.h"
#include "bns_packet.h"
#include "bns_config.h"
#include "bns_logger.h"

/* 19 = espaces + \r\n ; * 2 pour le texte */
#define BUFFER_LENGTH ((PRINT_HEX_MAX_PER_LINES + 19) * 2)

static FILE* output = NULL;
static FILE* input = NULL;
static char input_buffer[BUFFER_LENGTH];

static const struct option long_options[] = { 
    { "help"   , 0, NULL, 'h' },
    { "iface"  , 1, NULL, '0' },
    { "output" , 1, NULL, '1' },
    { "input"  , 1, NULL, '2' },
    { "host"   , 1, NULL, '3' },
    { "port"   , 1, NULL, '4' },
    { "extract", 0, NULL, '5' },
    { NULL     , 0, NULL, 0   } 
};

#define convert_to_int(str, n_out) ({		\
    n_out = strtol(str, NULL, 10);		\
    if((errno == ERANGE) || (errno == EINVAL))	\
      n_out = 0;				\
  })

static void bns_sig_int(sig_t s);
static void bns_cleanup(void);


void usage(int err) {
  fprintf(stdout, "usage: bns options\n");
  fprintf(stdout, "/!\\ Without input: Root privileges required.\n");
  fprintf(stdout, "\t--help, -h: Print this help.\n");
  fprintf(stdout, "\t--iface: Interface name.\n");
  fprintf(stdout, "\t--output: Output file name.\n");
  fprintf(stdout, "\t--input: Input file name [if set all options are useless, except --extract].\n");
  fprintf(stdout, "\t--port: port filter.\n");
  fprintf(stdout, "\t--host: host address filter.\n");
  fprintf(stdout, "\t--extract: Extract the payload in stdout (only available with --input).\n");
  exit(err);
}


int main(int argc, char** argv) {
  struct iface_s ifaces;
  struct iface_s* iter;
  char* buffer;
  int maxfd = 0;
  fd_set rset;
  char iname[IF_NAMESIZE], host[_POSIX_HOST_NAME_MAX];
  __u16 port = 0;
  _Bool extract = 0;
  unsigned int long_host = 0;
  long long int counts = 0L;
  struct bns_network_s net;

  bzero(iname, IF_NAMESIZE);
  bzero(host, _POSIX_HOST_NAME_MAX);
  bzero(input_buffer, BUFFER_LENGTH);
  
  fprintf(stdout, "Basic network sniffer is a FREE software v%d.%d.\nCopyright 2011-2013 By kei\nLicense GPL.\n", BNS_VERSION_MAJOR, BNS_VERSION_MINOR);

  atexit(bns_cleanup);
  signal(SIGINT, (__sighandler_t)bns_sig_int);

  int opt;
  while ((opt = getopt_long(argc, argv, "h0:1:2:3:4:5", long_options, NULL)) != -1) {
    switch (opt) {
      case 'h': usage(0); break;
      case '0': /* iface */
	strncpy(iname, optarg, IF_NAMESIZE);
	if(strncmp(iname, "any", IF_NAMESIZE))
	  bzero(iname, IF_NAMESIZE);
	break;
      case '1': /* output */
	output = fopen(optarg, "w+");
	if(!output) {
	  logger("Unable to open file '%s': (%d) %s\n", optarg, errno, strerror(errno));
	  usage(EXIT_FAILURE);
	}
	break;
      case '2': /* input */
	input = fopen(optarg, "r");
	if(!input) {
	  logger("File '%s' not found\n", optarg);
	  usage(EXIT_FAILURE);
	}
	break;
      case '3': /* host */
	strncpy(host, optarg, _POSIX_HOST_NAME_MAX);
	if(!bns_utils_is_ipv4(host))
	  bns_utils_hostname_to_ip(host, host);
	long_host = bns_utils_ip_to_long(host);
	break;
      case '4': /* port */
	convert_to_int(optarg, port);
	break;
      case '5': /* extract */
	extract = 1;
      default: /* '?' */
	usage(EXIT_FAILURE);
	break;
    }
  }

  if(input) {
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
      printf("\textract:%d, %s", extract, input_buffer);
      bzero(input_buffer, BUFFER_LENGTH);
    }
    return EXIT_SUCCESS; /* input ne fait que ca */
  } else if(output)
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


	if(decode_network_buffer(buffer, &net, ret) != 0) {
	  free(buffer);
	  bns_utils_clear_ifaces(&ifaces);
	  logger("FATAL: DECODE FAILED\n");
	  exit(EXIT_FAILURE); /* pas besoin de continuer... */
	}
	if(long_host || port)
          if(!match_from_simple_filter(&net, long_host, port)) {
	    release_network_buffer(&net);
	    free(buffer);
	    continue;
	  } 
	if(output) {
	  /* affichage du buffer */
	  fprintf(output, "---b%lld\n", counts);
	  bns_utils_print_hex(output, buffer, ret);
	  fprintf(output, "---e%lld\n", counts);
	  fflush(output);
	  counts++;
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
	release_network_buffer(&net);
      }
    }
  }

  /* liberation des resources ; bien que dans ce cas unreachable */
  bns_utils_clear_ifaces(&ifaces);
  return EXIT_SUCCESS;
}


static void bns_sig_int(sig_t s) {
  exit(0); /* call atexit */
}

static void bns_cleanup(void) {
  if(input && fileno(input) > 2)
    fclose(input);
  if(output && fileno(output) > 2)
    fclose(output);
}
