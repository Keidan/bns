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
#include "bns_common.h"
#include "bns_config.h"
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

static FILE* output = NULL;
static FILE* input = NULL;

static const struct option long_options[] = { 
    { "help"   , 0, NULL, 'h' },
    { "iface"  , 1, NULL, '0' },
    { "output" , 1, NULL, '1' },
    { "input"  , 1, NULL, '2' },
    { "host"   , 1, NULL, '3' },
    { "port"   , 1, NULL, '4' },
    { "payload", 0, NULL, '5' },
    { "raw"    , 0, NULL, '6' },
    { "size"   , 1, NULL, '7' },
    { "count"  , 1, NULL, '8' },
    { NULL     , 0, NULL, 0   } 
};

#define convert_to_int(str, n_out) ({		\
    n_out = strtol(str, NULL, 10);		\
    if((errno == ERANGE) || (errno == EINVAL))	\
      n_out = 0;				\
  })
  
#ifndef _POSIX_HOST_NAME_MAX
  #define _POSIX_HOST_NAME_MAX 255
#endif

static void bns_sig_int(sig_t s);
static void bns_cleanup(void);

/**
 * Affichage du 'usage'.
 * @param err Code passe a exit.
 */
void usage(int err) {
  fprintf(stdout, "usage: bns options\n");
  fprintf(stdout, "/!\\ Without input: Root privileges required.\n");
  fprintf(stdout, "\t--help, -h: Print this help.\n");
  fprintf(stdout, "\t--iface: Interface name.\n");
  fprintf(stdout, "\t--output: Output file name.\n");
  fprintf(stdout, "\t--input: Input file name [if set all options are useless, except --payload, --raw, --port, --host].\n");
  fprintf(stdout, "\t--port: port filter.\n");
  fprintf(stdout, "\t--host: host address filter.\n");
  fprintf(stdout, "\t--payload: Extract the payload only in stdout (only available with --input).\n");
  fprintf(stdout, "\t--raw: Print the payload in raw (only available with --input).\n");
  fprintf(stdout, "\t--size: Maximum size in Mb of the output file (only available with --output).\n");
  fprintf(stdout, "\t--count: Maximum number of files (only available with --output).\n");
  exit(err);
}


int main(int argc, char** argv) {
  char iname[IF_NAMESIZE], host[_POSIX_HOST_NAME_MAX];
  __u16 port = 0;
  _Bool payload_only = 0, raw = 0;
  __u32 long_host = 0, size = 0, count = 0;
  char* outputname = NULL;

  bzero(iname, IF_NAMESIZE);
  bzero(host, _POSIX_HOST_NAME_MAX);
  
  fprintf(stdout, "Basic network sniffer is a FREE software v%d.%d.\nCopyright 2011-2013 By kei\nLicense GPL.\n", BNS_VERSION_MAJOR, BNS_VERSION_MINOR);
  /* pour fermer proprement sur le kill */
  atexit(bns_cleanup);
  signal(SIGINT, (__sighandler_t)bns_sig_int);

  int opt;
  while ((opt = getopt_long(argc, argv, "h0:1:2:3:4:56:7:", long_options, NULL)) != -1) {
    switch (opt) {
      case 'h': usage(0); break;
      case '0': /* iface */
	strncpy(iname, optarg, IF_NAMESIZE);
	if(strncmp(iname, "any", IF_NAMESIZE))
	  bzero(iname, IF_NAMESIZE);
	break;
      case '1': /* output */
	if(outputname) free(outputname), outputname = NULL;
	if(!(outputname = (char*)malloc(strlen(optarg)))) {
	  logger("Unable to alloc memory for file name '%s'\n", optarg);
	  usage(EXIT_FAILURE);
	}
	strcpy(outputname, optarg);
	output = fopen(outputname, "w+");
	if(!output) {
	  free(outputname);
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
        /* passage de l'ip en long*/
	long_host = bns_utils_ip_to_long(host);
	break;
      case '4': /* port */
	convert_to_int(optarg, port);
	break;
      case '5': /* payload */
	payload_only = 1;
	break;
      case '6': /* raw */
	raw = 1;
	break;
      case '7': /* size */
	convert_to_int(optarg, size);
	break;
      case '8': /* count */
	convert_to_int(optarg, count);
	break;
      default: /* '?' */
	logger("Unknown option '%c'\n", opt);
	usage(EXIT_FAILURE);
	break;
    }
  }

  struct bns_filter_s filter = {
    .ip = long_host,
    .port = port,
  };
  bzero(filter.iface, IF_NAMESIZE);
  if(strlen(iname))
    strcpy(filter.iface, iname);
  if(input) {
    free(outputname);
    return bns_input(input, filter, payload_only, raw);
  }
  int ret = bns_output(output, outputname, filter, size, count, usage);
  free(outputname);
  return ret;
}


static void bns_sig_int(sig_t s) {
  exit(0); /* call atexit */
}

static void bns_cleanup(void) {
  /* si les fichiers ne sont pas sur stdxxx */
  if(input && fileno(input) > 2)
    fclose(input);
  if(output && fileno(output) > 2)
    fclose(output);
}
