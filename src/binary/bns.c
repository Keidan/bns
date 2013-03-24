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
    { NULL     , 0, NULL, 0   } 
};

#define convert_to_int(str, n_out) ({		\
    n_out = strtol(str, NULL, 10);		\
    if((errno == ERANGE) || (errno == EINVAL))	\
      n_out = 0;				\
  })

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
  fprintf(stdout, "\t--input: Input file name [if set all options are useless, except --extract].\n");
  fprintf(stdout, "\t--port: port filter.\n");
  fprintf(stdout, "\t--host: host address filter.\n");
  fprintf(stdout, "\t--payload: Extract the payload only in stdout (only available with --input).\n");
  fprintf(stdout, "\t--raw: Print the payload in raw (only available with --input).\n");
  exit(err);
}


int main(int argc, char** argv) {
  char iname[IF_NAMESIZE], host[_POSIX_HOST_NAME_MAX];
  __u16 port = 0;
  _Bool payload_only = 0, raw = 0;
  unsigned int long_host = 0;

  bzero(iname, IF_NAMESIZE);
  bzero(host, _POSIX_HOST_NAME_MAX);
  
  fprintf(stdout, "Basic network sniffer is a FREE software v%d.%d.\nCopyright 2011-2013 By kei\nLicense GPL.\n", BNS_VERSION_MAJOR, BNS_VERSION_MINOR);
  /* pour fermer proprement sur le kill */
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
      default: /* '?' */
	logger("Unknown option '%c'\n", opt);
	usage(EXIT_FAILURE);
	break;
    }
  }

  if(input)
    return bns_input(input, payload_only, raw);
  struct bns_filter_s filter = {
    .ip = long_host,
    .port = port
  };
  return bns_output(output, iname, filter, usage);
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
