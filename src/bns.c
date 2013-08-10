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
#include <tk/text/string.h>
#include <tk/text/stringtoken.h>
#include <tk/sys/sysutils.h>

static FILE* output = NULL;
static FILE* input = NULL;
static int packets = 0;

static const struct option long_options[] = { 
    { "help"   , 0, NULL, 'h' },
    { "iface"  , 1, NULL, '0' },
    { "output" , 1, NULL, '1' },
    { "input"  , 1, NULL, '2' },
    { "filter" , 1, NULL, '3' },
    { "payload", 0, NULL, '4' },
    { "raw"    , 0, NULL, '5' },
    { "size"   , 1, NULL, '6' },
    { "count"  , 1, NULL, '7' },
    { "link"   , 1, NULL, '8' },
    { NULL     , 0, NULL, 0   } 
};

  
#ifndef _POSIX_HOST_NAME_MAX
  #define _POSIX_HOST_NAME_MAX 255
#endif

#define blogger(...) ({				\
    logger(LOG_ERR, __VA_ARGS__);		\
    fprintf(stderr, __VA_ARGS__);		\
  })

static void bns_cleanup(void);

void usage(int err) {
  fprintf(stdout, "usage: bns options\n");
  fprintf(stdout, "/!\\ Without input: Root privileges required.\n");
  fprintf(stdout, "\t--help, -h: Print this help.\n");
  fprintf(stdout, "\t--iface: Interface name.\n");
  fprintf(stdout, "\t--output: Output file name.\n");
  fprintf(stdout, "\t--input: Input file name [if set all options are useless, except --payload, --raw, --port, --host].\n");
  fprintf(stdout, "\t--filter: {mac,host,port} filter.\n");
  fprintf(stdout, "\t\tavilable entries (in order): mac, host, port.\n");
  fprintf(stdout, "\t\teg:\n");
  fprintf(stdout, "\t\t {mac_value,host_value,por_value} <- For all entries.\n");
  fprintf(stdout, "\t\t {mac_value,,} <- MAC only.\n");
  fprintf(stdout, "\t\t {,host_value,} <- Host only.\n");
  fprintf(stdout, "\t\t {,,por_value} <- Port only.\n");
  fprintf(stdout, "\t\t {mac_value,,por_value} <- MAC and port.\n");
  fprintf(stdout, "\t\t etc...\n");
  fprintf(stdout, "\t--payload: Extract the payload only in stdout (only available with --input).\n");
  fprintf(stdout, "\t--raw: Print the payload in raw (only available with --input and --payload).\n");
  fprintf(stdout, "\t--size: Maximum size in Mb of the output file (only available with --output).\n");
  fprintf(stdout, "\t--count: Maximum number of files - max value %d (only available with --output).\n", BNS_OUTPUT_MAX_FILES);
  fprintf(stdout, "\t--link: Force the default link type (only available with --output).\n");
  fprintf(stdout, "\t\tThe default link type correspond to value %d (ethernet)\n", NETUTILS_PCAP_LINKTYPE_ETHERNET);
  fprintf(stdout, "\t\tSee the following link for more types: http://www.tcpdump.org/linktypes.html\n");
  exit(err);
}


int main(int argc, char** argv) {
  char iname[IF_NAMESIZE], host[_POSIX_HOST_NAME_MAX], *tmp, *tmptok;
  __u16 port = 0;
  _Bool payload_only = 0, raw = 0;
  __u32 long_host = 0, size = 0, count = 0;
  __u32 idx;
  __u32 link = NETUTILS_PCAP_LINKTYPE_ETHERNET;
  char fname[FILENAME_MAX];
  smac_t mac;
  stringtoken_t tok;

  log_init("bns", LOG_PID, LOG_USER);
  bzero(fname, FILENAME_MAX);
  bzero(mac, NETUTILS_SMAC_LEN);
  bzero(iname, IF_NAMESIZE);
  bzero(host, _POSIX_HOST_NAME_MAX);
  fprintf(stdout, "Basic network sniffer is a FREE software v%d.%d.\nCopyright 2011-2013 By kei\nLicense GPL.\n\n", BNS_VERSION_MAJOR, BNS_VERSION_MINOR);


  sysutils_exit_action(log_init_cast("bns", LOG_PID, LOG_USER), bns_cleanup);

  int opt;
  while ((opt = getopt_long(argc, argv, "h0:1:2:3:456:7:8:", long_options, NULL)) != -1) {
    switch (opt) {
      case 'h': usage(0); break;
      case '0': /* iface */
	strncpy(iname, optarg, IF_NAMESIZE);
	if(strncmp(iname, "any", IF_NAMESIZE) == 0)
	  bzero(iname, IF_NAMESIZE);
	break;
      case '1': /* output */
	strncpy(fname, optarg, FILENAME_MAX);
	output = fopen(fname, "w+");
	if(!output) {
	  blogger("Unable to open file '%s': (%d) %s\n", optarg, errno, strerror(errno));
	  usage(EXIT_FAILURE);
	}
	break;
      case '2': /* input */
	strncpy(fname, optarg, FILENAME_MAX);
	input = fopen(fname, "rb");
	if(!input) {
	  blogger("Unable to open file '%s': (%d) %s\n", optarg, errno, strerror(errno));
	  usage(EXIT_FAILURE);
	}
	break;
      case '3': /* filter */
	tmp = optarg;
	idx = string_indexof(tmp, "{");
	if(idx == -1) {
	  blogger("Invalid filter format: '{' requires \n");
	  usage(EXIT_FAILURE);
	}
	if(string_count(tmp, ',') != 2) {
	  blogger("Invalid filter format: ','x2 requires \n");
	  usage(EXIT_FAILURE);
	}
	if(string_count(tmp, '}') != 1) {
	  blogger("Invalid filter format: '}'x1 requires \n");
	  usage(EXIT_FAILURE);
	}
	tmp[strlen(tmp)-1] = 0;
	
	tok = stringtoken_init(tmp+1, ",");
	/* mac */
	tmptok = stringtoken_next_token(tok);
	if(tmptok) {
	  strcpy(mac, tmptok);
	  free(tmptok);
	}
	/* host */
	tmptok = stringtoken_next_token(tok);
	if(tmptok){
	  strcpy(host, tmptok);
	  free(tmptok);
	}
	/* port */
	tmptok = stringtoken_next_token(tok);
	if(tmptok) {
	  port = string_parse_int(tmptok, 0);
	  free(tmptok);
	}
	stringtoken_release(tok);
	/* test */
	if(strlen(host)) {
	  if(!netutils_is_ipv4(host))
	    netutils_hostname_to_ip(host, host);
	  long_host = netutils_ip_to_long(host);
	}
	break;
      case '4': /* payload */
	payload_only = 1;
	break;
      case '5': /* raw */
	raw = 1;
	break;
      case '6': /* size */
	size = string_parse_int(optarg, 0);
	break;
      case '7': /* count */
	count = string_parse_int(optarg, BNS_OUTPUT_MAX_FILES+1);
        if(count > BNS_OUTPUT_MAX_FILES) {
          blogger("Invalid count value (max:%d)\n", BNS_OUTPUT_MAX_FILES);
          usage(EXIT_FAILURE);
        }
	break;
      case '8': /* link */
	link = string_parse_int(optarg, NETUTILS_PCAP_LINKTYPE_ETHERNET);
	break;
      default: /* '?' */
	blogger("Unknown option '%c'\n", opt);
	usage(EXIT_FAILURE);
	break;
    }
  }

  struct netutils_filter_s filter;
  memset(&filter, 0, sizeof(struct netutils_filter_s));
  filter.ip = long_host;
  filter.port = port;
  if(strlen(iname)) strcpy(filter.iface, iname);
  if(strlen(mac)) strcpy(filter.mac, mac);

  fprintf(stdout, "Mode: ");
  if(input)       fprintf(stdout, "Input ('%s')\n", fname);
  else if(output) fprintf(stdout, "Ouput ('%s')\n", fname);
  else            fprintf(stdout, "Console\n");

  fprintf(stdout, "Filter: [%s]{%s,%s,%d}\n",  strlen(iname) ? iname : "*", netutils_valid_mac(mac) ? mac : "*", strlen(host) ? host : "*", port);
  fprintf(stdout, "PCAP support: %s\n", NETPRINT_SET_NSET(1));
  fprintf(stdout, "\n");
  if(input)
    return bns_input(input, filter, payload_only, raw);
  int ret = bns_output(output, fname, filter, size, count, &packets, link, usage);
  return ret;
}

static void bns_cleanup(void) {
  char ssize[SYSUTILS_MAX_SSIZE];
  if(input) fclose(input), input = NULL;
  if(output) {
    fprintf(stderr, "%d packets captured.\n", packets);
    sysutils_size_to_string(sysutils_fsize(output), ssize);
    fprintf(stderr, "File size %s.\n", ssize);
    fclose(output), output = NULL;
  }
  log_close();
}
