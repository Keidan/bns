/**
 *******************************************************************************
 * @file bns_utils.c
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
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <bns/bns_utils.h>
#include <bns/bns_logger.h>

int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset, const char iname[IF_NAMESIZE]) {
  int i;
  struct ifreq ifr;
  struct sockaddr_ll sll;
  char *name;
  int fd;

  memset(&sll, 0, sizeof(sll));
  memset(&ifr, 0, sizeof(ifr));

  /* Liste toutes les cartes reseaux du PC */
  struct if_nameindex *nameindex = if_nameindex();
  if(nameindex == NULL){
    logger("if_nameindex: (%d) %s.\n", errno, strerror(errno));
    return -1;
  }

  /* init de la liste */
  INIT_LIST_HEAD(&(ifaces->list));

  /* boucle sur les interfaces */
  i = 0; /* init */
  while(1){
    if(!nameindex[i].if_name) break;
    if(strlen(iname) && strncmp(iname, nameindex[i].if_name, IF_NAMESIZE) != 0) continue;
    /* Recuperation du nom qui sera utilise plus bas. */
    name = nameindex[i++].if_name;

    /* Creation d'un socket qui sera utilise pour l'ecoute + les ios*/
    /* Socket raw */
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd < 0) {
      if_freenameindex(nameindex);
      logger("socket failed: (%d) %s.\n", errno, strerror(errno));
      return -1;
    }

    /* Pas d'ajout de l'interface si elle n'est pas UP */
    if(!bns_utils_device_is_up(fd, name)) {
      close(fd);
      continue;
    }
      
    /* set du fd_set + calcul du maxfd */
    if(fd > *maxfd) *maxfd = fd;
    FD_SET(fd, rset);

    /* Recuperation de l'index correspondant a l'interface reseau  */
    strncpy((char *)ifr.ifr_name, name, IF_NAMESIZE);
    if((ioctl(fd, SIOCGIFINDEX, &ifr)) == -1) {
      if_freenameindex(nameindex);
      close(fd);
      logger("get index failed: (%d) %s.\n", errno, strerror(errno));
      return -1;
    }

    /* Init de la structure sockaddr_ll */
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL); /* On veut ecouter tous les paquets */

    /* Bind sur l'interface*/
    if((bind(fd, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
      if_freenameindex(nameindex);
      close(fd);
      logger("bind failed: (%d) %s.\n", errno, strerror(errno));
      return -1;
    }

    /* ajout de l'interface */
    bns_utils_add_iface(ifaces, name, ifr.ifr_ifindex, fd);
  }

  /* Liberation des ressources */
  if_freenameindex(nameindex);
  return 0;
}


void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd) {
  struct iface_s* node;
  node = (struct iface_s*)malloc(sizeof(struct iface_s));
  if(!node) {
    logger("if_nameindex: (%d) %s.\n", errno, strerror(errno));
    return;
  }
  /* init + ajout de l'element */
  strncpy(node->name, name, IF_NAMESIZE);
  node->fd = fd;
  node->index = index;
  list_add_tail(&(node->list), &(list->list));
}


void bns_utils_clear_ifaces(struct iface_s* ifaces) {
  struct iface_s* iter;
  while(!list_empty(&ifaces->list) ) {
    iter = list_entry(ifaces->list.next, struct iface_s, list);
    close(iter->fd); /* close du socket */
    list_del(&iter->list); /*delete de l'item dans la liste */
    free(iter);
  }
}


_Bool bns_utils_device_is_up(int fd, char name[IF_NAMESIZE]) {
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  /* copy du nom de l'interface */
  strncpy((char *)ifr.ifr_name, name, IF_NAMESIZE);
  /* demande la liste des flags */
  int ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
  if (ret == -1) {
    logger("flags: (%d) %s.\n", errno, strerror(errno));
    return ret;
  }
  /* 1 si le flag up est positionne */
  return !!(ifr.ifr_flags & IFF_UP);
}


__u32 bns_utils_datas_available(int fd) {
  __u32 available = 0;
  /* demande le nombre d'octets quipeuvent etre lues */
  int ret = ioctl(fd, FIONREAD, &available);
  if (ret == -1) {
    logger("available: (%d) %s.\n", errno, strerror(errno));
    return ret; /* ... */
  }
  return available;
}


int bns_utils_is_ipv4(const char* ip) {    
  struct in_addr i_addr;
  int ret = 0;
  ret = inet_pton(AF_INET, ip, &i_addr);
  if(ret == 1) return 1;
  else if(ret == 0) return 0;
  return -1;
}
 
int bns_utils_hostname_to_ip(const char *hostname, char* ip) {
  struct hostent *he;
  struct in_addr **addr_list;
  int i;
  if((he = gethostbyname(hostname)) == NULL) {
    logger("gethostbyname: (%d) %s.\n", errno, strerror(errno));
    return -1;
  }
  addr_list = (struct in_addr **) he->h_addr_list;
  for(i = 0; addr_list[i] != NULL; i++) {
    strcpy(ip , inet_ntoa(*addr_list[i]) );
    return 0;
  }
  return -1;
}

void bns_utils_print_hex(FILE* std, char* buffer, int len) {
  int i = 0, max = PRINT_HEX_MAX_PER_LINES, loop = len;
  __u8 *p = (__u8 *)buffer;
  char line [max + 3]; /* spaces + \0 */
  memset(line, 0, sizeof(line));
  while(loop--) {
    __u8 c = *(p++);
    fprintf(std, "%02x ", c);
    /* uniquement les espaces et les char visibles */
    if(c >= 0x20 && c <= 0x7e) line[i] = c;
    /* sinon on masque avec un '.' */
    else line[i] = 0x2e; /* . */
    /* on passe a la ligne suivante */
    if(i == max) {
      fprintf(std, "  %s\n", line);
      /* re init */
      i = 0;
      memset(line, 0, sizeof(line));
    }
    /* sinon suivant */
    else i++;
    /* espace a la moitie */
    if(i == max / 2) {
      fprintf(std, " ");
      line[i++] = 0x20;
    }
  }
  /* Cette etape permet d'aligner 'line'*/
  if(i != 0 && (i < max || i <= len)) {
    while(i++ <= max) fprintf(std, "   "); /* comble avec 3 espaces ex: "00 " */
    fprintf(std, "  %s\n", line);
  }
  fprintf(std, "\n");
}


const char* bns_utils_long_to_ip(unsigned int v)  {
  struct in_addr x;
  x.s_addr = htonl(v);
  return inet_ntoa(x);
}

unsigned int bns_utils_ip_to_long(const char* s) {
  struct sockaddr_in n;
  inet_aton(s,&n.sin_addr);
  return ntohl(n.sin_addr.s_addr);
}
