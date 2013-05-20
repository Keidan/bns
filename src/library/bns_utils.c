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
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <bns/bns_utils.h>
#include <bns/bns_logger.h>

/**
 * @def BNS_PCAP_VERSION_MAJOR
 * @brief Version major du fichier pcap.
 * @see netdump_utils_pcap_global_hdr
 */
#define BNS_PCAP_VERSION_MAJOR     2
/**
 * @def BNS_PCAP_VERSION_MINOR
 * @brief Version minor du fichier pcap.
 * @see netdump_utils_pcap_global_hdr
 */
#define BNS_PCAP_VERSION_MINOR     4
/**
 * @def BNS_PCAP_MAGIC_NATIVE
 * @brief Magic du fichier pcap.
 * @see netdump_utils_pcap_global_hdr
 */
#define BNS_PCAP_MAGIC_NATIVE      0xa1b2c3d4
/**
 * @def BNS_PCAP_LINKTYPE_ETHERNET
 * @brief Type de capture.
 * @see netdump_utils_pcap_global_hdr
 */
#define BNS_PCAP_LINKTYPE_ETHERNET 1
/**
 * @def BNS_PCAP_SNAPLEN
 * @brief Taille de la capture.
 * @see netdump_utils_pcap_global_hdr
 */
#define BNS_PCAP_SNAPLEN           65535

/**
 * @def VALUE_1KO
 * @brief Valeur 1 Ko en octets
 * @see bns_utils_size_to_string
 */
#define VALUE_1KO   0x400
/**
 * @def VALUE_1MO
 * @brief Valeur 1 Mo en octets
 * @see bns_utils_size_to_string
 */
#define VALUE_1MO   0x100000
/**
 * @def VALUE_1GO
 * @brief Valeur 1 Go en octets
 * @see bns_utils_size_to_string
 */
#define VALUE_1GO   0x40000000



/**
 * Liste toutes les interfaces et les ajoutent a la liste (IMPORTANT: apres appel de cette methode des sockets sont ouverts).
 * @param ifaces Liste des interfaces (la taille vaut 1 ou 0 si iname n'est pas vide).
 * @param maxfd Utilise pour le select.
 * @param rset fd_set utilise pour le select.
 * @param iname Demande la configuration d'une interface.
 * @return -1 en cas d'erreur sinon 0.
 */
int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset, const char iname[IF_NAMESIZE]) {
  int i;
  struct ifreq ifr;
  struct sockaddr_ll sll;
  char *name;
  int fd, family;

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
    /* Recuperation du nom qui sera utilise plus bas. */
    name = nameindex[i++].if_name;
    if(iname[0] && strncmp(iname, name, IF_NAMESIZE) != 0) continue;

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

    /* recuperation de la famille de l'interface. */
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
      family = ifr.ifr_hwaddr.sa_family;
    } else
      family = -1;

    /* Bind sur l'interface*/
    if((bind(fd, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
      if_freenameindex(nameindex);
      close(fd);
      logger("bind failed: (%d) %s.\n", errno, strerror(errno));
      return -1;
    }

    /* ajout de l'interface */
    bns_utils_add_iface(ifaces, name, ifr.ifr_ifindex, fd, family);
  }

  /* Liberation des ressources */
  if_freenameindex(nameindex);
  return 0;
}

/**
 * @fn void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd, int family)
 * @brief Ajout d'un interface a la liste.
 * @param list Liste d'interfaces.
 * @param name Nom de l'interface.
 * @param index Index de l'interface.
 * @param fd FD du socket utilise.
 * @param family Famille de l'interface.
 */
void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd, int family) {
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
  node->family = family;
  list_add_tail(&(node->list), &(list->list));
}

/**
 * @fn void bns_utils_clear_ifaces(struct iface_s* ifaces)
 * @brief Suppression des elements de la liste.
 * @param ifaces Liste a vider.
 */
void bns_utils_clear_ifaces(struct iface_s* ifaces) {
  struct iface_s* iter;
  while(!list_empty(&ifaces->list) ) {
    iter = list_entry(ifaces->list.next, struct iface_s, list);
    close(iter->fd); /* close du socket */
    list_del(&iter->list); /*delete de l'item dans la liste */
    free(iter);
  }
}

/**
 * @fn _Bool bns_utils_device_is_up(int fd, char name[IF_NAMESIZE])
 * @brief Effectue un test pour savoir si le device est up
 * @param fd FD pour l'ioctl.
 * @param name Nom du device.
 * @return Vrai si up.
 */
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

/**
 * @fn __u32 bns_utils_datas_available(int fd)
 * @brief Recuperation du nombre de donnees a lire.
 * @param fd fd a tester.
 * @return Nb donnees a lire. 
 */
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

/**
 * @fn int bns_utils_is_ipv4(const char* ip)
 * @brief Test si l'adresse ip est valide.
 * @param ip Adresse IP.
 * @return -1 si erreur, 0 si non match, 1 si match.
 */
int bns_utils_is_ipv4(const char* ip) {    
  struct in_addr i_addr;
  int ret = 0;
  ret = inet_pton(AF_INET, ip, &i_addr);
  if(ret == 1) return 1;
  else if(ret == 0) return 0;
  return -1;
}
 
/**
 * @fn int bns_utils_hostname_to_ip(const char *hostname, char* ip)
 * @brief Recuperation de l'adresse ip en fonction du nom de host.
 * @param hostname Nom du host.
 * @param ip Adresse IP.
 * @return -1 si erreur sinon 0.
 */
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

/**
 * @fn void bns_utils_print_hex(FILE* std, char* buffer, int len, _Bool print_raw)
 * @brief Affichage d'un packet (wireshark like).
 * @param std Flux de sortie.
 * @param buffer Packet.
 * @param len Taille du packet.
 * @param print_raw Affichage en raw mode.
 */
void bns_utils_print_hex(FILE* std, char* buffer, int len, _Bool print_raw) {
  int i = 0, max = PRINT_HEX_MAX_PER_LINES, loop = len;
  __u8 *p = (__u8 *)buffer;
  char line [max + 3]; /* spaces + \0 */
  memset(line, 0, sizeof(line));
  while(loop--) {
    __u8 c = *(p++);
    if(!print_raw) {
      fprintf(std, "%02x ", c);
      /* uniquement les espaces et les char visibles */
      if(c >= 0x20 && c <= 0x7e) line[i] = c;
      /* sinon on masque avec un '.' */
      else line[i] = 0x2e; /* . */
    } else fprintf(std, "%02x", c);
    /* on passe a la ligne suivante */
    if(i == max) {
      if(!print_raw)
	fprintf(std, "  %s\n", line);
      else fprintf(std, "\n");
      /* re init */
      i = 0;
      memset(line, 0, sizeof(line));
    }
    /* sinon suivant */
    else i++;
    /* espace a la moitie */
    if(i == max / 2 && !print_raw) {
      fprintf(std, " ");
      line[i++] = 0x20;
    }
  }
  /* Cette etape permet d'aligner 'line'*/
  if(i != 0 && (i < max || i <= len) && !print_raw) {
    while(i++ <= max) fprintf(std, "   "); /* comble avec 3 espaces ex: "00 " */
    fprintf(std, "  %s\n", line);
  }
  fprintf(std, "\n");
}

/**
 * @fn unsigned int bns_utils_ip_to_long(const char* s)
 * @brief Transforme une adresse IP en long.
 * @param s IP a transformer.
 * @return Long.
 */
const char* bns_utils_long_to_ip(unsigned int v)  {
  struct in_addr x;
  x.s_addr = htonl(v);
  return inet_ntoa(x);
}

/**
 * @fn unsigned int bns_utils_ip_to_long(const char* s)
 * @brief Transforme une adresse IP en long.
 * @param s IP a transformer.
 * @return Long.
 */
unsigned int bns_utils_ip_to_long(const char* s) {
  struct sockaddr_in n;
  inet_aton(s,&n.sin_addr);
  return ntohl(n.sin_addr.s_addr);
}

/**
 * @fn void bns_utils_size_to_string(long size, char ssize[BNS_UTILS_MAX_SSIZE])
 * @brief Convertie une taille en string avec l'unite.
 * @param size Taille.
 * @param ssize Output
 */
void bns_utils_size_to_string(long size, char ssize[BNS_UTILS_MAX_SSIZE]) {
  memset(ssize, 0, BNS_UTILS_MAX_SSIZE);
  float s = size;
  if(size < VALUE_1KO)
    snprintf(ssize, BNS_UTILS_MAX_SSIZE, "%ld octet%s", size, size > 1 ? "s" : "");
  else if(size < VALUE_1MO)
    snprintf(ssize, BNS_UTILS_MAX_SSIZE, "%ld Ko", (long)ceil(s/VALUE_1KO));
  else if(size < VALUE_1GO)
    snprintf(ssize, BNS_UTILS_MAX_SSIZE, "%ld Mo", (long)ceil(s/VALUE_1MO));
  else
    snprintf(ssize, BNS_UTILS_MAX_SSIZE, "%ld Go",  (long)ceil(s/VALUE_1GO));
}

/**
 * @fn long bns_utils_fsize(FILE* file)
 * @brief Recupere la taille du fichier.
 * @param file Taille.
 * @return Long.
 */
long bns_utils_fsize(FILE* file) {
  long size = 0L, old = 0L;
  if (file) {
    old = ftell(file);
    fseek(file, 0L, SEEK_END);
    size = ftell(file);
    fseek(file, old, SEEK_SET);
  }
  return size;
}

/**
 * @fn pcap_hdr_t bns_utils_pcap_global_hdr(void)
 * @brief Construction du main header du fichier.
 * @return pcap_hdr_t
 */
pcap_hdr_t bns_utils_pcap_global_hdr(void) {
  pcap_hdr_t hdr;
  memset(&hdr, 0, sizeof(pcap_hdr_t));
  hdr.magic_number = BNS_PCAP_MAGIC_NATIVE;
  hdr.version_major = BNS_PCAP_VERSION_MAJOR;
  hdr.version_minor = BNS_PCAP_VERSION_MINOR;  
  tzset(); /* force le set de la variable timezone */
  hdr.thiszone = timezone;
  hdr.sigfigs = 0;
  hdr.snaplen = BNS_PCAP_SNAPLEN;
  hdr.network = BNS_PCAP_LINKTYPE_ETHERNET;
  return hdr;
}

/**
 * @fn pcap_hdr_t bns_utils_pcap_packet_hdr(__u32 incl_len, __u32 ori_len)
 * @brief Construction du header par paquets.
 * @return pcaprec_hdr_t.
 */
pcaprec_hdr_t bns_utils_pcap_packet_hdr(__u32 incl_len, __u32 ori_len) {
  pcaprec_hdr_t hdr;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  hdr.ts_sec = tv.tv_sec;
  hdr.ts_usec = tv.tv_usec;
  hdr.incl_len = incl_len;
  hdr.orig_len = ori_len;
  return hdr;
}

/**
 * @fn void bns_utils_write_pcap_packet(const FILE* output, const char* buffer, size_t a_length, size_t r_length, _Bool *first)
 * @brief Ecriture des headers pcap et du buffer dans le fichier specifie.
 * Source: http://wiki.wireshark.org/Development/LibpcapFileFormat
 * Packet structure:
 * -----------------------------------------------------------------------------------------------------------------
 * | Global Header | Packet Header | Packet Data | Packet Header | Packet Data | Packet Header | Packet Data | ... |
 * -----------------------------------------------------------------------------------------------------------------
 * @param output Fichier de sortie.
 * @param buffer Buffer d'entree.
 * @param a_length Taille demandee a l'appel de recvfrom.
 * @param r_length Taille recuperee apres l'appel de recvfrom.
 * @param first Cette variable permet l'ecriture du header global, en debut de fichier uniquement.
 */
void bns_utils_write_pcap_packet(FILE* output, const char* buffer, size_t a_length, size_t r_length, _Bool *first) {
  if(*first) {
    pcap_hdr_t ghdr = bns_utils_pcap_global_hdr();
    fwrite(&ghdr, 1, sizeof(pcap_hdr_t), output);
    *first = 0;
  }
  pcaprec_hdr_t phdr = bns_utils_pcap_packet_hdr(r_length, a_length);
  fwrite(&phdr, 1, sizeof(pcaprec_hdr_t), output);
  fwrite(buffer, 1, r_length, output);
  fflush(output);
}
