/**
 *******************************************************************************
 * @file bns_utils.h
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
#ifndef __BNS_UTILS_H__
  #define __BNS_UTILS_H__


  #include <net/if.h>
  #include <linux/if_ether.h>
  #include <sys/select.h>
  #include <list.h>

  /* nombre max de chars dans une ligne */
  #define PRINT_HEX_MAX_PER_LINES 16


  struct iface_s {
    struct list_head list;              /**< Liste d'interfaces. */
    char             name[IF_NAMESIZE]; /**< Nom de l'interface. */
    int              index;             /**< Index de la carte. */
    int              fd;                /**< FD du socket utilise pour les io's/bind/select. */
    int              family;            /**< Famille de l'interface. */
  };

  /**
   * @typedef pcap_hdr_t
   * @brief Global header
   * Source: http://wiki.wireshark.org/Development/LibpcapFileFormat
   */
  typedef struct pcap_hdr_s {
      __u32 magic_number;  /**< magic number */
      __u16 version_major; /**< major version number */
      __u16 version_minor; /**< minor version number */
      __s32 thiszone;      /**< GMT to local correction */
      __u32 sigfigs;       /**< accuracy of timestamps */
      __u32 snaplen;       /**< max length of captured packets, in octets */
      __u32 network;       /**< data link type */
  } pcap_hdr_t;

  /**
   * @typedef pcaprec_hdr_t
   * @brief Packet header
   * Source: http://wiki.wireshark.org/Development/LibpcapFileFormat
   */
  typedef struct pcaprec_hdr_s {
      __u32 ts_sec;        /**< timestamp seconds */
      __u32 ts_usec;       /**< timestamp microseconds */
      __u32 incl_len;      /**< number of octets of packet saved in file */
      __u32 orig_len;      /**< actual length of packet */
  } pcaprec_hdr_t;

  /**
   * @def BNS_UTILS_MAX_SSIZE
   * @brief Taille max du string utilise avec la fonction "bns_utils_size_to_string"
   * @see bns_utils_size_to_string
   */
  #define BNS_UTILS_MAX_SSIZE 15

  /**
   * @fn int bns_utils_is_ipv4(const char* ip)
   * @brief Test si l'adresse ip est valide.
   * @param ip Adresse IP.
   * @return -1 si erreur, 0 si non match, 1 si match.
   */
  int bns_utils_is_ipv4(const char* ip);

  /**
   * @fn int bns_utils_hostname_to_ip(const char *hostname, char* ip)
   * @brief Recuperation de l'adresse ip en fonction du nom de host.
   * @param hostname Nom du host.
   * @param ip Adresse IP.
   * @return -1 si erreur sinon 0.
   */
  int bns_utils_hostname_to_ip(const char *hostname, char* ip);

  /**
   * @fn _Bool bns_utils_device_is_up(int fd, char name[IF_NAMESIZE])
   * @brief Effectue un test pour savoir si le device est up
   * @param fd FD pour l'ioctl.
   * @param name Nom du device.
   * @return Vrai si up.
   */
  _Bool bns_utils_device_is_up(int fd, char name[IF_NAMESIZE]);

  /**
   * @fn __u32 bns_utils_datas_available(int fd)
   * @brief Recuperation du nombre de donnees a lire.
   * @param fd fd a tester.
   * @return Nb donnees a lire. 
   */
  __u32 bns_utils_datas_available(int fd);

  /**
   * @fn void bns_utils_print_hex(FILE* std, char* buffer, int len, _Bool print_raw)
   * @brief Affichage d'un packet (wireshark like).
   * @param std Flux de sortie.
   * @param buffer Packet.
   * @param len Taille du packet.
   * @param print_raw Affichage en raw mode.
   */
  void bns_utils_print_hex(FILE* std, char* buffer, int len, _Bool print_raw);

  /**
   * @fn int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset, const char iname[IF_NAMESIZE])
   * @brief Liste toutes les interfaces et les ajoutent a la liste (IMPORTANT: apres appel de cette methode des sockets sont ouverts).
   * @param ifaces Liste des interfaces (la taille vaut 1 ou 0 si iname n'est pas vide).
   * @param maxfd Utilise pour le select.
   * @param rset fd_set utilise pour le select.
   * @param iname Demande la configuration d'une interface.
   * @return -1 en cas d'erreur sinon 0.
   */
  int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset, const char iname[IF_NAMESIZE]);

  /**
   * @fn void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd, int family)
   * @brief Ajout d'un interface a la liste.
   * @param list Liste d'interfaces.
   * @param name Nom de l'interface.
   * @param index Index de l'interface.
   * @param fd FD du socket utilise.
   * @param family Famille de l'interface.
   */
  void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd, int family);

  /**
   * @fn void bns_utils_clear_ifaces(struct iface_s* ifaces)
   * @brief Suppression des elements de la liste.
   * @param ifaces Liste a vider.
   */
  void bns_utils_clear_ifaces(struct iface_s* ifaces);

  /**
   * @fn const char* bns_utils_long_to_ip(unsigned int v)
   * @brief Transforme un long en adresse IP.
   * @param v long a transformer.
   * @return L'adresse IP.
   */
  const char* bns_utils_long_to_ip(unsigned int v);

  /**
   * @fn unsigned int bns_utils_ip_to_long(const char* s)
   * @brief Transforme une adresse IP en long.
   * @param s IP a transformer.
   * @return Long.
   */
  unsigned int bns_utils_ip_to_long(const char* s);

  /**
   * @fn long bns_utils_fsize(FILE* file)
   * @brief Recupere la taille du fichier.
   * @param file Taille.
   * @return Long.
   */
  long bns_utils_fsize(FILE* file);

  /**
   * @fn pcap_hdr_t bns_utils_pcap_global_hdr(void)
   * @brief Construction du main header du fichier.
   * @return pcap_hdr_t
   */
  pcap_hdr_t bns_utils_pcap_global_hdr(void);

  /**
   * @fn pcap_hdr_t bns_utils_pcap_packet_hdr(__u32 incl_len, __u32 ori_len)
   * @brief Construction du header par paquets.
   * @return pcaprec_hdr_t.
   */
  pcaprec_hdr_t bns_utils_pcap_packet_hdr(__u32 incl_len, __u32 ori_len);


  /**
   * @fn void bns_utils_size_to_string(long size, char ssize[BNS_UTILS_MAX_SSIZE])
   * @brief Convertie une taille en string avec l'unite.
   * @param size Taille.
   * @param ssize Output
   */
  void bns_utils_size_to_string(long size, char ssize[BNS_UTILS_MAX_SSIZE]);

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
  void bns_utils_write_pcap_packet(FILE* output, const char* buffer, size_t a_length, size_t r_length, _Bool *first);
#endif /* __BNS_UTILS_H__ */
