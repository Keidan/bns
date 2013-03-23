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
  #include "list.h"

  /* nombre max de chars dans une ligne */
  #define PRINT_HEX_MAX_PER_LINES 16


  struct iface_s {
    struct list_head list;              /*!< Liste d'interfaces. */
    char             name[IF_NAMESIZE]; /*!< Nom de l'interface. */
    int              index;             /*!< Index de la carte. */
    int              fd;                /*!< FD du socket utilise pour les io's/bind/select. */
  };


  /**
   * Test si l'adresse ip est valide.
   * @param ip[in] Adresse IP.
   * @return -1 si erreur, 0 si non match, 1 si match.
   */
  int bns_utils_is_ipv4(const char* ip);

  /**
   * Recuperation de l'adresse ip en fonction du nom de host.
   * @param hostname[in] Nom du host.
   * @param name[out] Adresse IP.
   * @return -1 si erreur sinon 0.
   */
  int bns_utils_hostname_to_ip(const char *hostname, char* ip);

  /**
   * Effectue un test pour savoir si le device est up
   * @param fd[in] FD pour l'ioctl.
   * @param name[in] Nom du device.
   * @return Vrai si up.
   */
  _Bool bns_utils_device_is_up(int fd, char name[IF_NAMESIZE]);

  /**
   * Recuperation du nombre de donnees a lire.
   * @param fd[in] fd a tester.
   * @return Nb donnees a lire. 
   */
  __u32 bns_utils_datas_available(int fd);

  /**
   * Affichage d'un packet (wireshark like).
   * @param buffer[in] Packet.
   * @param len[in] Taille du packet.
   */
  void bns_utils_print_hex(FILE* std, char* buffer, int len);

  /**
   * Liste toutes les interfaces et les ajoutent a la liste (IMPORTANT: apres appel de cette methode des sockets sont ouverts).
   * @param ifaces[in,out] Liste des interfaces (la taille vaut 1 ou 0 si iname n'est pas vide).
   * @param maxfd[in,out] Utilise pour le select.
   * @param rset[in,out] fd_set utilise pour le select.
   * @param iname[in] Demande la configuration d'une interface.
   * @return -1 en cas d'erreur sinon 0.
   */
  int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset, const char iname[IF_NAMESIZE]);

  /**
   * Ajout d'un interface a la liste.
   * @param list[in,out] Liste d'interfaces.
   * @param name[in] Nom de l'interface.
   * @param index[in] Index de l'interface.
   * @param fd[in] FD du socket utilise.
   */
  void bns_utils_add_iface(struct iface_s* list, char name[IF_NAMESIZE], int index, int fd);

  /**
   * Suppression des elements de la liste.
   * @param ifaces[in,out] Liste a vider.
   */
  void bns_utils_clear_ifaces(struct iface_s* ifaces);

  /**
   * Transforme un long en adresse IP.
   * @param v[in] long a transformer.
   * @return L'adresse IP.
   */
  const char* bns_utils_long_to_ip(unsigned int v);

  /**
   * Transforme une adresse IP en long.
   * @param s[in] IP a transformer.
   * @return Long.
   */
  unsigned int bns_utils_ip_to_long(const char* s);

#endif /* __BNS_UTILS_H__ */
