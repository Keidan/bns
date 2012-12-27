#ifndef __BNS_UTILS_H__
  #define __BNS_UTILS_H__


  #include <net/if.h>
  #include <linux/if_ether.h>
  #include <sys/select.h>
  #include "list.h"


  struct iface_s {
    struct list_head list;              /*!< Liste d'interfaces. */
    char             name[IF_NAMESIZE]; /*!< Nom de l'interface. */
    int              index;             /*!< Index de la carte. */
    int              fd;                /*!< FD du socket utilise pour les io's/bind/select. */
  };

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
  void bns_utils_print_hex(char* buffer, int len);

  /**
   * Liste toutes les interfaces et les ajoutent a la liste (IMPORTANT: apres appel de cette methode des sockets sont ouverts).
   * @param ifaces[in,out] Liste des interfaces.
   * @param maxfd[in,out] Utilise pour le select.
   * @param rset[in,out] fd_set utilise pour le select.
   * @return -1 en cas d'erreur sinon 0.
   */
  int bns_utils_prepare_ifaces(struct iface_s *ifaces, int *maxfd, fd_set *rset);

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

#endif /* __BNS_UTILS_H__ */
