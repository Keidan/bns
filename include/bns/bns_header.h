/**
 *******************************************************************************
 * @file bns_header.h
 * @author Keidan
 * @date 19/05/2013
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

#ifndef __BNS_HEADER_H__
  #define __BNS_HEADER_H__


  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <linux/udp.h>
  #include <linux/tcp.h>
  #include <arpa/inet.h>
  #include <limits.h>
  #include <net/if.h>

  #define BNS_HEADER_SET_NSET(cond) (cond ? "Set" : "Not Set")

  typedef enum { BNS_PACKET_CONVERT_NONE, BNS_PACKET_CONVERT_HOST2NET, BNS_PACKET_CONVERT_NET2HOST} bns_packet_convert_et;

  struct bns_filter_s {
    __u32 ip;
    __u32 port;
    char iface[IF_NAMESIZE];
  };


/* utilisee pour le decodage de la reponse/requete ARP */
  struct arphdr2 {
    unsigned char sha[ETH_ALEN];
    unsigned char sip[4];
    unsigned char tha[ETH_ALEN];
    unsigned char tip[4];
  };

  struct arphdrs{
      struct arphdr *arp1;
      struct arphdr2 *arp2;
  };

  struct bns_network_s {
      struct ethhdr *eth;
      struct arphdrs *arp;
      struct iphdr  *ipv4;
      struct udphdr *udp;
      struct tcphdr *tcp;
  };

  /**
   * @fn int bns_header_decode_buffer(const char* buffer, __u32 length, struct bns_network_s *net, bns_packet_convert_et convert)
   * @brief Decodage des paquets en fonction du buffer.
   * @param buffer Buffer de donnee.
   * @param length Taille du buffer.
   * @param net Liste des entetes.
   * @param convert Conversion de certains champs des differentes entetes.
   * @return -1 sur erreur sinon la taill de la payload (peut etre 0).
   */
  int bns_header_decode_buffer(const char* buffer, __u32 length, struct bns_network_s *net, bns_packet_convert_et convert);

  /**
   * @fn void bns_header_release_buffer(struct bns_network_s *net)
   * @brief Liberation des ressources allouee par decode_network_buffer.
   * @param net Liste des entetes a liberer.
   */
  void bns_header_release_buffer(struct bns_network_s *net);

  /**
   * @fn _Bool bns_header_match_from_simple_filter(struct bns_network_s *net, struct bns_filter_s filter)
   * @brief Test si le regle matche ou non.
   * @param net entetes.
   * @param filter Filtre a tester.
   * @return Retourne 1 si match.
   */
  _Bool bns_header_match_from_simple_filter(struct bns_network_s *net, struct bns_filter_s filter);

  /**
   * @fn void bns_header_print_headers(const char* buffer, __u32 length, struct bns_network_s net)
   * @brief Affichage des entetes.
   * @param buffer Buffer de donnee.
   * @param length Taille du buffer.
   * @param net Entetes.
   */
  void bns_header_print_headers(const char* buffer, __u32 length, struct bns_network_s net);

  /**
   * @fn void bns_header_print_eth(struct ethhdr *eth)
   * @brief Affichage de l'entete Ethernet.
   * @param eth Entete Ethernet.
   */
  void bns_header_print_eth(struct ethhdr *eth);

  /**
   * @fn void bns_header_print_arp(struct arphdrs *arpp)
   * @brief Affichage de l'entete ARP.
   * @param arpp Entete ARP.
   */
  void bns_header_print_arp(struct arphdrs *arpp);

  /**
   * @fn void bns_header_print_ip(struct iphdr* ipv4)
   * @brief Affichage de l'entete IPv4/IPv6.
   * @param ipv4 Entete IPv4.
   */
  void bns_header_print_ip(struct iphdr* ipv4);

  /**
   * @fn void bns_header_print_upd(struct udphdr *udp)
   * @brief Affichage de l'entete UDP.
   * @param udp Entete UDP.
   */
  void bns_header_print_upd(struct udphdr *udp);

  /**
   * @fn void bns_header_print_tcp(struct tcphdr *tcp)
   * @brief Affichage de l'entete TCP.
   * @param tcp Entet TCP.
   */
  void bns_header_print_tcp(struct tcphdr *tcp);

#endif /* __BNS_HEADER_H__ */
