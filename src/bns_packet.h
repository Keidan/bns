/**
 *******************************************************************************
 * @file bns_packet.h
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
#ifndef __BNS_PACKET_H__
  #define __BNS_PACKET_H__


  #include <netinet/if_ether.h>
  #include <netinet/ip.h>
  #include <linux/udp.h>
  #include <linux/tcp.h>
  #include <arpa/inet.h>
  #include <limits.h>


/* utilisee pour le decodage de la reponse/requete ARP */
  struct arphdr_part2_s {
    unsigned char sha[ETH_ALEN];
    unsigned char sip[4];
    unsigned char tha[ETH_ALEN];
    unsigned char tip[4];
  };

  struct arp_parts_s{
      struct arphdr *arp1;
      struct arphdr_part2_s *arp2;
  };

  struct bns_network_s {
      struct ethhdr *eth;
      struct arp_parts_s *arp;
      struct iphdr  *ipv4;
      struct udphdr *udp;
      struct tcphdr *tcp;
  };

  /**
   * Decodage des paquets en fonction du buffer.
   * @param buffer[in] Buffer de donnee.
   * @param length[in] Tail du buffer.
   * @param net[ou] Liste des entetes.
   * @return -1 sur erreur sinon la taill de la payload (peut etre 0).
   */
  int decode_network_buffer(const char* buffer, __u32 length, struct bns_network_s *net);

  /**
   * Liberation des ressources allouee par decode_network_buffer.
   * @param net[in,out] Liste des entetes a liberer.
   */
  void release_network_buffer(struct bns_network_s *net);

  /**
   * Test si le regle matche ou non.
   * @param net[in] entetes.
   * @param host[in] Host a tester (ou null, vide).
   * @param port[in] Port a test (ou 0)
   * @return Retourne 1 si match.
   */
  _Bool match_from_simple_filter(struct bns_network_s *net, long host, int port);


  /**
   * Affichage de l'entete Ethernet.
   * @param eth[in] Entete Ethernet.
   */
  void bns_header_print_eth(struct ethhdr *eth);


  /**
   * Affichage de l'entete ARP.
   * @param arp[in] Entete ARP.
   * @param p2[in] Entete ARP partie 2.
   */
  void bns_header_print_arp(struct arp_parts_s *arp);

  /**
   * Affichage de l'entete IPv4/IPv6.
   * @param ipv4[in] Entete IPv4.
   */
  void bns_header_print_ip(struct iphdr* ipv4);

  /**
   * Affichage de l'entete UDP.
   * @param udp[in] Entete UDP.
   */
  void bns_header_print_upd(struct udphdr *udp);

  /**
   * Affichage de l'entete TCP.
   * @param tcp[in] Entet TCP.
   */
  void bns_header_print_tcp(struct tcphdr *tcp);

#endif /* __BNS_PACKET_H__ */
