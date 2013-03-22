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


  _Bool match_from_simple_filter(char* buffer, long host, int port);


  /**
   * Affichage de l'entete Ethernet.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  __be16 bns_header_print_eth(char* buffer, __u32 length, __u32 *offset);


  /**
   * Affichage de l'entete ARP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  void bns_header_print_arp(char* buffer, __u32 length, __u32 *offset);

  /**
   * Affichage de l'entete IPv4/IPv6.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  __u8 bns_header_print_ip(char* buffer, __u32 length, __u32 *offset);

  /**
   * Affichage de l'entete UDP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  void bns_header_print_upd(char* buffer, __u32 length, __u32 *offset);

  /**
   * Affichage de l'entete TCP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  void bns_header_print_tcp(char* buffer, __u32 length, __u32 *offset);

#endif /* __BNS_PACKET_H__ */
