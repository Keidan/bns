/**
 *******************************************************************************
 * @file bns_header.h
 * @author Keidan
 * @date 03/01/2013
 * @par Project
 * bns
 *
 * @par Copyright
 * Copyright 2011 Keidan, all right reserved
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
//#include <netinet/ip6.h>
  #include <linux/udp.h>
  #include <linux/tcp.h>
  #include <arpa/inet.h>

  #define SET_NSET(cond) (!!(cond)), (cond ? "Set" : "Not Set")

  /* utilisee pour le decodage de la reponse/requete ARP */
  struct arphdr_part2 {
    unsigned char sha[ETH_ALEN];
    unsigned char sip[4];
    unsigned char tha[ETH_ALEN];
    unsigned char tip[4];
  };

  /** 
   * Pour eviter les pb de support et surtout de compilation la structure est 
   * copiée du header linux/ipv6.h
   */
  struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8               priority:4,
  version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  
    __u8               version:4,
  priority:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8               flow_lbl[3];
  
    __be16             payload_len;
    __u8               nexthdr;
    __u8               hop_limit;
    struct  in6_addr   saddr;
    struct  in6_addr   daddr;
  };


  /**
   * Affichage de l'entete Ethernet.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  static inline __be16 bns_header_print_eth(char* buffer, __u32 length, __u32 *offset) {
    struct ethhdr *eth = (struct ethhdr *)buffer;
    *offset += sizeof(struct ethhdr);
    printf("Ethernet:\n");
    __be16 proto = ntohs(eth->h_proto);
    printf("\tSource: %02x:%02x:%02x:%02x:%02x:%02x\n\tDestination: %02x:%02x:%02x:%02x:%02x:%02x\n\tType:0x%04x\n",
	   eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
	   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
	   proto);
    return proto;
  }


  /**
   * Affichage de l'entete ARP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  static inline void bns_header_print_arp(char* buffer, __u32 length, __u32 *offset) {
    struct arphdr *arp = (struct arphdr*)(buffer + *offset);
    *offset += sizeof(struct arphdr);
    arp->ar_op = ntohs(arp->ar_op);
    arp->ar_hrd = ntohs(arp->ar_hrd);
    __be16 op = ntohs(arp->ar_op);
    __be16 hrd = ntohs(arp->ar_hrd);
    printf("Adress Resolution Protocol:\n");
    printf("\tHardware type: 0x%04x\n", hrd);
    printf("\tProtocol type: 0x%04x\n", arp->ar_pro);
    printf("\tHardware size: %x\n", arp->ar_hln);
    printf("\tProtocol size: %x\n", arp->ar_pln);
    printf("\tOpcode: %s (%x)\n", (op == 2 ? "reply" : (op == 1 ? "request" : "unknown")) , op);

    /* 
     * Uniquement pour les requetes reponse et si la taille du protocol vaut 4 (IPv4).
     * Je n'ai rien sous la main pour tester l'IPv6, je passe mon tour pour le moment...
     */
    if((op == 1 || op == 2) && arp->ar_pln == 4) {
      struct arphdr_part2 *p2 = (struct arphdr_part2*)(buffer + *offset);
      *offset += sizeof(struct arphdr_part2);
      printf("\tSender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	     p2->sha[0], p2->sha[1], p2->sha[2], p2->sha[3], p2->sha[4], p2->sha[5]);
      printf("\tSender IP address: %d.%d.%d.%d\n",
	     p2->sip[0], p2->sip[1], p2->sip[2], p2->sip[3]);
      printf("\tTarget MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	     p2->tha[0], p2->tha[1], p2->tha[2], p2->tha[3], p2->tha[4], p2->tha[5]);
      printf("\tTarget IP address: %d.%d.%d.%d\n",
	     p2->tip[0], p2->tip[1], p2->tip[2], p2->tip[3]);
    }
    if((length - *offset)) {
      printf("\tTrailer: Not supported (%d bytes)\n", (length - *offset));
      (*offset) += (length - *offset);
    }
  }


  /**
   * Affichage de l'entete IPv4/IPv6.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  static inline __u8 bns_header_print_ip(char* buffer, __u32 length, __u32 *offset) {
    struct iphdr *ip = (struct iphdr*)(buffer + *offset);
    if(ip->version == 4) {
      *offset += sizeof(struct iphdr);
      /* Affichage de l'entete IPv4 */
      char src [INET_ADDRSTRLEN], dst [INET_ADDRSTRLEN];
      memset(dst, 0, sizeof(dst));
      memset(src, 0, sizeof(src));
      inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
      __u16 tot_len = ntohs(ip->tot_len);
      __u8 tos = ntohs(ip->tos); /* pas certains */
      __u32 ihl = /*ntohl(*/ip->ihl/*)*/;
      __u16 frag_off = ntohs(ip->frag_off);

      printf("Internet Protocol Version %d:\n", ip->version);
      printf("\tVersion: %d\n\tHeader length: %d bytes\n", ip->version, ihl + sizeof(struct iphdr));
      printf("\tDifferentiated Services Field:\n");
      printf("\t\tTotal Length: %d\n\t\tIdentification: 0x%04x (%d)\n", tot_len, tos, tos);
      printf("\tFlags: 0x%02x\n", ip->id);
      printf("\t\t%d... Reserved bit: %s\n",  SET_NSET(ip->id&IP_RF));
      printf("\t\t.%d.. Don't fragment: %s\n", SET_NSET(ip->id&IP_DF));
      printf("\t\t..%d. More fragments: %s\n", SET_NSET(ip->id&IP_MF));
      printf("\tFragment offset: %d\n", frag_off);
      printf("\tTime to live: %d\n\tProtocol: %d\n\tHeader checksum: 0x%04x\n", ip->ttl, ip->protocol, ip->check);
      printf("\tSource: %s\n\tDestination: %s\n", src, dst);
      return ip->protocol;
    } else { /* ip v6 */
      /* Je n'ai rien sous la main pour tester l'IPv6 */
/*       struct ipv6hdr *ip6 = (struct ipv6hdr*)(buffer + *offset); */
/*       *offset += sizeof(struct ipv6hdr); */
/*       /\* Affichage de l'entete IPv6 *\/ */
/*       char dst [INET6_ADDRSTRLEN], src [INET6_ADDRSTRLEN]; */
/*       memset(dst, 0, sizeof(dst)); */
/*       memset(src, 0, sizeof(src)); */
/*       inet_ntop(AF_INET6, &ip6->saddr, src, INET6_ADDRSTRLEN); */
/*       inet_ntop(AF_INET6, &ip6->daddr, dst, INET6_ADDRSTRLEN); */
/*       printf("Internet Protocol Version 6:\n"); */
/*       printf("\tVersion: %d\n\tPriority: %d\n\tFlowlabel:0x%02x%02x%02x\n", */
/*       	     ip6->version, ip6->priority, */
/*       	     ip6->flow_lbl[0], ip6->flow_lbl[1], ip6->flow_lbl[2]); */
/*       printf("\tPayload length: %d\n\tNext header: %d\n\tHop limit: %d\n", */
/*       	      ip6->payload_len, ip6->nexthdr, ip6->hop_limit); */
/*       printf("\tSource: %s\n\tDestination: %s\n", src, dst); */
/*       return ip6->nexthdr; */
    }
    return 0;
  }


  /**
   * Affichage de l'entete UDP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  static inline void bns_header_print_upd(char* buffer, __u32 length, __u32 *offset) {
    struct udphdr *udp = (struct udphdr*)(buffer + *offset);
    *offset += sizeof(struct udphdr);
    __u16 source = ntohs(udp->source);
    __u16 dest = ntohs(udp->dest);
    __u16 check = ntohs(udp->check);
    __u16 len = ntohs(udp->len);
    /* Affichage de l'entete UDP */
    printf("User Datagram Protocol:\n");
    printf("\tSource port: %d\t\n\tDestination port: %d\n", source, dest);
    printf("\tLength: %d\n\tChecksum: 0x%04x\n", len, check);
  }


  /**
   * Affichage de l'entete TCP.
   * @param buffer[in] Buffer contenant les headers + payload.
   * @param length[in] Taille du buffer.
   * @param offset[in,out] Offset de depart, sera modifie apres appel.
   */
  static inline void bns_header_print_tcp(char* buffer, __u32 length, __u32 *offset) {
    union tcp_word_hdr *utcp = (union tcp_word_hdr*)(buffer + *offset);
    struct tcphdr *tcp = &utcp->hdr;
    *offset += sizeof(union tcp_word_hdr);
    __be16 source = ntohs(tcp->source);
    __be16 dest = ntohs(tcp->dest);
    __be32 seq = /*ntohl(*/tcp->seq/*)*/;
    __be32 ack_seq = /*ntohl(*/tcp->ack_seq/*)*/;
    __sum16 check = ntohs(tcp->check);
    /* Affichage de l'entete TCP */
    printf("Transmission Control Protocol:\n");
    printf("\tSource port: %d\n\tDestination port: %d\n", source, dest);
    printf("\tSequence number: %d\n\tAcknowledgement number: %d\n", seq, ack_seq);
    printf("\tFlags:\n");
    printf("\t\t%d... .... = Congestion Window Reduced (CWR): %s\n", SET_NSET(tcp->cwr));
    printf("\t\t.%d.. .... = ECN-Echo: %s\n", SET_NSET(tcp->ece));
    printf("\t\t..%d. .... = Urgent: %s\n", SET_NSET(tcp->urg));
    printf("\t\t...%d .... = Acknowledgement: %s\n", SET_NSET(tcp->ack));
    printf("\t\t.... %d... = Push: %s\n", SET_NSET(tcp->psh));
    printf("\t\t.... .%d.. = Reset: %s\n", SET_NSET(tcp->rst));
    printf("\t\t.... ..%d. = Syn: %s\n", SET_NSET(tcp->syn));
    printf("\t\t.... ...%d = Fin: %s\n", SET_NSET(tcp->fin));
    printf("\tWindow size: %d\n\tChecksum: 0x%04x\n", tcp->window, check);
    printf("\tUrg ptr: %d\n", tcp->urg_ptr);
    if(!tcp->psh && !tcp->syn && (length - *offset)) {
      printf("\tTrailer: Not supported (%d bytes)\n", (length - *offset));
      (*offset) += (length - *offset);
    }
  }


#endif /* __BNS_HEADER_H__ */
