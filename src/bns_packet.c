#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "bns_packet.h"
#include "bns_utils.h"
#include "bns_logger.h"


#define SET_NSET(cond) (!!(cond)), (cond ? "Set" : "Not Set")

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


int decode_network_buffer(const char* buffer, __u32 length, struct bns_network_s *net) {
  __u32 offset = sizeof(struct ethhdr);
  memset(net, 0, sizeof(struct bns_network_s));
  struct ethhdr *eth = (struct ethhdr *)buffer;
  net->eth = (struct ethhdr *)malloc(sizeof(struct ethhdr));
  if(!net->eth) {
    logger("Unable to alloc memory for eth header!\n");
    return -1;
  }
  memcpy(net->eth, eth, sizeof(struct ethhdr));
  net->eth->h_proto = ntohs(net->eth->h_proto);
  if(net->eth->h_proto == ETH_P_IP || net->eth->h_proto == ETH_P_IPV6) {
    struct iphdr *ip4 = (struct iphdr*)(buffer + offset);

    __u8 protocol = 0;
    if(ip4->version == 4) {
      net->ipv4 = (struct iphdr *)malloc(sizeof(struct iphdr));
      if(!net->ipv4) {
	release_network_buffer(net);
	logger("Unable to alloc memory for ipv4 header!\n");
	return -1;
      }
      memcpy(net->ipv4, ip4, sizeof(struct iphdr));
      offset += sizeof(struct iphdr);
      net->ipv4->tot_len = ntohs(ip4->tot_len);
      net->ipv4->tos = ntohs(ip4->tos); /* pas certains */
      //net->ipv4->ihl = /*ntohl(*/ip4->ihl/*)*/;
      net->ipv4->frag_off = ntohs(ip4->frag_off);
      protocol = net->ipv4->protocol;
    }
    if(protocol == IPPROTO_TCP) {
      union tcp_word_hdr *utcp = (union tcp_word_hdr*)(buffer + offset);
      struct tcphdr *tcp = &utcp->hdr;     
      net->tcp = (struct tcphdr *)malloc(sizeof(struct tcphdr));
      if(!net->tcp) {
	release_network_buffer(net);
	logger("Unable to alloc memory for tcp header!\n");
	return -1;
      }
      memcpy(net->tcp, tcp, sizeof(struct tcphdr));
      offset += sizeof(union tcp_word_hdr);
      net->tcp->source = ntohs(net->tcp->source);
      net->tcp->dest = ntohs(net->tcp->dest);
      net->tcp->seq = ntohs(net->tcp->seq);
      net->tcp->ack_seq = ntohs(net->tcp->ack_seq);
      net->tcp->check = ntohs(net->tcp->check);
      if(!net->tcp->psh && !net->tcp->syn && (length - offset)) {
	printf("TCP Trailer: Not supported (%d bytes)\n", (length - offset));
	offset += (length - offset);
      }
    } else if(protocol == IPPROTO_UDP) {
      struct udphdr *udp = (struct udphdr*)(buffer + offset);
      net->udp = (struct udphdr *)malloc(sizeof(struct udphdr));
      if(!net->udp) {
	release_network_buffer(net);
	logger("Unable to alloc memory for udp header!\n");
	return -1;
      }
      memcpy(net->udp, udp, sizeof(struct udphdr));
      offset += sizeof(struct udphdr);
      net->udp->source = ntohs(net->udp->source);
      net->udp->dest = ntohs(net->udp->dest);
      net->udp->check = ntohs(net->udp->check);
      net->udp->len = ntohs(net->udp->len);
    } else if(protocol == IPPROTO_ICMP) {
      printf("***ICMPv4 UNSUPPORTED ***\n");
    } else if(protocol == IPPROTO_ICMPV6) {
      printf("***ICMPv6 UNSUPPORTED ***\n");
    }
  } else if(net->eth->h_proto == ETH_P_ARP) {
    struct arphdr *arp = (struct arphdr*)(buffer + offset);
    net->arp = (struct arp_parts_s *)malloc(sizeof(struct arp_parts_s));
    if(!net->arp) {
      release_network_buffer(net);
      logger("Unable to alloc memory for arp header!\n");
      return -1;
    }
    memset(net->arp, 0, sizeof(struct arp_parts_s));
    net->arp->arp1 = (struct arphdr *)malloc(sizeof(struct arphdr));
    if(!net->arp->arp1) {
      release_network_buffer(net);
      logger("Unable to alloc memory for arp1 header!\n");
      return -1;
    }
    memcpy(net->arp->arp1, arp, sizeof(struct arphdr));
    offset += sizeof(struct arphdr);  
    net->arp->arp1->ar_op = ntohs(net->arp->arp1->ar_op);
    net->arp->arp1->ar_hrd = ntohs(net->arp->arp1->ar_hrd);  
    /* part 2 */
    if((net->arp->arp1->ar_op == 1 || net->arp->arp1->ar_op == 2) && net->arp->arp1->ar_pln == 4) {
      struct arphdr_part2_s *p2 = (struct arphdr_part2_s*)(buffer + offset);
      net->arp->arp2 = (struct arphdr_part2_s *)malloc(sizeof(struct arphdr_part2_s));   
      if(!net->arp->arp2) {
	release_network_buffer(net);
	logger("Unable to alloc memory for arp2 header!\n");
	return -1;
      }
      memcpy(net->arp->arp2, p2, sizeof(struct arphdr_part2_s));
      offset += sizeof(struct arphdr_part2_s);
    }
    if((length - offset)) {
      printf("ARP Trailer: Not supported (%d bytes)\n", (length - offset));
      offset += (length - offset);
    }
  }
  return offset;
}


void release_network_buffer(struct bns_network_s *net) {
  if(net->eth) free(net->eth), net->eth = NULL;
  if(net->arp) {
    if(net->arp->arp1) free(net->arp->arp1), net->arp->arp1 = NULL;
    if(net->arp->arp2) free(net->arp->arp2), net->arp->arp2 = NULL;
    free(net->arp), net->arp = NULL;
  }
  if(net->ipv4) free(net->ipv4), net->ipv4 = NULL;
  if(net->udp) free(net->udp), net->udp = NULL;
  if(net->tcp) free(net->tcp), net->tcp = NULL;
}


_Bool match_from_simple_filter(struct bns_network_s *net, long host, int port) {
  _Bool ip_found = 0, port_found = 0;
  if(net->eth->h_proto == ETH_P_IP || net->eth->h_proto == ETH_P_IPV6) {
    if(net->ipv4) {
      if(host) {
	char src [INET_ADDRSTRLEN], dst [INET_ADDRSTRLEN];
	memset(dst, 0, sizeof(dst));
	memset(src, 0, sizeof(src));
	inet_ntop(AF_INET, &net->ipv4->saddr, src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &net->ipv4->daddr, dst, INET_ADDRSTRLEN);
	if(host == bns_utils_ip_to_long(src))
	  ip_found = 1;
	else if(host == bns_utils_ip_to_long(dst))
	  ip_found = 1;
	if(!ip_found) return 0;
      } else ip_found = 1;

      if(net->tcp) {
	if(port > 0) {
	  if(port == net->tcp->source) port_found = 1;
	  else if(port == net->tcp->dest) port_found = 1;
	} else port_found = 1;
      } else if(net->udp) {
	if(port > 0) {
	  if(port == net->udp->source) port_found = 1;
	  else if(port == net->udp->dest) port_found = 1;
	} else port_found = 1;
      }
    }
  }
  return ip_found && port_found;
}


void bns_header_print_eth(struct ethhdr *eth) {
  printf("Ethernet:\n");
  printf("\tSource: %02x:%02x:%02x:%02x:%02x:%02x\n\tDestination: %02x:%02x:%02x:%02x:%02x:%02x\n\tType:0x%04x\n",
	 eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
	 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
	 eth->h_proto);
}


void bns_header_print_arp(struct arp_parts_s *arpp) {
  struct arphdr *arp = arpp->arp1;
  struct arphdr_part2_s *p2 = arpp->arp2;
  printf("Adress Resolution Protocol:\n");
  printf("\tHardware type: 0x%04x\n", arp->ar_hrd);
  printf("\tProtocol type: 0x%04x\n", arp->ar_pro);
  printf("\tHardware size: %x\n", arp->ar_hln);
  printf("\tProtocol size: %x\n", arp->ar_pln);
  printf("\tOpcode: %s (%x)\n", (arp->ar_op == 2 ? "reply" : (arp->ar_op == 1 ? "request" : "unknown")) , arp->ar_op);

  /* 
   * Uniquement pour les requetes reponse et si la taille du protocol vaut 4 (IPv4).
   * Je n'ai rien sous la main pour tester l'IPv6, je passe mon tour pour le moment...
   */
  if(p2) {
    printf("\tSender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	   p2->sha[0], p2->sha[1], p2->sha[2], p2->sha[3], p2->sha[4], p2->sha[5]);
    printf("\tSender IP address: %d.%d.%d.%d\n",
	   p2->sip[0], p2->sip[1], p2->sip[2], p2->sip[3]);
    printf("\tTarget MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	   p2->tha[0], p2->tha[1], p2->tha[2], p2->tha[3], p2->tha[4], p2->tha[5]);
    printf("\tTarget IP address: %d.%d.%d.%d\n",
	   p2->tip[0], p2->tip[1], p2->tip[2], p2->tip[3]);
  }
}


void bns_header_print_ip(struct iphdr* ipv4) {
  if(ipv4->version == 4) {
    /* Affichage de l'entete IPv4 */
    char src [INET_ADDRSTRLEN], dst [INET_ADDRSTRLEN];
    memset(dst, 0, sizeof(dst));
    memset(src, 0, sizeof(src));
    inet_ntop(AF_INET, &ipv4->saddr, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ipv4->daddr, dst, INET_ADDRSTRLEN);

    printf("Internet Protocol Version %d:\n", ipv4->version);
    printf("\tVersion: %d\n\tHeader length: %d bytes\n", ipv4->version, ipv4->ihl + sizeof(struct iphdr));
    printf("\tDifferentiated Services Field:\n");
    printf("\t\tTotal Length: %d\n\t\tIdentification: 0x%04x (%d)\n", ipv4->tot_len, ipv4->tos, ipv4->tos);
    printf("\tFlags: 0x%02x\n", ipv4->id);
    printf("\t\t%d... Reserved bit: %s\n",  SET_NSET(ipv4->id&IP_RF));
    printf("\t\t.%d.. Don't fragment: %s\n", SET_NSET(ipv4->id&IP_DF));
    printf("\t\t..%d. More fragments: %s\n", SET_NSET(ipv4->id&IP_MF));
    printf("\tFragment offset: %d\n", ipv4->frag_off);
    printf("\tTime to live: %d\n\tProtocol: %d\n\tHeader checksum: 0x%04x\n", ipv4->ttl, ipv4->protocol, ipv4->check);
    printf("\tSource: %s\n\tDestination: %s\n", src, dst);
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
}


void bns_header_print_upd(struct udphdr *udp) {
  /* Affichage de l'entete UDP */
  printf("User Datagram Protocol:\n");
  printf("\tSource port: %d\t\n\tDestination port: %d\n", udp->source, udp->dest);
  printf("\tLength: %d\n\tChecksum: 0x%04x\n", udp->len, udp->check);
}


void bns_header_print_tcp(struct tcphdr *tcp) { 
  /* Affichage de l'entete TCP */
  printf("Transmission Control Protocol:\n");
  printf("\tSource port: %d\n\tDestination port: %d\n", tcp->source, tcp->dest);
  printf("\tSequence number: %d\n\tAcknowledgement number: %d\n", tcp->seq, tcp->ack_seq);
  printf("\tFlags:\n");
  printf("\t\t%d... .... = Congestion Window Reduced (CWR): %s\n", SET_NSET(tcp->cwr));
  printf("\t\t.%d.. .... = ECN-Echo: %s\n", SET_NSET(tcp->ece));
  printf("\t\t..%d. .... = Urgent: %s\n", SET_NSET(tcp->urg));
  printf("\t\t...%d .... = Acknowledgement: %s\n", SET_NSET(tcp->ack));
  printf("\t\t.... %d... = Push: %s\n", SET_NSET(tcp->psh));
  printf("\t\t.... .%d.. = Reset: %s\n", SET_NSET(tcp->rst));
  printf("\t\t.... ..%d. = Syn: %s\n", SET_NSET(tcp->syn));
  printf("\t\t.... ...%d = Fin: %s\n", SET_NSET(tcp->fin));
  printf("\tWindow size: %d\n\tChecksum: 0x%04x\n", tcp->window, tcp->check);
  printf("\tUrg ptr: %d\n", tcp->urg_ptr);
}
