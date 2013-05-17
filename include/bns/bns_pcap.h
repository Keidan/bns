/**
 *******************************************************************************
 * @file bns_pcap.h
 * @author Keidan
 * @date 05/13/2013
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
#ifndef __BNS_PCAP_H__
  #define __BNS_PCAP_H__


  #include <linux/if_ether.h>

  #define BNS_PCAP_VERSION_MAJOR     2
  #define BNS_PCAP_VERSION_MINOR     4
  #define BNS_PCAP_MAGIC_NATIVE      0xa1b2c3d4
  #define BNS_PCAP_MAGIC_SWAPPED     0xd4c3b2a1
  #define BNS_PCAP_LINKTYPE_ETHERNET 1
  #define BNS_PCAP_SNAPLEN           65535

  /*
    Source: http://wiki.wireshark.org/Development/LibpcapFileFormat
    Packet structure:
    -----------------------------------------------------------------------------------------------------------------
    | Global Header | Packet Header | Packet Data | Packet Header | Packet Data | Packet Header | Packet Data | ... |
    -----------------------------------------------------------------------------------------------------------------
  */

  /****************/
  /* global header */
  typedef struct pcap_hdr_s {
      __u32 magic_number;   /* magic number */
      __u16 version_major;  /* major version number */
      __u16 version_minor;  /* minor version number */
      __s32 thiszone;       /* GMT to local correction */
      __u32 sigfigs;        /* accuracy of timestamps */
      __u32 snaplen;        /* max length of captured packets, in octets */
      __u32 network;        /* data link type */
  } pcap_hdr_t;
  /*
    - magic_number: used to detect the file format itself and the byte ordering. The writing application writes 0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read either 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1 value, it knows that all the following fields will have to be swapped too.
    
    - version_major, version_minor: the version number of this file format (current version is 2.4)
    
    - thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are always in GMT, so thiszone is always 0.
    
    - sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0
    
    - snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user), see: incl_len vs. orig_len below
    
    - network: link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for Ethernet, see tcpdump.org's link-layer header types page for details; http://www.tcpdump.org/linktypes.html); this can be various types such as 802.11, 802.11 with various radio information, PPP, Token Ring, FDDI, etc. 
  */

  /****************/
  /* packet header */
  typedef struct pcaprec_hdr_s {
      __u32 ts_sec;         /* timestamp seconds */
      __u32 ts_usec;        /* timestamp microseconds */
      __u32 incl_len;       /* number of octets of packet saved in file */
      __u32 orig_len;       /* actual length of packet */
  } pcaprec_hdr_t;
  /*
    - ts_sec: the date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00 GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use thiszone from the global header for adjustments.
    
    - ts_usec: the microseconds when this packet was captured, as an offset to ts_sec. /!\ Beware: this value shouldn't reach 1 second (1 000 000), in this case ts_sec must be increased instead!
    
    - incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen value of the global header.
    
    - orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len differ, the actually saved packet size was limited by snaplen. 
  */

  /****************/
  /* packet Data */
  /*
    The actual packet data will immediately follow the packet header as a data blob of incl_len bytes without a specific byte alignment. 
  */
  /****************/



  pcap_hdr_t bns_pcap_global_hdr(void);
  pcaprec_hdr_t bns_pcap_packet_hdr(__u32 incl_len, __u32 ori_len);

#endif /* __BNS_PCAP_H__ */
