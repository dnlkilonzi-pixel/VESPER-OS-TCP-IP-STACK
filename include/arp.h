/*
 * arp.h - ARP (Address Resolution Protocol) definitions for VESPER OS
 *
 * Implements RFC 826 ARP for IPv4-over-Ethernet.
 *
 * ARP packet wire layout (28 bytes):
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Hardware Type         |         Protocol Type         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   HW Addr Len | Proto Addr Len|          Operation            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Sender Hardware Address (6 bytes)               |
 * +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               |    Sender IP Address (4 B)    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
 * |                               |                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  Target HW Address (6 bytes)  +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Target IP Address (4 bytes)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef VESPER_ARP_H
#define VESPER_ARP_H

#include "types.h"
#include "ethernet.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define ARP_HTYPE_ETHERNET  1       /* Ethernet hardware type           */
#define ARP_PTYPE_IPV4      0x0800  /* IPv4 protocol type               */
#define ARP_HLEN_ETHERNET   6       /* MAC address length (bytes)       */
#define ARP_PLEN_IPV4       4       /* IPv4 address length (bytes)      */

#define ARP_OPER_REQUEST    1       /* ARP request operation code       */
#define ARP_OPER_REPLY      2       /* ARP reply operation code         */

#define ARP_PKT_LEN         28      /* Fixed size of an IPv4 ARP packet */

#define ARP_CACHE_SIZE      16      /* Number of IP→MAC cache entries   */

/* ------------------------------------------------------------------ */
/* ARP packet structure                                                */
/* ------------------------------------------------------------------ */

/*
 * arp_packet_t - ARP packet as it appears on the wire
 *
 * All multi-byte fields are in network (big-endian) byte order.
 * The IP address fields (spa, tpa) are uint8_t arrays rather than
 * uint32_t to avoid unaligned 32-bit memory access — the 6-byte SHA
 * field causes both addresses to land at non-4-byte-aligned offsets.
 */
typedef struct {
    uint16_t htype;         /* Hardware type: 1 = Ethernet              */
    uint16_t ptype;         /* Protocol type: 0x0800 = IPv4             */
    uint8_t  hlen;          /* Hardware address length: 6               */
    uint8_t  plen;          /* Protocol address length: 4               */
    uint16_t oper;          /* Operation: 1=REQUEST, 2=REPLY            */
    uint8_t  sha[6];        /* Sender hardware (MAC) address            */
    uint8_t  spa[4];        /* Sender protocol (IPv4) address           */
    uint8_t  tha[6];        /* Target hardware (MAC) address            */
    uint8_t  tpa[4];        /* Target protocol (IPv4) address           */
} __attribute__((packed)) arp_packet_t;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * arp_init - Initialise the ARP module
 *
 * Stores the local IP and MAC that will be used as the sender fields
 * in outgoing ARP packets.  Clears the ARP cache.
 *
 * Must be called once before any other ARP function.
 * Typically invoked from net_init().
 *
 * @local_ip  : our IPv4 address (host byte order)
 * @local_mac : our NIC MAC address (6 bytes)
 */
void arp_init(uint32_t local_ip, const uint8_t *local_mac);

/*
 * arp_send_request - Broadcast an ARP request for target_ip
 *
 * Sends an Ethernet broadcast frame ("FF:FF:FF:FF:FF:FF") containing
 * an ARP REQUEST asking "Who has <target_ip>? Tell <local_ip>".
 *
 * @target_ip : IP address to resolve (host byte order)
 */
void arp_send_request(uint32_t target_ip);

/*
 * arp_handle_packet - Process a received ARP frame payload
 *
 * Called by net_receive_handler when EtherType == ETHERTYPE_ARP.
 *
 * Behaviour:
 *   - Always adds the sender's IP→MAC mapping to the cache (gratuitous
 *     ARP and reply learning).
 *   - REQUEST aimed at our IP  → sends a unicast ARP reply.
 *   - REPLY                    → logs and cache update (already done).
 *
 * @payload : bytes starting at the arp_packet_t (after the Ethernet hdr)
 * @length  : byte count of the ARP payload
 */
void arp_handle_packet(const uint8_t *payload, uint16_t length);

/*
 * arp_cache_lookup - Look up the MAC address for a given IP
 *
 * @ip      : IPv4 address to look up (host byte order)
 * @mac_out : output buffer for the 6-byte MAC address
 *
 * Returns true if the entry was found and mac_out was populated,
 * false if the IP is not present in the cache.
 */
bool arp_cache_lookup(uint32_t ip, uint8_t *mac_out);

/*
 * arp_cache_add - Add or update an IP→MAC mapping in the cache
 *
 * If an entry for @ip already exists it is updated in-place.
 * Otherwise the entry is placed in the next available slot using a
 * round-robin eviction policy when the cache is full.
 *
 * @ip  : IPv4 address (host byte order)
 * @mac : 6-byte MAC address
 */
void arp_cache_add(uint32_t ip, const uint8_t *mac);

#endif /* VESPER_ARP_H */
