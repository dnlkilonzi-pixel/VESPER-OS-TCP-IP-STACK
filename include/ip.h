/*
 * ip.h - IPv4 header definitions for VESPER OS
 *
 * Implements the Internet Protocol version 4 as specified in RFC 791.
 * The ip_header_t struct maps exactly to the 20-byte fixed IP header
 * so a pointer cast onto a raw buffer is sufficient for parsing.
 *
 * IPv4 header layout (20 bytes, no options):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef VESPER_IP_H
#define VESPER_IP_H

#include "types.h"
#include "ethernet.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define IP_HLEN         20          /* Fixed IPv4 header size (bytes) */
#define IP_VERSION      4           /* IPv4 version field value       */
#define IP_IHL_NO_OPT   5           /* IHL = 5 × 4 = 20 bytes        */
#define IP_DEFAULT_TTL  64          /* Sensible default hop limit     */
#define IP_FLAG_DF      0x4000      /* Don't-fragment flag (net order)*/

/* Protocol numbers (IANA assigned) */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

/* ------------------------------------------------------------------ */
/* IPv4 header structure                                               */
/* ------------------------------------------------------------------ */

/*
 * ip_header_t - Fixed 20-byte IPv4 header
 *
 * Fields are in network byte order where required.  The version and IHL
 * are packed into a single byte — version in the upper nibble, IHL in
 * the lower nibble, as per RFC 791.
 */
typedef struct {
    uint8_t  version_ihl;    /* [7:4] version=4, [3:0] IHL (in 32-bit words) */
    uint8_t  tos;            /* Type of Service / DSCP+ECN (usually 0)       */
    uint16_t total_length;   /* Total length including header (network order) */
    uint16_t id;             /* Identification — unique per datagram          */
    uint16_t flags_fragment; /* [15:13] flags, [12:0] fragment offset        */
    uint8_t  ttl;            /* Time To Live — decremented at each hop        */
    uint8_t  protocol;       /* Upper-layer protocol (TCP=6, UDP=17, ICMP=1) */
    uint16_t checksum;       /* One's complement checksum of header           */
    uint32_t src_ip;         /* Source IP address (network byte order)        */
    uint32_t dst_ip;         /* Destination IP address (network byte order)   */
} __attribute__((packed)) ip_header_t;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * ip_build_packet - Construct an IPv4 packet inside an Ethernet frame
 *
 * Fills in the IP header fields, computes the header checksum, and
 * copies the given payload after the IP header.  The resulting bytes
 * are placed in the payload region of @eth_frame (after the Ethernet
 * header).
 *
 * @eth_frame   : caller-allocated Ethernet frame buffer
 * @src_ip      : source IPv4 address (host byte order)
 * @dst_ip      : destination IPv4 address (host byte order)
 * @protocol    : IP protocol number (e.g. IP_PROTO_TCP)
 * @payload     : pointer to upper-layer payload (may be NULL if len=0)
 * @payload_len : byte length of the upper-layer payload
 * @src_mac     : source MAC address (6 bytes)
 * @dst_mac     : destination MAC address (6 bytes)
 *
 * Returns the total Ethernet frame length on success, 0 on error.
 */
uint16_t ip_build_packet(eth_frame_t *eth_frame,
                         uint32_t src_ip,
                         uint32_t dst_ip,
                         uint8_t  protocol,
                         const uint8_t *payload,
                         uint16_t payload_len,
                         const uint8_t *src_mac,
                         const uint8_t *dst_mac);

/*
 * ip_parse_packet - Parse an IPv4 header from a raw buffer
 *
 * @buf        : raw bytes starting at the IP header
 * @len        : total byte count available in buf
 * @header     : output — filled with parsed IP header fields
 * @payload    : output pointer — points into buf at the IP payload
 * @payload_len: output — byte count of the IP payload
 *
 * Returns true on success, false if the buffer is malformed.
 */
bool ip_parse_packet(const uint8_t *buf,
                     uint16_t len,
                     ip_header_t *header,
                     const uint8_t **payload,
                     uint16_t *payload_len);

/*
 * ip_checksum - Compute the one's-complement checksum over @len bytes
 *
 * This is the standard Internet checksum algorithm (RFC 1071) used for
 * IP headers and TCP/UDP pseudo-headers.
 *
 * @data : pointer to the data to checksum
 * @len  : byte length of the data
 *
 * Returns the 16-bit checksum value (already in network byte order).
 */
uint16_t ip_checksum(const void *data, uint16_t len);

/*
 * ip_print_packet - Log an IPv4 packet header to the kernel console
 */
void ip_print_packet(const ip_header_t *hdr);

/* Helpers for IPv4 address manipulation */
static inline uint32_t ip_make_addr(uint8_t a, uint8_t b,
                                    uint8_t c, uint8_t d)
{
    /* Returns address in host byte order */
    return ((uint32_t)a << 24) |
           ((uint32_t)b << 16) |
           ((uint32_t)c <<  8) |
           ((uint32_t)d);
}

#endif /* VESPER_IP_H */
