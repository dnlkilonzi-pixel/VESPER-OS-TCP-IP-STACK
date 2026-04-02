/*
 * ethernet.h - Ethernet II frame definitions for VESPER OS
 *
 * Implements the IEEE 802.3 / Ethernet II framing as used on all modern
 * Ethernet networks.  Every byte of the structure maps directly to the
 * on-wire layout so that a pointer cast is sufficient to parse a raw
 * frame received from the NIC.
 *
 * Frame layout (bytes on wire):
 *   +--------------+--------------+--------+---------+----------+
 *   | Dst MAC (6)  | Src MAC (6)  | Type(2)| Payload | FCS(4)*  |
 *   +--------------+--------------+--------+---------+----------+
 *   * FCS is appended/stripped by the NIC hardware.
 */

#ifndef VESPER_ETHERNET_H
#define VESPER_ETHERNET_H

#include "types.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define ETH_ALEN        6           /* MAC address length in bytes   */
#define ETH_HLEN        14          /* Ethernet header length        */
#define ETH_MAX_FRAME   1514        /* Max frame size (1500 + 14 hdr)*/
#define ETH_MIN_PAYLOAD 46          /* Minimum payload (pad to this) */

/* EtherType values (big-endian as stored in the header) */
#define ETHERTYPE_IP    0x0800      /* IPv4                          */
#define ETHERTYPE_ARP   0x0806      /* ARP                           */
#define ETHERTYPE_IPV6  0x86DD      /* IPv6                          */

/* ------------------------------------------------------------------ */
/* Ethernet header structure                                           */
/* ------------------------------------------------------------------ */

/*
 * eth_header - Ethernet II header
 *
 * All fields are stored in network byte order (big-endian).
 * The __attribute__((packed)) ensures the compiler inserts no padding,
 * so the struct is exactly ETH_HLEN (14) bytes.
 */
typedef struct {
    uint8_t  dst_mac[ETH_ALEN];  /* Destination MAC address (6 bytes) */
    uint8_t  src_mac[ETH_ALEN];  /* Source MAC address      (6 bytes) */
    uint16_t ethertype;          /* EtherType field in network order  */
} __attribute__((packed)) eth_header_t;

/* ------------------------------------------------------------------ */
/* Ethernet frame buffer                                               */
/* ------------------------------------------------------------------ */

/*
 * eth_frame - Complete Ethernet frame (header + payload)
 *
 * This structure is used as a flat memory buffer.  The payload field
 * is a flexible array — callers must allocate sizeof(eth_header_t) +
 * payload_len bytes.
 */
typedef struct {
    eth_header_t header;                /* 14-byte Ethernet header   */
    uint8_t      payload[ETH_MAX_FRAME - ETH_HLEN]; /* payload area  */
} __attribute__((packed)) eth_frame_t;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * eth_build_frame - Populate an Ethernet frame header
 *
 * @frame     : pointer to a caller-allocated eth_frame_t buffer
 * @dst_mac   : 6-byte destination MAC address
 * @src_mac   : 6-byte source MAC address
 * @ethertype : EtherType value (host byte order; converted internally)
 * @payload   : pointer to payload bytes to copy into the frame
 * @payload_len: length of the payload in bytes
 *
 * Returns the total frame length (header + payload), or 0 on error.
 */
uint16_t eth_build_frame(eth_frame_t *frame,
                         const uint8_t *dst_mac,
                         const uint8_t *src_mac,
                         uint16_t ethertype,
                         const uint8_t *payload,
                         uint16_t payload_len);

/*
 * eth_parse_frame - Parse a raw byte buffer as an Ethernet frame
 *
 * @buf     : raw byte buffer received from the NIC
 * @len     : total length of the received buffer
 * @header  : output parameter — filled with parsed header fields
 * @payload : output pointer — set to the start of the payload inside buf
 * @payload_len: output parameter — filled with payload byte count
 *
 * Returns true on success, false if the buffer is too short.
 */
bool eth_parse_frame(const uint8_t *buf,
                     uint16_t len,
                     eth_header_t *header,
                     const uint8_t **payload,
                     uint16_t *payload_len);

/*
 * eth_print_frame - Log an Ethernet frame header to the kernel console
 *
 * @frame     : frame to print
 * @frame_len : total frame length (header + payload)
 */
void eth_print_frame(const eth_frame_t *frame, uint16_t frame_len);

/* Helper: compare two MAC addresses */
static inline bool mac_equal(const uint8_t *a, const uint8_t *b)
{
    int i;
    for (i = 0; i < ETH_ALEN; i++)
        if (a[i] != b[i])
            return false;
    return true;
}

/* Helper: copy a MAC address */
static inline void mac_copy(uint8_t *dst, const uint8_t *src)
{
    int i;
    for (i = 0; i < ETH_ALEN; i++)
        dst[i] = src[i];
}

#endif /* VESPER_ETHERNET_H */
