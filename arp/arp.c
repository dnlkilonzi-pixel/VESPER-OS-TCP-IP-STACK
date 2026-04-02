/*
 * arp.c - ARP (Address Resolution Protocol) implementation for VESPER OS
 *
 * Implements RFC 826 ARP for IPv4-over-Ethernet.
 *
 * Features:
 *  - Statically-allocated ARP cache (ARP_CACHE_SIZE entries).
 *  - Round-robin cache eviction when the table is full.
 *  - Responds to ARP requests targeted at our IP address.
 *  - Learns sender IP→MAC mappings from every ARP packet received.
 */

#include "../include/arp.h"
#include "../include/nic.h"
#include "../include/ethernet.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Module-private state                                                */
/* ------------------------------------------------------------------ */

/* Our local IP and MAC address — set by arp_init() */
static uint32_t g_local_ip            = 0;
static uint8_t  g_local_mac[ETH_ALEN] = {0};

/* ARP cache entry */
typedef struct {
    uint32_t ip;            /* IPv4 address (host byte order) */
    uint8_t  mac[ETH_ALEN]; /* Corresponding MAC address       */
    bool     valid;         /* Whether this slot holds live data */
} arp_entry_t;

static arp_entry_t g_arp_cache[ARP_CACHE_SIZE];

/* Next eviction index (round-robin) */
static uint8_t g_arp_next_slot = 0;

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void mem_zero(void *dst, size_t len)
{
    uint8_t *d = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = 0;
}

/*
 * read_u32_be - read a 4-byte big-endian value from an unaligned buffer
 *
 * Used for the spa/tpa fields in the ARP packet which may not be
 * 4-byte aligned due to the preceding 6-byte SHA field.
 */
static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
            (uint32_t)p[3];
}

/*
 * write_u32_be - write a 32-bit value as big-endian bytes
 */
static void write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

/* ------------------------------------------------------------------ */
/* arp_init                                                            */
/* ------------------------------------------------------------------ */

void arp_init(uint32_t local_ip, const uint8_t *local_mac)
{
    int i;
    g_local_ip = local_ip;
    for (i = 0; i < ETH_ALEN; i++)
        g_local_mac[i] = local_mac[i];
    mem_zero(g_arp_cache, sizeof(g_arp_cache));
    g_arp_next_slot = 0;
}

/* ------------------------------------------------------------------ */
/* arp_cache_add                                                       */
/* ------------------------------------------------------------------ */

void arp_cache_add(uint32_t ip, const uint8_t *mac)
{
    int i;

    if (!mac) return;

    /* Update in-place if the IP is already cached */
    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        if (g_arp_cache[i].valid && g_arp_cache[i].ip == ip) {
            mac_copy(g_arp_cache[i].mac, mac);
            return;
        }
    }

    /* Insert into the next available slot (round-robin eviction) */
    g_arp_cache[g_arp_next_slot].ip    = ip;
    mac_copy(g_arp_cache[g_arp_next_slot].mac, mac);
    g_arp_cache[g_arp_next_slot].valid = true;
    g_arp_next_slot = (uint8_t)((g_arp_next_slot + 1) % ARP_CACHE_SIZE);
}

/* ------------------------------------------------------------------ */
/* arp_cache_lookup                                                    */
/* ------------------------------------------------------------------ */

bool arp_cache_lookup(uint32_t ip, uint8_t *mac_out)
{
    int i;

    if (!mac_out) return false;

    for (i = 0; i < ARP_CACHE_SIZE; i++) {
        if (g_arp_cache[i].valid && g_arp_cache[i].ip == ip) {
            mac_copy(mac_out, g_arp_cache[i].mac);
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* arp_send_request                                                    */
/* ------------------------------------------------------------------ */

void arp_send_request(uint32_t target_ip)
{
    eth_frame_t  eth_frame;
    arp_packet_t arp_pkt;
    uint16_t     frame_len;

    static const uint8_t BROADCAST_MAC[ETH_ALEN] =
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t ZERO_MAC[ETH_ALEN] =
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    mem_zero(&arp_pkt, sizeof(arp_pkt));

    arp_pkt.htype = HTONS(ARP_HTYPE_ETHERNET);
    arp_pkt.ptype = HTONS(ARP_PTYPE_IPV4);
    arp_pkt.hlen  = ARP_HLEN_ETHERNET;
    arp_pkt.plen  = ARP_PLEN_IPV4;
    arp_pkt.oper  = HTONS(ARP_OPER_REQUEST);

    mac_copy(arp_pkt.sha, g_local_mac);
    write_u32_be(arp_pkt.spa, g_local_ip);
    mac_copy(arp_pkt.tha, ZERO_MAC);
    write_u32_be(arp_pkt.tpa, target_ip);

    frame_len = eth_build_frame(&eth_frame,
                                BROADCAST_MAC,
                                g_local_mac,
                                ETHERTYPE_ARP,
                                (const uint8_t *)&arp_pkt,
                                ARP_PKT_LEN);
    if (frame_len == 0) return;

    klog_puts("[ARP] Request: who has ");
    klog_ipv4(target_ip);
    klog_puts("? Tell ");
    klog_ipv4(g_local_ip);
    klog_puts("\r\n");

    nic_send_frame((const uint8_t *)&eth_frame, frame_len);
}

/* ------------------------------------------------------------------ */
/* arp_handle_packet                                                   */
/* ------------------------------------------------------------------ */

void arp_handle_packet(const uint8_t *payload, uint16_t length)
{
    const arp_packet_t *arp;
    uint16_t oper;
    uint32_t sender_ip;
    uint32_t target_ip;

    if (!payload || length < ARP_PKT_LEN)
        return;

    arp = (const arp_packet_t *)payload;

    /* Only handle Ethernet/IPv4 ARP */
    if (NTOHS(arp->htype) != ARP_HTYPE_ETHERNET) return;
    if (NTOHS(arp->ptype) != ARP_PTYPE_IPV4)     return;
    if (arp->hlen != ARP_HLEN_ETHERNET)           return;
    if (arp->plen != ARP_PLEN_IPV4)               return;

    oper      = NTOHS(arp->oper);
    sender_ip = read_u32_be(arp->spa);
    target_ip = read_u32_be(arp->tpa);

    /*
     * Learn the sender's IP→MAC mapping from every ARP packet we see,
     * regardless of operation (supports gratuitous ARP).
     */
    if (sender_ip != 0)
        arp_cache_add(sender_ip, arp->sha);

    if (oper == ARP_OPER_REQUEST) {
        /* Only respond if someone is asking for our IP */
        if (target_ip != g_local_ip)
            return;

        /* Build and send a unicast ARP reply */
        {
            eth_frame_t  reply_frame;
            arp_packet_t reply_pkt;
            uint16_t     reply_len;

            mem_zero(&reply_pkt, sizeof(reply_pkt));
            reply_pkt.htype = HTONS(ARP_HTYPE_ETHERNET);
            reply_pkt.ptype = HTONS(ARP_PTYPE_IPV4);
            reply_pkt.hlen  = ARP_HLEN_ETHERNET;
            reply_pkt.plen  = ARP_PLEN_IPV4;
            reply_pkt.oper  = HTONS(ARP_OPER_REPLY);

            /* Sender = us */
            mac_copy(reply_pkt.sha, g_local_mac);
            write_u32_be(reply_pkt.spa, g_local_ip);

            /* Target = requester */
            mac_copy(reply_pkt.tha, arp->sha);
            write_u32_be(reply_pkt.tpa, sender_ip);

            reply_len = eth_build_frame(&reply_frame,
                                        arp->sha,       /* send to requester */
                                        g_local_mac,
                                        ETHERTYPE_ARP,
                                        (const uint8_t *)&reply_pkt,
                                        ARP_PKT_LEN);
            if (reply_len > 0) {
                klog_puts("[ARP] Reply: ");
                klog_ipv4(g_local_ip);
                klog_puts(" is at ");
                klog_mac(g_local_mac);
                klog_puts("\r\n");
                nic_send_frame((const uint8_t *)&reply_frame, reply_len);
            }
        }
    } else if (oper == ARP_OPER_REPLY) {
        klog_puts("[ARP] Learned: ");
        klog_ipv4(sender_ip);
        klog_puts(" is at ");
        klog_mac(arp->sha);
        klog_puts("\r\n");
    }
}
