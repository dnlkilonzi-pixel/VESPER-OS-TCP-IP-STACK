/*
 * ip.c - IPv4 packet construction, parsing and checksum for VESPER OS
 *
 * Implements the functions declared in include/ip.h.
 *
 * Key design choices:
 *  - A monotonically incrementing global ID counter is used for the IP
 *    Identification field (good enough for a minimal stack).
 *  - The Don't-Fragment (DF) bit is always set; we do not implement
 *    IP fragmentation.
 *  - All fields are converted to network byte order with HTONS/HTONL
 *    before being written into the header.
 */

#include "../include/ip.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

static void mem_copy(void *dst, const void *src, size_t len)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = s[i];
}

/* Global packet ID counter — incremented for every datagram sent */
static uint16_t g_ip_id = 0;

/* ------------------------------------------------------------------ */
/* ip_checksum (RFC 1071)                                              */
/* ------------------------------------------------------------------ */

uint16_t ip_checksum(const void *data, uint16_t len)
{
    const uint8_t *ptr = (const uint8_t *)data;
    uint32_t sum = 0;
    uint16_t i;

    /*
     * Sum all 16-bit words.  If the data length is odd we zero-pad
     * the final byte (treated as a 16-bit word with the high byte = 0).
     */
    for (i = 0; i + 1 < len; i += 2) {
        /* Reconstruct a big-endian 16-bit word from two bytes */
        uint16_t word = ((uint16_t)ptr[i] << 8) | ptr[i + 1];
        sum += word;
    }
    /* Handle odd trailing byte */
    if (len & 1)
        sum += (uint16_t)ptr[len - 1] << 8;

    /* Fold 32-bit carry bits into 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    /*
     * Return one's complement.  The result is in network byte order
     * because we processed the bytes as big-endian 16-bit words above.
     */
    return (uint16_t)(~sum & 0xFFFF);
}

/* ------------------------------------------------------------------ */
/* ip_build_packet                                                     */
/* ------------------------------------------------------------------ */

uint16_t ip_build_packet(eth_frame_t *eth_frame,
                         uint32_t src_ip,
                         uint32_t dst_ip,
                         uint8_t  protocol,
                         const uint8_t *payload,
                         uint16_t payload_len,
                         const uint8_t *src_mac,
                         const uint8_t *dst_mac)
{
    ip_header_t *iph;
    uint16_t     ip_total_len;
    uint8_t      ip_buf[IP_HLEN + (ETH_MAX_FRAME - ETH_HLEN - IP_HLEN)];
    uint16_t     eth_frame_len;

    if (!eth_frame || !src_mac || !dst_mac)
        return 0;

    if (payload_len > (uint16_t)(ETH_MAX_FRAME - ETH_HLEN - IP_HLEN))
        return 0;

    ip_total_len = IP_HLEN + payload_len;

    /* Build the IP header in a local buffer, then copy into the frame */
    iph = (ip_header_t *)ip_buf;

    /*
     * version_ihl: upper nibble = 4 (IPv4), lower nibble = 5 (no options)
     * Stored as a plain byte — no byte-order conversion needed.
     */
    iph->version_ihl    = (IP_VERSION << 4) | IP_IHL_NO_OPT;
    iph->tos            = 0;                        /* Best-effort service  */
    iph->total_length   = HTONS(ip_total_len);      /* Network byte order   */
    iph->id             = HTONS(g_ip_id);           /* Unique datagram ID   */
    g_ip_id++;
    iph->flags_fragment = HTONS(IP_FLAG_DF);        /* Don't Fragment       */
    iph->ttl            = IP_DEFAULT_TTL;
    iph->protocol       = protocol;
    iph->checksum       = 0;                        /* Zero before computing */

    /*
     * IP addresses are stored in network byte order.
     * ip_make_addr() returns addresses in host byte order (A.B.C.D as
     * a 32-bit integer with A in the MSB).  HTONL() reverses the bytes
     * so they are in the correct on-wire representation.
     */
    iph->src_ip = HTONL(src_ip);
    iph->dst_ip = HTONL(dst_ip);

    /* Compute header checksum over the 20-byte header */
    iph->checksum = HTONS(ip_checksum(iph, IP_HLEN));

    /* Copy payload after the IP header in our temporary buffer */
    if (payload && payload_len > 0)
        mem_copy(ip_buf + IP_HLEN, payload, payload_len);

    /* Wrap in an Ethernet frame targeting the destination MAC */
    eth_frame_len = eth_build_frame(eth_frame,
                                    dst_mac,
                                    src_mac,
                                    ETHERTYPE_IP,
                                    ip_buf,
                                    ip_total_len);
    return eth_frame_len;
}

/* ------------------------------------------------------------------ */
/* ip_parse_packet                                                     */
/* ------------------------------------------------------------------ */

bool ip_parse_packet(const uint8_t *buf,
                     uint16_t len,
                     ip_header_t *header,
                     const uint8_t **payload,
                     uint16_t *payload_len)
{
    const ip_header_t *iph;
    uint8_t  ihl_bytes;
    uint16_t total_len;

    if (!buf || !header || !payload || !payload_len)
        return false;

    /* Minimum: we need the fixed 20-byte IP header */
    if (len < IP_HLEN)
        return false;

    iph = (const ip_header_t *)buf;

    /* Validate IP version */
    if ((iph->version_ihl >> 4) != IP_VERSION)
        return false;

    /* Header length in bytes = IHL field × 4 */
    ihl_bytes = (uint8_t)((iph->version_ihl & 0x0F) * 4);
    if (ihl_bytes < IP_HLEN || ihl_bytes > len)
        return false;

    /* Total length as indicated in the header */
    total_len = NTOHS(iph->total_length);
    if (total_len < ihl_bytes || total_len > len)
        return false;

    /* Copy header into caller's struct */
    mem_copy(header, iph, IP_HLEN);

    /* Byte-swap multi-byte fields to host order for the caller */
    header->total_length   = NTOHS(header->total_length);
    header->id             = NTOHS(header->id);
    header->flags_fragment = NTOHS(header->flags_fragment);
    header->checksum       = NTOHS(header->checksum);
    header->src_ip         = NTOHL(header->src_ip);
    header->dst_ip         = NTOHL(header->dst_ip);

    /* Point to payload beyond the (possibly variable-length) header */
    *payload     = buf + ihl_bytes;
    *payload_len = (uint16_t)(total_len - ihl_bytes);

    return true;
}

/* ------------------------------------------------------------------ */
/* ip_print_packet                                                     */
/* ------------------------------------------------------------------ */

void ip_print_packet(const ip_header_t *hdr)
{
    if (!hdr) return;

    klog_puts("[IP]  src=");
    klog_ipv4(hdr->src_ip);
    klog_puts(" dst=");
    klog_ipv4(hdr->dst_ip);
    klog_puts(" proto=");
    klog_udec(hdr->protocol);
    klog_puts(" ttl=");
    klog_udec(hdr->ttl);
    klog_puts(" len=");
    klog_udec(hdr->total_length);
    klog_puts(" id=0x");
    klog_hex16(hdr->id);
    klog_puts("\r\n");
}
