/*
 * ethernet.c - Ethernet II frame construction and parsing for VESPER OS
 *
 * Implements the functions declared in include/ethernet.h.
 *
 * All multi-byte EtherType values must be stored in network (big-endian)
 * byte order.  The HTONS() macro from types.h performs the conversion on
 * the little-endian x86 platform.
 */

#include "../include/ethernet.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Internal helpers                                                    */
/* ------------------------------------------------------------------ */

/*
 * mem_copy - minimal memcpy replacement (no libc available)
 */
static void mem_copy(void *dst, const void *src, size_t len)
{
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = s[i];
}

/* ------------------------------------------------------------------ */
/* eth_build_frame                                                     */
/* ------------------------------------------------------------------ */

uint16_t eth_build_frame(eth_frame_t *frame,
                         const uint8_t *dst_mac,
                         const uint8_t *src_mac,
                         uint16_t ethertype,
                         const uint8_t *payload,
                         uint16_t payload_len)
{
    if (!frame || !dst_mac || !src_mac)
        return 0;

    /* Guard against overflowing the static payload buffer */
    if (payload_len > (uint16_t)(ETH_MAX_FRAME - ETH_HLEN))
        return 0;

    /* Fill destination MAC (6 bytes) */
    mac_copy(frame->header.dst_mac, dst_mac);

    /* Fill source MAC (6 bytes) */
    mac_copy(frame->header.src_mac, src_mac);

    /*
     * EtherType is stored in network byte order (big-endian).
     * Callers pass values like ETHERTYPE_IP (0x0800) in host order;
     * we convert with HTONS so the bytes on the wire are correct.
     */
    frame->header.ethertype = HTONS(ethertype);

    /* Copy the payload after the Ethernet header */
    if (payload && payload_len > 0)
        mem_copy(frame->payload, payload, payload_len);

    return (uint16_t)(ETH_HLEN + payload_len);
}

/* ------------------------------------------------------------------ */
/* eth_parse_frame                                                     */
/* ------------------------------------------------------------------ */

bool eth_parse_frame(const uint8_t *buf,
                     uint16_t len,
                     eth_header_t *header,
                     const uint8_t **payload,
                     uint16_t *payload_len)
{
    if (!buf || !header || !payload || !payload_len)
        return false;

    /* We need at least ETH_HLEN bytes to read the header */
    if (len < ETH_HLEN)
        return false;

    /* Copy the raw header bytes into the structured output */
    mem_copy(header, buf, ETH_HLEN);

    /* Convert EtherType from network to host byte order for callers */
    header->ethertype = NTOHS(header->ethertype);

    /* Point at payload inside the caller's buffer (zero-copy) */
    *payload     = buf + ETH_HLEN;
    *payload_len = len - ETH_HLEN;

    return true;
}

/* ------------------------------------------------------------------ */
/* eth_print_frame                                                     */
/* ------------------------------------------------------------------ */

void eth_print_frame(const eth_frame_t *frame, uint16_t frame_len)
{
    uint16_t etype;

    if (!frame) return;

    /*
     * The header's ethertype field is stored in network byte order
     * inside the frame struct, so convert before printing.
     */
    etype = NTOHS(frame->header.ethertype);

    klog_puts("[ETH] dst=");
    klog_mac(frame->header.dst_mac);
    klog_puts(" src=");
    klog_mac(frame->header.src_mac);
    klog_puts(" type=0x");
    klog_hex16(etype);
    klog_puts(" len=");
    klog_udec(frame_len);
    klog_puts("\r\n");
}
