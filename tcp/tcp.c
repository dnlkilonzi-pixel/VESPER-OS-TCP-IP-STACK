/*
 * tcp.c - TCP segment construction, parsing, checksum and state machine
 *         for VESPER OS
 *
 * Implements the functions declared in include/tcp.h.
 *
 * Design principles:
 *  - All outgoing sequence/acknowledgement numbers are maintained in the
 *    tcp_conn_t.  Callers should treat the struct as opaque.
 *  - The initial sequence number (ISN) is derived from a simple counter.
 *    A real implementation would use a clock-based ISN per RFC 6528.
 *  - Only the 20-byte fixed TCP header is produced (no options).
 *  - The TCP checksum covers a 12-byte pseudo-header + TCP segment.
 */

#include "../include/tcp.h"
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

static void mem_zero(void *dst, size_t len)
{
    uint8_t *d = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < len; i++)
        d[i] = 0;
}

/* Simple counter used to derive the ISN (not clock-based) */
static uint32_t g_next_isn = 0xDEAD0000U;

/* ------------------------------------------------------------------ */
/* tcp_state_name                                                      */
/* ------------------------------------------------------------------ */

const char *tcp_state_name(tcp_state_t state)
{
    switch (state) {
    case TCP_STATE_CLOSED:       return "CLOSED";
    case TCP_STATE_LISTEN:       return "LISTEN";
    case TCP_STATE_SYN_SENT:     return "SYN_SENT";
    case TCP_STATE_SYN_RECEIVED: return "SYN_RECEIVED";
    case TCP_STATE_ESTABLISHED:  return "ESTABLISHED";
    case TCP_STATE_FIN_WAIT_1:   return "FIN_WAIT_1";
    case TCP_STATE_FIN_WAIT_2:   return "FIN_WAIT_2";
    case TCP_STATE_TIME_WAIT:    return "TIME_WAIT";
    case TCP_STATE_CLOSE_WAIT:   return "CLOSE_WAIT";
    case TCP_STATE_LAST_ACK:     return "LAST_ACK";
    default:                     return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* tcp_checksum                                                        */
/* ------------------------------------------------------------------ */

/*
 * TCP pseudo-header as defined in RFC 793 §3.1.
 *
 * Used only for checksum computation — it is never placed on the wire.
 * All fields are in network byte order.
 */
typedef struct {
    uint32_t src_ip;    /* Source IP address                  */
    uint32_t dst_ip;    /* Destination IP address             */
    uint8_t  zero;      /* Always zero                        */
    uint8_t  protocol;  /* IP protocol = 6 (TCP)              */
    uint16_t tcp_len;   /* TCP header + data length (net ord) */
} __attribute__((packed)) tcp_pseudo_hdr_t;

uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const void *tcp_seg, uint16_t tcp_len)
{
    /*
     * We need to checksum pseudo_hdr + tcp_seg together.
     * Build a contiguous temporary buffer on the stack.
     * Maximum TCP segment: ETH_MAX_FRAME - ETH_HLEN - IP_HLEN = 1480 bytes.
     * Pseudo header = 12 bytes.
     * Total buffer size = 12 + 1480 = 1492 bytes.
     */
    uint8_t buf[sizeof(tcp_pseudo_hdr_t) + 1480];
    tcp_pseudo_hdr_t *ph = (tcp_pseudo_hdr_t *)buf;

    if (tcp_len > 1480)
        return 0;

    /* Populate pseudo-header — all values in network byte order */
    ph->src_ip   = HTONL(src_ip);
    ph->dst_ip   = HTONL(dst_ip);
    ph->zero     = 0;
    ph->protocol = IP_PROTO_TCP;
    ph->tcp_len  = HTONS(tcp_len);

    /* Copy TCP segment after pseudo-header */
    mem_copy(buf + sizeof(tcp_pseudo_hdr_t), tcp_seg, tcp_len);

    return ip_checksum(buf, (uint16_t)(sizeof(tcp_pseudo_hdr_t) + tcp_len));
}

/* ------------------------------------------------------------------ */
/* tcp_build_segment                                                   */
/* ------------------------------------------------------------------ */

uint16_t tcp_build_segment(const tcp_conn_t *conn,
                           uint16_t flags,
                           const uint8_t *payload,
                           uint16_t payload_len,
                           eth_frame_t *out_frame)
{
    /*
     * Assemble: TCP header (20 bytes) + payload.
     * Then hand to ip_build_packet() which wraps it in an IP + Ethernet frame.
     */
    uint8_t tcp_buf[TCP_HLEN + 1460]; /* max segment size */
    tcp_header_t *tcph = (tcp_header_t *)tcp_buf;
    uint16_t tcp_total_len;
    uint16_t data_offset_flags;

    if (!conn || !out_frame)
        return 0;

    if (payload_len > 1460)
        return 0;

    tcp_total_len = TCP_HLEN + payload_len;

    /* Source and destination ports (network byte order) */
    tcph->src_port = HTONS(conn->local_port);
    tcph->dst_port = HTONS(conn->remote_port);

    /* Sequence number (network byte order) */
    tcph->seq_num = HTONL(conn->snd_nxt);

    /* Acknowledgment number — valid only when ACK flag is set */
    tcph->ack_num = (flags & TCP_FLAG_ACK) ? HTONL(conn->rcv_nxt) : 0;

    /*
     * data_offset_flags:
     *   Bits [15:12] = data offset (header length in 32-bit words = 5)
     *   Bits [11:6]  = reserved (0)
     *   Bits [5:0]   = control flags
     * The field is stored in network byte order.
     */
    data_offset_flags = (uint16_t)(((uint16_t)TCP_DATA_OFFSET_MIN << 12) |
                                   (flags & TCP_FLAGS_MASK));
    tcph->data_offset_flags = HTONS(data_offset_flags);

    /* Advertise our receive window */
    tcph->window = HTONS((uint16_t)conn->rcv_wnd);

    /* Zero checksum and urgent pointer before computing checksum */
    tcph->checksum   = 0;
    tcph->urgent_ptr = 0;

    /* Copy payload into the TCP buffer (after the header) */
    if (payload && payload_len > 0)
        mem_copy(tcp_buf + TCP_HLEN, payload, payload_len);

    /* Compute TCP checksum over pseudo-header + TCP segment */
    tcph->checksum = HTONS(tcp_checksum(conn->local_ip, conn->remote_ip,
                                        tcp_buf, tcp_total_len));

    /* Encapsulate in IP + Ethernet */
    return ip_build_packet(out_frame,
                           conn->local_ip,
                           conn->remote_ip,
                           IP_PROTO_TCP,
                           tcp_buf,
                           tcp_total_len,
                           conn->local_mac,
                           conn->remote_mac);
}

/* ------------------------------------------------------------------ */
/* tcp_parse_segment                                                   */
/* ------------------------------------------------------------------ */

bool tcp_parse_segment(const uint8_t *buf,
                       uint16_t len,
                       tcp_header_t *header,
                       const uint8_t **payload,
                       uint16_t *payload_len)
{
    const tcp_header_t *tcph;
    uint16_t data_offset_flags;
    uint8_t  hdr_len;

    if (!buf || !header || !payload || !payload_len)
        return false;

    if (len < TCP_HLEN)
        return false;

    tcph = (const tcp_header_t *)buf;

    /* Copy raw header bytes first */
    mem_copy(header, tcph, TCP_HLEN);

    /* Decode data_offset_flags — convert from network order first */
    data_offset_flags = NTOHS(header->data_offset_flags);

    /* Header length in bytes */
    hdr_len = (uint8_t)(((data_offset_flags >> 12) & 0xF) * 4);
    if (hdr_len < TCP_HLEN || hdr_len > len)
        return false;

    /* Byte-swap all multi-byte fields to host order for callers */
    header->src_port          = NTOHS(header->src_port);
    header->dst_port          = NTOHS(header->dst_port);
    header->seq_num           = NTOHL(header->seq_num);
    header->ack_num           = NTOHL(header->ack_num);
    header->data_offset_flags = data_offset_flags; /* already host order */
    header->window            = NTOHS(header->window);
    header->checksum          = NTOHS(header->checksum);
    header->urgent_ptr        = NTOHS(header->urgent_ptr);

    *payload     = buf + hdr_len;
    *payload_len = (uint16_t)(len - hdr_len);

    return true;
}

/* ------------------------------------------------------------------ */
/* tcp_print_segment                                                   */
/* ------------------------------------------------------------------ */

void tcp_print_segment(const tcp_header_t *hdr)
{
    uint16_t flags;
    if (!hdr) return;

    flags = hdr->data_offset_flags & TCP_FLAGS_MASK;

    klog_puts("[TCP] src=");
    klog_udec(hdr->src_port);
    klog_puts(" dst=");
    klog_udec(hdr->dst_port);
    klog_puts(" seq=0x");
    klog_hex32(hdr->seq_num);
    klog_puts(" ack=0x");
    klog_hex32(hdr->ack_num);
    klog_puts(" flags=");
    if (flags & TCP_FLAG_SYN) klog_puts("SYN ");
    if (flags & TCP_FLAG_ACK) klog_puts("ACK ");
    if (flags & TCP_FLAG_FIN) klog_puts("FIN ");
    if (flags & TCP_FLAG_RST) klog_puts("RST ");
    if (flags & TCP_FLAG_PSH) klog_puts("PSH ");
    klog_puts("win=");
    klog_udec(hdr->window);
    klog_puts("\r\n");
}

/* ------------------------------------------------------------------ */
/* State machine helpers                                               */
/* ------------------------------------------------------------------ */

void tcp_conn_init(tcp_conn_t *conn,
                   uint32_t local_ip,  uint16_t local_port,
                   uint32_t remote_ip, uint16_t remote_port,
                   const uint8_t *local_mac,
                   const uint8_t *remote_mac)
{
    int i;
    if (!conn) return;

    mem_zero(conn, sizeof(*conn));

    conn->local_ip    = local_ip;
    conn->local_port  = local_port;
    conn->remote_ip   = remote_ip;
    conn->remote_port = remote_port;

    for (i = 0; i < 6; i++) {
        conn->local_mac[i]  = local_mac[i];
        conn->remote_mac[i] = remote_mac[i];
    }

    /* Generate an initial sequence number */
    conn->snd_isn = g_next_isn;
    g_next_isn += 0x1000; /* advance counter for next connection */

    conn->snd_nxt = conn->snd_isn;
    conn->rcv_nxt = 0;
    conn->rcv_wnd = TCP_DEFAULT_WINDOW;
    conn->state   = TCP_STATE_CLOSED;
}

/* ------------------------------------------------------------------ */
/* tcp_send_syn                                                        */
/* ------------------------------------------------------------------ */

uint16_t tcp_send_syn(tcp_conn_t *conn, eth_frame_t *out_frame)
{
    uint16_t frame_len;

    if (!conn || !out_frame) return 0;
    if (conn->state != TCP_STATE_CLOSED) return 0;

    /* Build a SYN segment (no payload, no ACK) */
    frame_len = tcp_build_segment(conn, TCP_FLAG_SYN,
                                  NULL, 0, out_frame);
    if (frame_len == 0) return 0;

    /*
     * A SYN consumes one sequence number.
     * Advance snd_nxt so the ACK we expect will be snd_isn + 1.
     */
    conn->snd_nxt++;

    /* Transition: CLOSED → SYN_SENT */
    conn->state = TCP_STATE_SYN_SENT;

    klog_puts("[TCP] State transition: CLOSED -> SYN_SENT (seq=0x");
    klog_hex32(conn->snd_isn);
    klog_puts(")\r\n");

    return frame_len;
}

/* ------------------------------------------------------------------ */
/* tcp_handle_syn_ack                                                  */
/* ------------------------------------------------------------------ */

uint16_t tcp_handle_syn_ack(tcp_conn_t *conn,
                            const uint8_t *buf,
                            uint16_t buf_len,
                            eth_frame_t *out_frame)
{
    ip_header_t   ip_hdr;
    tcp_header_t  tcp_hdr;
    const uint8_t *ip_payload;
    const uint8_t *tcp_payload;
    uint16_t ip_payload_len;
    uint16_t tcp_payload_len;
    uint16_t flags;
    uint16_t frame_len;

    if (!conn || !buf || !out_frame) return 0;
    if (conn->state != TCP_STATE_SYN_SENT) return 0;

    /* Parse IP header from the raw buffer */
    if (!ip_parse_packet(buf, buf_len, &ip_hdr,
                         &ip_payload, &ip_payload_len))
        return 0;

    /* Parse TCP header from IP payload */
    if (!tcp_parse_segment(ip_payload, ip_payload_len,
                           &tcp_hdr, &tcp_payload, &tcp_payload_len))
        return 0;

    /* Verify this is a SYN-ACK directed at us */
    flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;
    if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) != (TCP_FLAG_SYN | TCP_FLAG_ACK))
        return 0;

    if (tcp_hdr.dst_port != conn->local_port) return 0;
    if (tcp_hdr.src_port != conn->remote_port) return 0;

    /* Verify that the ACK number acknowledges our SYN */
    if (tcp_hdr.ack_num != conn->snd_nxt) return 0;

    /*
     * Record the remote's initial sequence number.
     * rcv_nxt = remote ISN + 1 (the SYN consumed one sequence number).
     */
    conn->rcv_nxt = tcp_hdr.seq_num + 1;

    klog_puts("[TCP] Received SYN-ACK: remote_seq=0x");
    klog_hex32(tcp_hdr.seq_num);
    klog_puts(" ack=0x");
    klog_hex32(tcp_hdr.ack_num);
    klog_puts("\r\n");

    /* Build the final ACK of the handshake (no payload) */
    frame_len = tcp_build_segment(conn, TCP_FLAG_ACK,
                                  NULL, 0, out_frame);
    if (frame_len == 0) return 0;

    /* Transition: SYN_SENT → ESTABLISHED */
    conn->state = TCP_STATE_ESTABLISHED;

    klog_puts("[TCP] State transition: SYN_SENT -> ESTABLISHED\r\n");

    return frame_len;
}

/* ------------------------------------------------------------------ */
/* tcp_send_data                                                       */
/* ------------------------------------------------------------------ */

uint16_t tcp_send_data(tcp_conn_t *conn,
                       const uint8_t *data,
                       uint16_t data_len,
                       eth_frame_t *out_frame)
{
    uint16_t frame_len;

    if (!conn || !data || !out_frame) return 0;
    if (conn->state != TCP_STATE_ESTABLISHED) return 0;
    if (data_len == 0) return 0;

    /* Build segment with PSH+ACK flags */
    frame_len = tcp_build_segment(conn,
                                  TCP_FLAG_PSH | TCP_FLAG_ACK,
                                  data, data_len,
                                  out_frame);
    if (frame_len == 0) return 0;

    /* Advance send sequence number by the number of data bytes sent */
    conn->snd_nxt += data_len;

    klog_puts("[TCP] Sending data: ");
    klog_udec(data_len);
    klog_puts(" bytes, seq=0x");
    klog_hex32(conn->snd_nxt - data_len);
    klog_puts("\r\n");

    return frame_len;
}

/* ------------------------------------------------------------------ */
/* tcp_send_fin                                                        */
/* ------------------------------------------------------------------ */

uint16_t tcp_send_fin(tcp_conn_t *conn, eth_frame_t *out_frame)
{
    uint16_t frame_len;

    if (!conn || !out_frame) return 0;
    if (conn->state != TCP_STATE_ESTABLISHED) return 0;

    /* Build FIN+ACK segment */
    frame_len = tcp_build_segment(conn,
                                  TCP_FLAG_FIN | TCP_FLAG_ACK,
                                  NULL, 0, out_frame);
    if (frame_len == 0) return 0;

    /* FIN consumes one sequence number */
    conn->snd_nxt++;

    /* Transition: ESTABLISHED → FIN_WAIT_1 */
    conn->state = TCP_STATE_FIN_WAIT_1;

    klog_puts("[TCP] State transition: ESTABLISHED -> FIN_WAIT_1\r\n");

    return frame_len;
}

/* ------------------------------------------------------------------ */
/* tcp_send_ack                                                        */
/* ------------------------------------------------------------------ */

uint16_t tcp_send_ack(tcp_conn_t *conn, eth_frame_t *out_frame)
{
    if (!conn || !out_frame) return 0;

    /* ACK is valid in any state where we have an established receive path */
    if (conn->state != TCP_STATE_ESTABLISHED &&
        conn->state != TCP_STATE_FIN_WAIT_1  &&
        conn->state != TCP_STATE_FIN_WAIT_2  &&
        conn->state != TCP_STATE_CLOSE_WAIT)
        return 0;

    /* Pure ACK — no data, no flags other than ACK, does not advance snd_nxt */
    return tcp_build_segment(conn, TCP_FLAG_ACK, NULL, 0, out_frame);
}
