/*
 * net.c - High-level network interface for VESPER OS
 *
 * Implements the functions declared in include/net.h.
 *
 * This module ties together the NIC driver, Ethernet, IP, ARP and TCP
 * layers into a coherent subsystem.  It owns the global receive path
 * and the simple spin-wait TCP connect / receive loops.
 */

#include "../include/net.h"
#include "../include/nic.h"
#include "../include/arp.h"
#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/tcp.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Global network configuration                                        */
/* ------------------------------------------------------------------ */

net_config_t g_net_config;

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

/* ------------------------------------------------------------------ */
/* Internal state — TCP connect path                                   */
/* ------------------------------------------------------------------ */

/*
 * Pointer to the connection currently waiting for an incoming packet
 * (set during net_tcp_connect's spin-wait loop).
 */
static tcp_conn_t *g_pending_conn = NULL;

/*
 * Buffer to write the response frame into when a SYN-ACK arrives
 * during the connect loop.
 */
static eth_frame_t g_response_frame;

/*
 * Flag set by net_receive_handler when a valid SYN-ACK has been
 * processed and g_response_frame is populated.
 */
static bool g_synack_received = false;

/* ------------------------------------------------------------------ */
/* Internal state — TCP data receive path                              */
/* ------------------------------------------------------------------ */

/* Connection currently waiting for incoming data (set by net_tcp_recv) */
static tcp_conn_t *g_rx_conn     = NULL;

/* Buffer and tracking for the data receive path */
static uint8_t   *g_rx_buf      = NULL;
static uint16_t   g_rx_capacity = 0;
static uint16_t   g_rx_len      = 0;

/* Set to true when a FIN is received on g_rx_conn */
static bool g_rx_done = false;

/* ------------------------------------------------------------------ */
/* net_receive_handler                                                 */
/* ------------------------------------------------------------------ */

void net_receive_handler(const uint8_t *frame, uint16_t length)
{
    eth_header_t  eth_hdr;
    ip_header_t   ip_hdr;
    const uint8_t *eth_payload;
    const uint8_t *ip_payload;
    uint16_t       eth_payload_len;
    uint16_t       ip_payload_len;

    if (!frame || length < ETH_HLEN)
        return;

    /* Parse Ethernet header */
    if (!eth_parse_frame(frame, length, &eth_hdr,
                         &eth_payload, &eth_payload_len))
        return;

    /* ---- ARP path ---- */
    if (eth_hdr.ethertype == ETHERTYPE_ARP) {
        arp_handle_packet(eth_payload, eth_payload_len);
        return;
    }

    /* Beyond this point we only handle IPv4 */
    if (eth_hdr.ethertype != ETHERTYPE_IP)
        return;

    /* Parse IP header */
    if (!ip_parse_packet(eth_payload, eth_payload_len, &ip_hdr,
                         &ip_payload, &ip_payload_len))
        return;

    /* Log the received IP packet */
    ip_print_packet(&ip_hdr);

    /* Only handle TCP */
    if (ip_hdr.protocol != IP_PROTO_TCP)
        return;

    /* ---- SYN-ACK path (three-way handshake in progress) ---- */
    if (g_pending_conn && !g_synack_received) {
        uint16_t frame_len = tcp_handle_syn_ack(g_pending_conn,
                                                eth_payload,
                                                eth_payload_len,
                                                &g_response_frame);
        if (frame_len > 0) {
            nic_send_frame((const uint8_t *)&g_response_frame, frame_len);
            eth_print_frame(&g_response_frame, frame_len);
            g_synack_received = true;
        }
        return;
    }

    /* ---- Data receive path (established connection) ---- */
    if (g_rx_conn) {
        tcp_header_t  tcp_hdr;
        const uint8_t *tcp_payload;
        uint16_t       tcp_payload_len;
        uint16_t       flags;

        if (!tcp_parse_segment(ip_payload, ip_payload_len,
                               &tcp_hdr, &tcp_payload, &tcp_payload_len))
            return;

        /* Verify the segment belongs to our registered connection */
        if (tcp_hdr.dst_port != g_rx_conn->local_port)  return;
        if (tcp_hdr.src_port != g_rx_conn->remote_port) return;
        if (ip_hdr.src_ip    != g_rx_conn->remote_ip)   return;

        flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;

        /* Copy data payload into receive buffer */
        if (tcp_payload_len > 0 && g_rx_buf != NULL) {
            uint16_t avail   = (uint16_t)(g_rx_capacity - g_rx_len);
            uint16_t to_copy = (tcp_payload_len < avail)
                               ? tcp_payload_len : avail;

            if (to_copy > 0) {
                mem_copy(g_rx_buf + g_rx_len, tcp_payload, to_copy);
                g_rx_len += to_copy;
            }

            /*
             * Advance rcv_nxt by the full received payload length even
             * if we truncated the copy — the ACK must cover what we
             * consumed from the sender's sequence space.
             */
            g_rx_conn->rcv_nxt += tcp_payload_len;

            /* Send a pure ACK to acknowledge the received data */
            {
                eth_frame_t ack_frame;
                uint16_t    ack_len = tcp_send_ack(g_rx_conn, &ack_frame);
                if (ack_len > 0)
                    nic_send_frame((const uint8_t *)&ack_frame, ack_len);
            }
        }

        /* Handle FIN — remote side is done sending */
        if (flags & TCP_FLAG_FIN) {
            g_rx_conn->rcv_nxt++; /* FIN consumes one sequence number */
            g_rx_done = true;

            /* ACK the FIN */
            {
                eth_frame_t ack_frame;
                uint16_t    ack_len = tcp_send_ack(g_rx_conn, &ack_frame);
                if (ack_len > 0)
                    nic_send_frame((const uint8_t *)&ack_frame, ack_len);
            }

            klog_puts("[NET] Remote FIN received — data transfer complete\r\n");
        }
    }
}

/* ------------------------------------------------------------------ */
/* net_init                                                            */
/* ------------------------------------------------------------------ */

void net_init(const net_config_t *config)
{
    if (!config) return;

    /* Copy caller's config into the global */
    g_net_config = *config;

    /* Initialise the NIC (fills g_nic, sets g_nic->mac) */
    nic_init();

    /* Override the local MAC with the one the NIC reports */
    nic_get_mac(g_net_config.local_mac);

    /* Initialise ARP with our confirmed IP and MAC */
    arp_init(g_net_config.local_ip, g_net_config.local_mac);

    /* Register our receive handler */
    nic_register_rx_handler(net_receive_handler);

    klog_puts("[NET] Network subsystem initialised\r\n");
    klog_puts("[NET] Local IP:  ");
    klog_ipv4(g_net_config.local_ip);
    klog_puts("\r\n[NET] Local MAC: ");
    klog_mac(g_net_config.local_mac);
    klog_puts("\r\n[NET] Gateway:   ");
    klog_ipv4(g_net_config.gateway_ip);
    klog_puts("\r\n");
}

/* ------------------------------------------------------------------ */
/* net_poll                                                            */
/* ------------------------------------------------------------------ */

void net_poll(void)
{
    nic_poll();
}

/* ------------------------------------------------------------------ */
/* net_tcp_connect                                                     */
/* ------------------------------------------------------------------ */

/*
 * Spin-wait iteration limits.
 * In a real OS these would be driven by a hardware timer.
 */
#define NET_CONNECT_TIMEOUT  1000000U
#define NET_ARP_TIMEOUT       500000U

bool net_tcp_connect(tcp_conn_t *conn,
                     uint16_t local_port,
                     uint32_t remote_ip,
                     uint16_t remote_port)
{
    eth_frame_t  syn_frame;
    uint16_t     syn_len;
    uint32_t     timeout;
    uint32_t     next_hop;
    uint8_t      resolved_mac[ETH_ALEN];

    if (!conn) return false;

    /* --------------------------------------------------------------- */
    /* ARP: resolve the next-hop MAC address                           */
    /* --------------------------------------------------------------- */

    /*
     * Determine the next-hop IP:
     *   - Same subnet → ARP for the destination directly.
     *   - Different subnet → ARP for the gateway.
     */
    if ((remote_ip & g_net_config.netmask) ==
        (g_net_config.local_ip & g_net_config.netmask))
        next_hop = remote_ip;
    else
        next_hop = g_net_config.gateway_ip;

    if (!arp_cache_lookup(next_hop, resolved_mac)) {
        /* Cache miss — send an ARP request and wait for a reply */
        arp_send_request(next_hop);

        for (timeout = 0; timeout < NET_ARP_TIMEOUT; timeout++) {
            net_poll();
            if (arp_cache_lookup(next_hop, resolved_mac))
                break;
        }

        if (!arp_cache_lookup(next_hop, resolved_mac)) {
            /*
             * ARP timed out.  Fall back to the statically configured
             * gateway MAC so the stack remains functional in stub/test
             * mode (where no real ARP reply ever arrives).
             */
            klog_puts("[NET] ARP timeout — using configured gateway MAC\r\n");
            {
                int i;
                for (i = 0; i < ETH_ALEN; i++)
                    resolved_mac[i] = g_net_config.gateway_mac[i];
            }
        }
    }

    klog_puts("[NET] Next-hop MAC: ");
    klog_mac(resolved_mac);
    klog_puts("\r\n");

    /* --------------------------------------------------------------- */
    /* Initialise the connection with the resolved MAC                 */
    /* --------------------------------------------------------------- */
    tcp_conn_init(conn,
                  g_net_config.local_ip, local_port,
                  remote_ip, remote_port,
                  g_net_config.local_mac,
                  resolved_mac);

    /* --- Phase 1: Send SYN --- */
    syn_len = tcp_send_syn(conn, &syn_frame);
    if (syn_len == 0) {
        klog_puts("[NET] Failed to build SYN segment\r\n");
        return false;
    }

    klog_puts("[NET] Sending SYN to ");
    klog_ipv4(remote_ip);
    klog_puts(":");
    klog_udec(remote_port);
    klog_puts("\r\n");

    eth_print_frame(&syn_frame, syn_len);

    if (!nic_send_frame((const uint8_t *)&syn_frame, syn_len)) {
        klog_puts("[NET] NIC failed to transmit SYN\r\n");
        return false;
    }

    /* --- Phase 2: Wait for SYN-ACK --- */
    g_pending_conn    = conn;
    g_synack_received = false;

    for (timeout = 0; timeout < NET_CONNECT_TIMEOUT; timeout++) {
        net_poll();
        if (g_synack_received)
            break;
    }

    g_pending_conn = NULL;

    if (!g_synack_received) {
        klog_puts("[NET] TCP connect timeout — no SYN-ACK received\r\n");
        return false;
    }

    klog_puts("[NET] TCP connection ESTABLISHED\r\n");
    return true;
}

/* ------------------------------------------------------------------ */
/* net_tcp_send                                                        */
/* ------------------------------------------------------------------ */

bool net_tcp_send(tcp_conn_t *conn,
                  const uint8_t *data,
                  uint16_t data_len)
{
    eth_frame_t data_frame;
    uint16_t    frame_len;

    if (!conn || !data || data_len == 0) return false;
    if (conn->state != TCP_STATE_ESTABLISHED) return false;

    frame_len = tcp_send_data(conn, data, data_len, &data_frame);
    if (frame_len == 0) return false;

    klog_puts("[NET] Sending TCP payload (");
    klog_udec(data_len);
    klog_puts(" bytes)\r\n");
    eth_print_frame(&data_frame, frame_len);

    return nic_send_frame((const uint8_t *)&data_frame, frame_len);
}

/* ------------------------------------------------------------------ */
/* net_tcp_close                                                       */
/* ------------------------------------------------------------------ */

void net_tcp_close(tcp_conn_t *conn)
{
    eth_frame_t fin_frame;
    uint16_t    frame_len;

    if (!conn) return;
    if (conn->state != TCP_STATE_ESTABLISHED) return;

    frame_len = tcp_send_fin(conn, &fin_frame);
    if (frame_len == 0) return;

    klog_puts("[NET] Sending FIN\r\n");
    eth_print_frame(&fin_frame, frame_len);

    nic_send_frame((const uint8_t *)&fin_frame, frame_len);
}

/* ------------------------------------------------------------------ */
/* net_tcp_recv                                                        */
/* ------------------------------------------------------------------ */

uint16_t net_tcp_recv(tcp_conn_t *conn,
                      uint8_t    *buf,
                      uint16_t    capacity,
                      uint32_t    timeout)
{
    uint32_t i;

    if (!conn || !buf || capacity == 0) return 0;
    if (conn->state != TCP_STATE_ESTABLISHED) return 0;

    /* Register this connection as the current data receiver */
    g_rx_conn     = conn;
    g_rx_buf      = buf;
    g_rx_capacity = capacity;
    g_rx_len      = 0;
    g_rx_done     = false;

    /* Spin-poll until we receive a FIN or the timeout expires */
    for (i = 0; i < timeout; i++) {
        net_poll();
        if (g_rx_done)
            break;
    }

    /* Deregister the receive connection */
    g_rx_conn = NULL;
    g_rx_buf  = NULL;

    klog_puts("[NET] TCP recv done: ");
    klog_udec(g_rx_len);
    klog_puts(" bytes received\r\n");

    return g_rx_len;
}
