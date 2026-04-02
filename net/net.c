/*
 * net.c - High-level network interface for VESPER OS
 *
 * Implements the functions declared in include/net.h.
 *
 * This module ties together the NIC driver, Ethernet, IP and TCP layers
 * into a coherent subsystem.  It owns the global receive path and the
 * simple spin-wait TCP connect loop.
 */

#include "../include/net.h"
#include "../include/nic.h"
#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/tcp.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Global network configuration                                        */
/* ------------------------------------------------------------------ */

net_config_t g_net_config;

/* ------------------------------------------------------------------ */
/* Internal state                                                      */
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
    uint16_t frame_len;

    if (!frame || length < ETH_HLEN)
        return;

    /* Parse Ethernet header */
    if (!eth_parse_frame(frame, length, &eth_hdr,
                         &eth_payload, &eth_payload_len))
        return;

    /* We only handle IPv4 frames */
    if (eth_hdr.ethertype != ETHERTYPE_IP)
        return;

    /* Parse IP header */
    if (!ip_parse_packet(eth_payload, eth_payload_len, &ip_hdr,
                         &ip_payload, &ip_payload_len))
        return;

    /* Log the received IP packet */
    ip_print_packet(&ip_hdr);

    /* Only handle TCP for now */
    if (ip_hdr.protocol != IP_PROTO_TCP)
        return;

    /*
     * If there is a connection waiting for a SYN-ACK, try to process
     * this TCP segment as the response.
     */
    if (g_pending_conn && !g_synack_received) {
        frame_len = tcp_handle_syn_ack(g_pending_conn,
                                       eth_payload,
                                       eth_payload_len,
                                       &g_response_frame);
        if (frame_len > 0) {
            /* Deliver the ACK frame through the NIC */
            nic_send_frame((const uint8_t *)&g_response_frame, frame_len);
            eth_print_frame(&g_response_frame, frame_len);
            g_synack_received = true;
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
 * Simple spin-wait counter.
 * In a real OS this would be replaced by a proper timer / scheduler.
 * We iterate up to NET_CONNECT_TIMEOUT times, calling net_poll() each
 * iteration, before giving up.
 */
#define NET_CONNECT_TIMEOUT  1000000U

bool net_tcp_connect(tcp_conn_t *conn,
                     uint16_t local_port,
                     uint32_t remote_ip,
                     uint16_t remote_port)
{
    eth_frame_t  syn_frame;
    uint16_t     syn_len;
    uint32_t     timeout;

    if (!conn) return false;

    /* Initialise the connection structure */
    tcp_conn_init(conn,
                  g_net_config.local_ip, local_port,
                  remote_ip, remote_port,
                  g_net_config.local_mac,
                  g_net_config.gateway_mac);

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
    g_pending_conn   = conn;
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
