/*
 * net.h - High-level network interface for VESPER OS kernel
 *
 * This is the single entry point the kernel (and any future application
 * layer) uses to access networking.  It hides the Ethernet / IP / TCP
 * implementation details and exposes a simple connection-oriented API.
 *
 * Typical usage:
 *
 *   net_init();
 *   tcp_conn_t conn;
 *   net_tcp_connect(&conn, local_ip, local_port, remote_ip, remote_port);
 *   net_tcp_send(&conn, "Hello from VESPER", 17);
 *   net_tcp_close(&conn);
 *
 * The kernel must call net_poll() regularly to process incoming packets.
 */

#ifndef VESPER_NET_H
#define VESPER_NET_H

#include "types.h"
#include "tcp.h"

/* ------------------------------------------------------------------ */
/* Global network configuration                                        */
/* ------------------------------------------------------------------ */

/*
 * net_config_t - Static network configuration
 *
 * In the absence of DHCP the kernel administrator hard-codes these
 * values before calling net_init().
 */
typedef struct {
    uint32_t local_ip;          /* Our IPv4 address (host byte order)    */
    uint32_t gateway_ip;        /* Default gateway (host byte order)     */
    uint32_t netmask;           /* Subnet mask (host byte order)         */
    uint8_t  local_mac[6];      /* Our MAC address (set from NIC)        */
    uint8_t  gateway_mac[6];    /* Gateway MAC (static ARP for now)      */
} net_config_t;

/* The single global network configuration instance */
extern net_config_t g_net_config;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * net_init - Initialise the entire network subsystem
 *
 * Initialises the NIC driver, populates g_net_config.local_mac from
 * the hardware, and prepares internal state.  Must be called once at
 * boot before any other net_* functions.
 *
 * @config : caller-filled config struct (local_ip, gateway_ip,
 *           netmask, gateway_mac must be set before calling)
 */
void net_init(const net_config_t *config);

/*
 * net_poll - Process pending incoming packets
 *
 * Drives the NIC receive logic and dispatches frames up the stack.
 * Must be called frequently from the kernel main loop (or an interrupt
 * handler) to ensure timely packet processing.
 */
void net_poll(void);

/*
 * net_tcp_connect - Perform a TCP three-way handshake with a remote host
 *
 * Builds and transmits a SYN, then polls for the SYN-ACK, then sends
 * the final ACK.  Uses a simple spin-wait loop suitable for bare-metal
 * (no scheduler required).
 *
 * @conn        : caller-allocated tcp_conn_t that will be populated
 * @local_port  : source TCP port (host byte order)
 * @remote_ip   : destination IPv4 address (host byte order)
 * @remote_port : destination TCP port (host byte order)
 *
 * Returns true if ESTABLISHED, false on timeout or error.
 */
bool net_tcp_connect(tcp_conn_t *conn,
                     uint16_t local_port,
                     uint32_t remote_ip,
                     uint16_t remote_port);

/*
 * net_tcp_send - Send a data payload over an ESTABLISHED TCP connection
 *
 * @conn     : connection in ESTABLISHED state
 * @data     : pointer to the bytes to transmit
 * @data_len : number of bytes to transmit
 *
 * Returns true on success.
 */
bool net_tcp_send(tcp_conn_t *conn,
                  const uint8_t *data,
                  uint16_t data_len);

/*
 * net_tcp_close - Gracefully close a TCP connection (send FIN)
 *
 * @conn : connection to close
 */
void net_tcp_close(tcp_conn_t *conn);

/*
 * net_receive_handler - Internal RX callback registered with the NIC
 *
 * This is called by the NIC driver for each received frame.  It parses
 * the frame up the stack and updates any waiting connection state.
 * Exposed in the header so the NIC driver can call it directly.
 */
void net_receive_handler(const uint8_t *frame, uint16_t length);

#endif /* VESPER_NET_H */
