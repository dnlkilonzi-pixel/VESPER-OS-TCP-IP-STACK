/*
 * tcp.h - TCP header and state machine definitions for VESPER OS
 *
 * Implements the Transmission Control Protocol as specified in RFC 793.
 * The tcp_header_t struct maps exactly to the 20-byte fixed TCP header
 * (without options) so that pointer casts work for both building and
 * parsing packets.
 *
 * TCP segment header layout (20 bytes, no options):
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef VESPER_TCP_H
#define VESPER_TCP_H

#include "types.h"
#include "ip.h"
#include "ethernet.h"

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define TCP_HLEN            20      /* Fixed TCP header length (bytes) */
#define TCP_DATA_OFFSET_MIN 5       /* Data offset = 5 × 4 = 20 bytes  */
#define TCP_DEFAULT_WINDOW  65535   /* Default receive window size      */

/* TCP control flag bits (stored in the low byte of data_offset_flags) */
#define TCP_FLAG_FIN  (1 << 0)   /* No more data from sender          */
#define TCP_FLAG_SYN  (1 << 1)   /* Synchronise sequence numbers      */
#define TCP_FLAG_RST  (1 << 2)   /* Reset the connection              */
#define TCP_FLAG_PSH  (1 << 3)   /* Push buffered data to application */
#define TCP_FLAG_ACK  (1 << 4)   /* Acknowledgment field is valid     */
#define TCP_FLAG_URG  (1 << 5)   /* Urgent pointer field is valid     */

/* ------------------------------------------------------------------ */
/* TCP header structure                                                */
/* ------------------------------------------------------------------ */

/*
 * tcp_header_t - Fixed 20-byte TCP segment header
 *
 * All multi-byte fields are in network byte order (big-endian).
 * The data_offset_flags field encodes:
 *   [15:12] Data offset (header length in 32-bit words; min = 5)
 *   [11:6]  Reserved — must be zero
 *   [5:0]   Control flags (URG, ACK, PSH, RST, SYN, FIN)
 */
typedef struct {
    uint16_t src_port;          /* Source port (network byte order)       */
    uint16_t dst_port;          /* Destination port (network byte order)  */
    uint32_t seq_num;           /* Sequence number (network byte order)   */
    uint32_t ack_num;           /* Acknowledgment number (net byte order) */
    uint16_t data_offset_flags; /* [15:12]=offset, [5:0]=flags            */
    uint16_t window;            /* Receive window size (network order)    */
    uint16_t checksum;          /* Checksum over pseudo-hdr + TCP segment */
    uint16_t urgent_ptr;        /* Urgent pointer (only valid if URG set) */
} __attribute__((packed)) tcp_header_t;

/* TCP flags mask (bits [5:0] of the data_offset_flags field) */
#define TCP_FLAGS_MASK  0x003F

/* ------------------------------------------------------------------ */
/* TCP connection state machine                                         */
/* ------------------------------------------------------------------ */

/*
 * tcp_state_t - Minimal subset of RFC 793 TCP states
 *
 * We implement only the states needed for a client performing a
 * three-way handshake and sending data:
 *
 *   CLOSED → [send SYN] → SYN_SENT
 *   SYN_SENT → [receive SYN-ACK, send ACK] → ESTABLISHED
 *   ESTABLISHED → [send/receive data] → ESTABLISHED
 *   ESTABLISHED → [send FIN] → FIN_WAIT_1
 *   FIN_WAIT_1 → [receive FIN-ACK] → TIME_WAIT
 *   TIME_WAIT → [timeout] → CLOSED
 */
typedef enum {
    TCP_STATE_CLOSED       = 0,
    TCP_STATE_LISTEN       = 1,
    TCP_STATE_SYN_SENT     = 2,
    TCP_STATE_SYN_RECEIVED = 3,
    TCP_STATE_ESTABLISHED  = 4,
    TCP_STATE_FIN_WAIT_1   = 5,
    TCP_STATE_FIN_WAIT_2   = 6,
    TCP_STATE_TIME_WAIT    = 7,
    TCP_STATE_CLOSE_WAIT   = 8,
    TCP_STATE_LAST_ACK     = 9,
} tcp_state_t;

/* Human-readable state name (for logging) */
const char *tcp_state_name(tcp_state_t state);

/* TCP flags mask (bits [5:0] of data_offset_flags) */
#define TCP_FLAGS_MASK 0x003F
/* ------------------------------------------------------------------ */

/*
 * tcp_conn_t - Represents a single TCP connection (client side)
 *
 * Tracks all per-connection variables needed by the state machine:
 *  - addressing (local/remote IP and port)
 *  - sequence numbers (send and receive)
 *  - current state
 *  - MAC addresses needed to hand frames to the Ethernet layer
 */
typedef struct {
    /* Network addressing */
    uint32_t local_ip;      /* Our IP address (host byte order)           */
    uint32_t remote_ip;     /* Remote IP address (host byte order)        */
    uint16_t local_port;    /* Our TCP port (host byte order)             */
    uint16_t remote_port;   /* Remote TCP port (host byte order)          */

    /* MAC addresses for Ethernet framing */
    uint8_t  local_mac[6];  /* Our NIC MAC address                        */
    uint8_t  remote_mac[6]; /* Next-hop (gateway or peer) MAC address     */

    /* Sequence number tracking */
    uint32_t snd_isn;       /* Initial send sequence number               */
    uint32_t snd_nxt;       /* Next sequence number to send               */
    uint32_t rcv_nxt;       /* Next sequence number expected from remote  */
    uint32_t rcv_wnd;       /* Receive window advertised to remote        */

    /* State machine */
    tcp_state_t state;      /* Current connection state                   */
} tcp_conn_t;

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
 * tcp_build_segment - Construct a TCP segment inside a pre-allocated
 *                     Ethernet + IP buffer.
 *
 * The caller must provide a buffer large enough for the full frame:
 *   ETH_HLEN + IP_HLEN + TCP_HLEN + payload_len bytes.
 *
 * @conn        : connection context (provides addressing + seq numbers)
 * @flags       : TCP control flags (TCP_FLAG_SYN | TCP_FLAG_ACK etc.)
 * @payload     : data to include after the TCP header (may be NULL)
 * @payload_len : byte count of the payload
 * @out_frame   : caller-allocated Ethernet frame buffer to write into
 *
 * Returns total Ethernet frame length on success, 0 on error.
 */
uint16_t tcp_build_segment(const tcp_conn_t *conn,
                           uint16_t flags,
                           const uint8_t *payload,
                           uint16_t payload_len,
                           eth_frame_t *out_frame);

/*
 * tcp_checksum - Compute the TCP checksum over the pseudo-header and
 *               TCP segment (RFC 793 §3.1).
 *
 * The pseudo-header includes:
 *   source IP (4), destination IP (4), zero (1), protocol=6 (1),
 *   TCP length (2).
 *
 * @src_ip   : source IPv4 address (host byte order)
 * @dst_ip   : destination IPv4 address (host byte order)
 * @tcp_seg  : pointer to the TCP header + data
 * @tcp_len  : total byte count of TCP header + data
 *
 * Returns the 16-bit checksum (network byte order).
 */
uint16_t tcp_checksum(uint32_t src_ip, uint32_t dst_ip,
                      const void *tcp_seg, uint16_t tcp_len);

/*
 * tcp_parse_segment - Parse a raw buffer as a TCP segment
 *
 * @buf        : raw bytes starting at the TCP header
 * @len        : total bytes available in buf
 * @header     : output — filled with parsed TCP header
 * @payload    : output pointer — points to data payload inside buf
 * @payload_len: output — byte count of the payload
 *
 * Returns true on success, false if the buffer is too short or malformed.
 */
bool tcp_parse_segment(const uint8_t *buf,
                       uint16_t len,
                       tcp_header_t *header,
                       const uint8_t **payload,
                       uint16_t *payload_len);

/*
 * tcp_print_segment - Log a TCP segment header to the kernel console
 */
void tcp_print_segment(const tcp_header_t *hdr);

/* ------------------------------------------------------------------ */
/* State machine helpers                                               */
/* ------------------------------------------------------------------ */

/*
 * tcp_conn_init - Initialise a tcp_conn_t with sensible defaults
 *
 * Sets state to CLOSED and populates addressing fields.
 */
void tcp_conn_init(tcp_conn_t *conn,
                   uint32_t local_ip,  uint16_t local_port,
                   uint32_t remote_ip, uint16_t remote_port,
                   const uint8_t *local_mac,
                   const uint8_t *remote_mac);

/*
 * tcp_send_syn - Build + transmit a SYN segment, advance state to SYN_SENT
 *
 * @conn      : initialised connection (state must be CLOSED)
 * @out_frame : buffer to write the Ethernet frame into
 *
 * Returns frame length on success, 0 on error.
 */
uint16_t tcp_send_syn(tcp_conn_t *conn, eth_frame_t *out_frame);

/*
 * tcp_handle_syn_ack - Process a received SYN-ACK, send ACK, enter ESTABLISHED
 *
 * @conn      : connection in SYN_SENT state
 * @buf       : raw buffer starting at the IP header of the received packet
 * @buf_len   : length of the received buffer
 * @out_frame : buffer to write the ACK Ethernet frame into
 *
 * Returns ACK frame length on success, 0 on error or invalid segment.
 */
uint16_t tcp_handle_syn_ack(tcp_conn_t *conn,
                            const uint8_t *buf,
                            uint16_t buf_len,
                            eth_frame_t *out_frame);

/*
 * tcp_send_data - Send a data segment on an ESTABLISHED connection
 *
 * @conn        : connection in ESTABLISHED state
 * @data        : payload bytes to send
 * @data_len    : payload length in bytes
 * @out_frame   : buffer to write the Ethernet frame into
 *
 * Returns frame length on success, 0 on error.
 */
uint16_t tcp_send_data(tcp_conn_t *conn,
                       const uint8_t *data,
                       uint16_t data_len,
                       eth_frame_t *out_frame);

/*
 * tcp_send_fin - Send a FIN segment to initiate connection tear-down
 *
 * @conn      : connection in ESTABLISHED state
 * @out_frame : buffer to write the Ethernet frame into
 *
 * Returns frame length on success, 0 on error.
 */
uint16_t tcp_send_fin(tcp_conn_t *conn, eth_frame_t *out_frame);

#endif /* VESPER_TCP_H */
