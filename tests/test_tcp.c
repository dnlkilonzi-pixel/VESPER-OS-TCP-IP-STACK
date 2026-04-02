/*
 * test_tcp.c - Unit tests for the TCP layer and state machine
 *
 * Tests:
 *  1. tcp_conn_init: state is CLOSED, sequence numbers set
 *  2. tcp_send_syn: builds a valid SYN frame, state → SYN_SENT
 *  3. tcp_send_syn: SYN flag set, ACK not set
 *  4. tcp_send_syn: seq_num = snd_isn, snd_nxt advanced by 1
 *  5. tcp_checksum: computing then verifying gives 0
 *  6. tcp_parse_segment: round-trip parse of the SYN segment
 *  7. tcp_handle_syn_ack: processing a crafted SYN-ACK → ESTABLISHED
 *  8. tcp_send_data: PSH+ACK segment, snd_nxt advanced
 *  9. tcp_send_fin: FIN+ACK segment, state → FIN_WAIT_1
 * 10. tcp_state_name: returns correct strings
 */

#include "test_host_shim.h"
#include "test_framework.h"
#include "../include/tcp.h"
#include "../include/ip.h"
#include "../include/ethernet.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static const uint8_t LOCAL_MAC[6]  = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
static const uint8_t REMOTE_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02};

#define LOCAL_IP    ip_make_addr(192, 168, 1, 10)
#define REMOTE_IP   ip_make_addr(192, 168, 1, 1)
#define LOCAL_PORT  49152
#define REMOTE_PORT 8080

/* ------------------------------------------------------------------ */
/* Helper: extract the TCP header from an Ethernet frame              */
/* ------------------------------------------------------------------ */

static bool get_tcp_hdr(const eth_frame_t *frame, uint16_t frame_len,
                        tcp_header_t *tcp_hdr)
{
    const uint8_t *eth_payload  = (const uint8_t *)frame + ETH_HLEN;
    uint16_t       eth_pay_len  = (uint16_t)(frame_len - ETH_HLEN);
    ip_header_t    ip_hdr;
    const uint8_t *ip_payload;
    uint16_t       ip_pay_len;
    const uint8_t *tcp_payload;
    uint16_t       tcp_pay_len;

    if (!ip_parse_packet(eth_payload, eth_pay_len,
                         &ip_hdr, &ip_payload, &ip_pay_len))
        return false;
    return tcp_parse_segment(ip_payload, ip_pay_len,
                             tcp_hdr, &tcp_payload, &tcp_pay_len);
}

/* ------------------------------------------------------------------ */
/* Helper: craft a SYN-ACK byte stream (raw IP packet, no Ethernet)   */
/* ------------------------------------------------------------------ */

static uint16_t make_synack(uint8_t *out, uint16_t out_size,
                            uint32_t remote_isn,
                            uint32_t ack_seq,
                            uint16_t src_port,
                            uint16_t dst_port)
{
    ip_header_t  *iph;
    tcp_header_t *tcph;
    uint16_t      tcp_len = TCP_HLEN; /* no payload */
    uint16_t      ip_total;

    if (out_size < (uint16_t)(IP_HLEN + tcp_len))
        return 0;

    ip_total = IP_HLEN + tcp_len;

    iph = (ip_header_t *)out;
    iph->version_ihl    = (4 << 4) | 5;
    iph->tos            = 0;
    iph->total_length   = HTONS(ip_total);
    iph->id             = HTONS(1);
    iph->flags_fragment = HTONS(0x4000); /* DF */
    iph->ttl            = 64;
    iph->protocol       = IP_PROTO_TCP;
    iph->checksum       = 0;
    iph->src_ip         = HTONL(REMOTE_IP);
    iph->dst_ip         = HTONL(LOCAL_IP);
    iph->checksum       = ip_checksum(iph, IP_HLEN);

    tcph = (tcp_header_t *)(out + IP_HLEN);
    tcph->src_port          = HTONS(src_port);
    tcph->dst_port          = HTONS(dst_port);
    tcph->seq_num           = HTONL(remote_isn);
    tcph->ack_num           = HTONL(ack_seq);
    tcph->data_offset_flags = HTONS((uint16_t)((5 << 12) |
                                    TCP_FLAG_SYN | TCP_FLAG_ACK));
    tcph->window            = HTONS(65535);
    tcph->checksum          = 0;
    tcph->urgent_ptr        = 0;
    tcph->checksum          = HTONS(tcp_checksum(REMOTE_IP, LOCAL_IP,
                                                 tcph, tcp_len));

    return ip_total;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_tcp(void)
{
    tcp_conn_t   conn;
    eth_frame_t  frame;
    tcp_header_t tcp_hdr;
    uint16_t     frame_len;
    uint16_t     flags;
    bool         ok;

    printf("\n--- TCP layer tests ---\n");

    /* ---- Test 1: tcp_conn_init ---- */
    tcp_conn_init(&conn,
                  LOCAL_IP,  LOCAL_PORT,
                  REMOTE_IP, REMOTE_PORT,
                  LOCAL_MAC, REMOTE_MAC);

    ASSERT("tcp_conn_init: state = CLOSED", conn.state == TCP_STATE_CLOSED);
    ASSERT("tcp_conn_init: local_ip correct",  conn.local_ip  == LOCAL_IP);
    ASSERT("tcp_conn_init: remote_ip correct", conn.remote_ip == REMOTE_IP);
    ASSERT("tcp_conn_init: snd_nxt = snd_isn",
           conn.snd_nxt == conn.snd_isn);

    /* ---- Test 2: tcp_send_syn builds a frame ---- */
    memset(&frame, 0, sizeof(frame));
    frame_len = tcp_send_syn(&conn, &frame);
    ASSERT("tcp_send_syn: returns non-zero length", frame_len > 0);

    /* ---- Test 3: state transitions to SYN_SENT ---- */
    ASSERT("tcp_send_syn: state = SYN_SENT",
           conn.state == TCP_STATE_SYN_SENT);

    /* ---- Test 4: snd_nxt advanced by 1 (SYN consumes a seq num) ---- */
    ASSERT("tcp_send_syn: snd_nxt = snd_isn + 1",
           conn.snd_nxt == conn.snd_isn + 1);

    /* ---- Test 5: SYN flag is set, ACK is NOT set ---- */
    ok = get_tcp_hdr(&frame, frame_len, &tcp_hdr);
    ASSERT("tcp_send_syn: parse succeeds", ok);
    flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;
    ASSERT("tcp_send_syn: SYN flag set",   (flags & TCP_FLAG_SYN) != 0);
    ASSERT("tcp_send_syn: ACK flag clear", (flags & TCP_FLAG_ACK) == 0);
    ASSERT("tcp_send_syn: src_port correct",
           tcp_hdr.src_port == LOCAL_PORT);
    ASSERT("tcp_send_syn: dst_port correct",
           tcp_hdr.dst_port == REMOTE_PORT);

    /* ---- Test 6: tcp_checksum verify ---- */
    {
        /*
         * Build a tiny TCP segment and verify that computing the checksum
         * and then re-verifying over the completed segment gives 0.
         */
        uint8_t seg_buf[TCP_HLEN] = {0};
        tcp_header_t *th = (tcp_header_t *)seg_buf;
        uint16_t csum;

        th->src_port          = HTONS(1234);
        th->dst_port          = HTONS(5678);
        th->seq_num           = HTONL(0x12345678);
        th->ack_num           = HTONL(0);
        th->data_offset_flags = HTONS((5 << 12) | TCP_FLAG_SYN);
        th->window            = HTONS(1024);
        th->checksum          = 0;
        th->urgent_ptr        = 0;

        csum = tcp_checksum(LOCAL_IP, REMOTE_IP, seg_buf, TCP_HLEN);
        th->checksum = HTONS(csum);

        ASSERT("tcp_checksum: verify after compute = 0",
               tcp_checksum(LOCAL_IP, REMOTE_IP, seg_buf, TCP_HLEN) == 0);
    }

    /* ---- Test 7: tcp_handle_syn_ack → ESTABLISHED ---- */
    {
        uint8_t  synack_buf[IP_HLEN + TCP_HLEN];
        uint16_t synack_len;
        eth_frame_t ack_frame;

        /* Craft a SYN-ACK that acknowledges our SYN */
        synack_len = make_synack(synack_buf, (uint16_t)sizeof(synack_buf),
                                 0xBEEF0000U,       /* remote ISN */
                                 conn.snd_nxt,      /* ack = our snd_nxt */
                                 REMOTE_PORT,
                                 LOCAL_PORT);
        ASSERT("make_synack: non-zero length", synack_len > 0);

        memset(&ack_frame, 0, sizeof(ack_frame));
        frame_len = tcp_handle_syn_ack(&conn,
                                       synack_buf, synack_len,
                                       &ack_frame);
        ASSERT("tcp_handle_syn_ack: returns non-zero frame", frame_len > 0);
        ASSERT("tcp_handle_syn_ack: state = ESTABLISHED",
               conn.state == TCP_STATE_ESTABLISHED);
        ASSERT("tcp_handle_syn_ack: rcv_nxt = remote_isn + 1",
               conn.rcv_nxt == 0xBEEF0001U);

        /* The ACK segment should have ACK set, SYN clear */
        ok = get_tcp_hdr(&ack_frame, frame_len, &tcp_hdr);
        ASSERT("tcp_handle_syn_ack: ACK parse ok", ok);
        flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;
        ASSERT("tcp_handle_syn_ack: ACK flag set",   (flags & TCP_FLAG_ACK) != 0);
        ASSERT("tcp_handle_syn_ack: SYN flag clear", (flags & TCP_FLAG_SYN) == 0);
    }

    /* ---- Test 8: tcp_send_data ---- */
    {
        static const uint8_t MSG[] = "Hello from VESPER";
        uint16_t data_len = (uint16_t)(sizeof(MSG) - 1);
        uint32_t seq_before = conn.snd_nxt;
        eth_frame_t data_frame;

        frame_len = tcp_send_data(&conn, MSG, data_len, &data_frame);
        ASSERT("tcp_send_data: returns non-zero frame", frame_len > 0);
        ASSERT("tcp_send_data: snd_nxt advanced by data_len",
               conn.snd_nxt == seq_before + data_len);

        ok = get_tcp_hdr(&data_frame, frame_len, &tcp_hdr);
        ASSERT("tcp_send_data: parse ok", ok);
        flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;
        ASSERT("tcp_send_data: PSH+ACK flags set",
               (flags & (TCP_FLAG_PSH | TCP_FLAG_ACK)) ==
               (TCP_FLAG_PSH | TCP_FLAG_ACK));
    }

    /* ---- Test 9: tcp_send_fin ---- */
    {
        uint32_t seq_before = conn.snd_nxt;
        eth_frame_t fin_frame;

        frame_len = tcp_send_fin(&conn, &fin_frame);
        ASSERT("tcp_send_fin: returns non-zero frame", frame_len > 0);
        ASSERT("tcp_send_fin: state = FIN_WAIT_1",
               conn.state == TCP_STATE_FIN_WAIT_1);
        ASSERT("tcp_send_fin: snd_nxt advanced by 1",
               conn.snd_nxt == seq_before + 1);

        ok = get_tcp_hdr(&fin_frame, frame_len, &tcp_hdr);
        ASSERT("tcp_send_fin: parse ok", ok);
        flags = tcp_hdr.data_offset_flags & TCP_FLAGS_MASK;
        ASSERT("tcp_send_fin: FIN flag set",  (flags & TCP_FLAG_FIN) != 0);
        ASSERT("tcp_send_fin: ACK flag set",  (flags & TCP_FLAG_ACK) != 0);
    }

    /* ---- Test 10: tcp_state_name ---- */
    ASSERT("tcp_state_name: CLOSED",
           strcmp(tcp_state_name(TCP_STATE_CLOSED), "CLOSED") == 0);
    ASSERT("tcp_state_name: ESTABLISHED",
           strcmp(tcp_state_name(TCP_STATE_ESTABLISHED), "ESTABLISHED") == 0);
    ASSERT("tcp_state_name: SYN_SENT",
           strcmp(tcp_state_name(TCP_STATE_SYN_SENT), "SYN_SENT") == 0);
}
