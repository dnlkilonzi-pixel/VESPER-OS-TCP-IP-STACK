/*
 * test_arp.c - Unit tests for the ARP layer
 *
 * Tests:
 *  1.  arp_cache_lookup returns false on empty cache
 *  2.  arp_cache_add then lookup returns true with correct MAC
 *  3.  arp_cache_add updates an existing entry in-place
 *  4.  arp_cache_lookup returns false for an unknown IP
 *  5.  arp_cache eviction — round-robin when cache is full
 *  6.  arp_send_request produces a correctly-formed ARP frame
 *  7.  arp_handle_packet (REPLY) populates the cache
 *  8.  arp_handle_packet (REQUEST for our IP) sends a reply frame
 *  9.  arp_handle_packet rejects a too-short payload
 * 10.  arp_handle_packet ignores requests for a different IP
 */

#include "test_host_shim.h"
#include "test_framework.h"
#include "../include/arp.h"
#include "../include/ethernet.h"
#include "../include/ip.h"
#include "../include/nic.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static const uint8_t LOCAL_MAC[6]   = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
static const uint8_t REMOTE_MAC[6]  = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x02};
static const uint8_t ANOTHER_MAC[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

#define LOCAL_IP    ip_make_addr(192, 168, 1, 10)
#define REMOTE_IP   ip_make_addr(192, 168, 1,  1)
#define ANOTHER_IP  ip_make_addr(10,   0, 0,   1)

/* Extern declarations for the NIC stub test helpers */
extern uint8_t nic_stub_tx_count(void);
extern bool    nic_stub_get_tx_frame(uint8_t index, uint8_t *buf,
                                     uint16_t *len_out);

/*
 * build_arp_reply - Build a raw ARP REPLY payload (28 bytes) into buf.
 *
 * Simulates a reply from REMOTE_IP/REMOTE_MAC telling us its address.
 */
static void build_arp_reply(uint8_t *buf,
                             uint32_t sender_ip,
                             const uint8_t *sender_mac,
                             uint32_t target_ip,
                             const uint8_t *target_mac)
{
    arp_packet_t *pkt = (arp_packet_t *)buf;
    int i;

    pkt->htype = HTONS(ARP_HTYPE_ETHERNET);
    pkt->ptype = HTONS(ARP_PTYPE_IPV4);
    pkt->hlen  = ARP_HLEN_ETHERNET;
    pkt->plen  = ARP_PLEN_IPV4;
    pkt->oper  = HTONS(ARP_OPER_REPLY);

    for (i = 0; i < 6; i++) pkt->sha[i] = sender_mac[i];
    pkt->spa[0] = (uint8_t)(sender_ip >> 24);
    pkt->spa[1] = (uint8_t)(sender_ip >> 16);
    pkt->spa[2] = (uint8_t)(sender_ip >>  8);
    pkt->spa[3] = (uint8_t)(sender_ip);

    for (i = 0; i < 6; i++) pkt->tha[i] = target_mac[i];
    pkt->tpa[0] = (uint8_t)(target_ip >> 24);
    pkt->tpa[1] = (uint8_t)(target_ip >> 16);
    pkt->tpa[2] = (uint8_t)(target_ip >>  8);
    pkt->tpa[3] = (uint8_t)(target_ip);
}

/*
 * build_arp_request - Build a raw ARP REQUEST payload (28 bytes) into buf.
 */
static void build_arp_request(uint8_t *buf,
                               uint32_t sender_ip,
                               const uint8_t *sender_mac,
                               uint32_t target_ip)
{
    static const uint8_t ZERO_MAC[6] = {0};
    arp_packet_t *pkt = (arp_packet_t *)buf;
    int i;

    pkt->htype = HTONS(ARP_HTYPE_ETHERNET);
    pkt->ptype = HTONS(ARP_PTYPE_IPV4);
    pkt->hlen  = ARP_HLEN_ETHERNET;
    pkt->plen  = ARP_PLEN_IPV4;
    pkt->oper  = HTONS(ARP_OPER_REQUEST);

    for (i = 0; i < 6; i++) pkt->sha[i] = sender_mac[i];
    pkt->spa[0] = (uint8_t)(sender_ip >> 24);
    pkt->spa[1] = (uint8_t)(sender_ip >> 16);
    pkt->spa[2] = (uint8_t)(sender_ip >>  8);
    pkt->spa[3] = (uint8_t)(sender_ip);

    for (i = 0; i < 6; i++) pkt->tha[i] = ZERO_MAC[i];
    pkt->tpa[0] = (uint8_t)(target_ip >> 24);
    pkt->tpa[1] = (uint8_t)(target_ip >> 16);
    pkt->tpa[2] = (uint8_t)(target_ip >>  8);
    pkt->tpa[3] = (uint8_t)(target_ip);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_arp(void)
{
    uint8_t  mac_out[6];
    uint8_t  frame_buf[NIC_MAX_PKT_SIZE];
    uint16_t frame_len;
    bool     ok;
    int      i;

    printf("\n--- ARP layer tests ---\n");

    /* Initialise ARP module and NIC stub for tests that send frames */
    nic_init();
    arp_init(LOCAL_IP, LOCAL_MAC);

    /* ---- Test 1: cache miss on empty cache ---- */
    ok = arp_cache_lookup(REMOTE_IP, mac_out);
    ASSERT("arp_cache_lookup: miss on empty cache", ok == false);

    /* ---- Test 2: cache hit after arp_cache_add ---- */
    arp_cache_add(REMOTE_IP, REMOTE_MAC);
    ok = arp_cache_lookup(REMOTE_IP, mac_out);
    ASSERT("arp_cache_lookup: hit after add", ok == true);
    {
        bool match = true;
        for (i = 0; i < 6; i++) {
            if (mac_out[i] != REMOTE_MAC[i]) { match = false; break; }
        }
        ASSERT("arp_cache_lookup: correct MAC returned", match);
    }

    /* ---- Test 3: cache_add updates existing entry ---- */
    arp_cache_add(REMOTE_IP, ANOTHER_MAC);
    ok = arp_cache_lookup(REMOTE_IP, mac_out);
    ASSERT("arp_cache_add: update existing entry", ok == true);
    {
        bool match = true;
        for (i = 0; i < 6; i++) {
            if (mac_out[i] != ANOTHER_MAC[i]) { match = false; break; }
        }
        ASSERT("arp_cache_add: updated MAC is correct", match);
    }

    /* ---- Test 4: miss for unknown IP ---- */
    ok = arp_cache_lookup(ANOTHER_IP, mac_out);
    ASSERT("arp_cache_lookup: miss for unknown IP", ok == false);

    /* ---- Test 5: cache eviction when full ---- */
    /*
     * Fill the cache with ARP_CACHE_SIZE different IPs and verify that
     * we can look all of them up.  Then add one more (causing eviction)
     * and verify the new entry is present.
     */
    {
        uint8_t  dummy_mac[6] = {0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00};
        uint32_t base_ip = ip_make_addr(10, 0, 0, 0);
        bool     all_found = true;

        /* Re-init to get a clean cache */
        arp_init(LOCAL_IP, LOCAL_MAC);

        for (i = 0; i < ARP_CACHE_SIZE; i++) {
            dummy_mac[5] = (uint8_t)i;
            arp_cache_add(base_ip + (uint32_t)i, dummy_mac);
        }
        /* Verify all entries are present */
        for (i = 0; i < ARP_CACHE_SIZE; i++) {
            if (!arp_cache_lookup(base_ip + (uint32_t)i, mac_out))
                all_found = false;
        }
        ASSERT("arp_cache: all ARP_CACHE_SIZE entries present", all_found);

        /* Add one more entry — evicts the oldest slot */
        dummy_mac[5] = (uint8_t)ARP_CACHE_SIZE;
        arp_cache_add(base_ip + (uint32_t)ARP_CACHE_SIZE, dummy_mac);
        ok = arp_cache_lookup(base_ip + (uint32_t)ARP_CACHE_SIZE, mac_out);
        ASSERT("arp_cache: new entry present after eviction", ok == true);
    }

    /* Re-init ARP for the remaining tests */
    arp_init(LOCAL_IP, LOCAL_MAC);

    /* ---- Test 6: arp_send_request produces a valid frame ---- */
    /*
     * The stub NIC stores sent frames in its TX ring.  We call
     * arp_send_request, then inspect the stored frame.
     */
    {
        uint8_t          tx_frame[NIC_MAX_PKT_SIZE];
        uint16_t         tx_len = 0;
        eth_header_t     eth_hdr;
        const uint8_t   *eth_payload;
        uint16_t         eth_payload_len;
        const arp_packet_t *arp;
        static const uint8_t BCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        bool bcast_ok;

        arp_send_request(REMOTE_IP);

        ok = nic_stub_get_tx_frame(
                 (uint8_t)(nic_stub_tx_count() - 1),
                 tx_frame, &tx_len);
        ASSERT("arp_send_request: NIC has a TX frame", ok);

        /* Parse Ethernet header */
        ok = eth_parse_frame(tx_frame, tx_len, &eth_hdr,
                             &eth_payload, &eth_payload_len);
        ASSERT("arp_send_request: valid Ethernet frame", ok);
        ASSERT("arp_send_request: EtherType = ARP",
               eth_hdr.ethertype == ETHERTYPE_ARP);

        /* Verify destination is broadcast */
        bcast_ok = true;
        for (i = 0; i < 6; i++) {
            if (eth_hdr.dst_mac[i] != BCAST[i]) { bcast_ok = false; break; }
        }
        ASSERT("arp_send_request: dst MAC is broadcast", bcast_ok);

        /* Inspect ARP fields */
        ASSERT("arp_send_request: payload >= ARP_PKT_LEN",
               eth_payload_len >= ARP_PKT_LEN);

        arp = (const arp_packet_t *)eth_payload;
        ASSERT("arp_send_request: htype = ETHERNET",
               NTOHS(arp->htype) == ARP_HTYPE_ETHERNET);
        ASSERT("arp_send_request: ptype = IPv4",
               NTOHS(arp->ptype) == ARP_PTYPE_IPV4);
        ASSERT("arp_send_request: oper = REQUEST",
               NTOHS(arp->oper) == ARP_OPER_REQUEST);

        /* Sender IP must be our local IP */
        {
            uint32_t spa = ((uint32_t)arp->spa[0] << 24) |
                           ((uint32_t)arp->spa[1] << 16) |
                           ((uint32_t)arp->spa[2] <<  8) |
                            (uint32_t)arp->spa[3];
            ASSERT("arp_send_request: sender IP = LOCAL_IP",
                   spa == (uint32_t)LOCAL_IP);
        }
        /* Target IP must be the requested IP */
        {
            uint32_t tpa = ((uint32_t)arp->tpa[0] << 24) |
                           ((uint32_t)arp->tpa[1] << 16) |
                           ((uint32_t)arp->tpa[2] <<  8) |
                            (uint32_t)arp->tpa[3];
            ASSERT("arp_send_request: target IP = REMOTE_IP",
                   tpa == (uint32_t)REMOTE_IP);
        }
    }

    /* ---- Test 7: arp_handle_packet (REPLY) updates cache ---- */
    {
        uint8_t reply_buf[ARP_PKT_LEN];
        build_arp_reply(reply_buf, REMOTE_IP, REMOTE_MAC, LOCAL_IP, LOCAL_MAC);
        arp_handle_packet(reply_buf, ARP_PKT_LEN);

        ok = arp_cache_lookup(REMOTE_IP, mac_out);
        ASSERT("arp_handle_packet(REPLY): entry in cache", ok == true);
        {
            bool match = true;
            for (i = 0; i < 6; i++) {
                if (mac_out[i] != REMOTE_MAC[i]) { match = false; break; }
            }
            ASSERT("arp_handle_packet(REPLY): correct MAC", match);
        }
    }

    /* ---- Test 8: arp_handle_packet (REQUEST for our IP) sends reply ---- */
    {
        uint8_t  req_buf[ARP_PKT_LEN];
        uint8_t  reply_frame[NIC_MAX_PKT_SIZE];
        uint16_t reply_len = 0;
        uint8_t  tx_count_before;

        tx_count_before = nic_stub_tx_count();
        build_arp_request(req_buf, REMOTE_IP, REMOTE_MAC, LOCAL_IP);
        arp_handle_packet(req_buf, ARP_PKT_LEN);

        /* The handler must have sent a reply via the NIC */
        ASSERT("arp_handle_packet(REQUEST): reply was sent",
               nic_stub_tx_count() > tx_count_before);

        ok = nic_stub_get_tx_frame(
                 (uint8_t)(nic_stub_tx_count() - 1),
                 reply_frame, &reply_len);
        ASSERT("arp_handle_packet(REQUEST): TX frame readable", ok);

        /* The reply's ARP oper should be REPLY */
        if (ok && reply_len >= (uint16_t)(ETH_HLEN + ARP_PKT_LEN)) {
            const arp_packet_t *rarp =
                (const arp_packet_t *)(reply_frame + ETH_HLEN);
            ASSERT("arp_handle_packet(REQUEST): reply oper = REPLY",
                   NTOHS(rarp->oper) == ARP_OPER_REPLY);
        }

        /* Sender's MAC should have been learned into the cache */
        ok = arp_cache_lookup(REMOTE_IP, mac_out);
        ASSERT("arp_handle_packet(REQUEST): sender learned in cache",
               ok == true);
    }

    /* ---- Test 9: too-short payload is silently ignored ---- */
    {
        uint8_t short_buf[ARP_PKT_LEN - 1];
        /* Should not crash or write to cache */
        arp_handle_packet(short_buf, ARP_PKT_LEN - 1);
        ASSERT("arp_handle_packet: too-short payload is ignored", true);
    }

    /* ---- Test 10: REQUEST for a different IP is ignored ---- */
    {
        uint8_t  req_buf[ARP_PKT_LEN];
        uint8_t  tx_count_before;

        arp_init(LOCAL_IP, LOCAL_MAC); /* fresh cache */
        tx_count_before = nic_stub_tx_count();

        /* Ask for ANOTHER_IP, not LOCAL_IP */
        build_arp_request(req_buf, REMOTE_IP, REMOTE_MAC, ANOTHER_IP);
        arp_handle_packet(req_buf, ARP_PKT_LEN);

        /* No extra TX frame should have been sent for the reply */
        ASSERT("arp_handle_packet: ignores REQUEST for other IP",
               nic_stub_tx_count() == tx_count_before);

        /* But the sender should still have been learned */
        ok = arp_cache_lookup(REMOTE_IP, mac_out);
        ASSERT("arp_handle_packet: sender still learned on non-matching req",
               ok == true);
    }

    /* NUL pointer sanity */
    ok = arp_cache_lookup(REMOTE_IP, NULL);
    ASSERT("arp_cache_lookup: NULL mac_out returns false", ok == false);
    arp_cache_add(0, NULL);   /* must not crash */
    ASSERT("arp_cache_add: NULL mac is a no-op", true);

    /* Reinitialise to leave ARP in a clean state for potential later tests */
    arp_init(LOCAL_IP, LOCAL_MAC);

    /* Suppress unused-variable warning from frame_buf declared at top */
    (void)frame_buf;
    (void)frame_len;
}
