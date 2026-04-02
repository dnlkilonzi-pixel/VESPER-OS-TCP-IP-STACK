/*
 * test_ethernet.c - Unit tests for the Ethernet layer
 *
 * Tests:
 *  1. Frame construction: correct header fields
 *  2. Frame construction: payload is copied verbatim
 *  3. Frame construction: total length returned correctly
 *  4. Frame parsing: round-trip (build then parse)
 *  5. Frame parsing: rejects too-short buffer
 *  6. Byte-order: EtherType is stored big-endian on the wire
 *  7. MAC comparison and copy helpers
 */

#include "test_host_shim.h"
#include "test_framework.h"
#include "../include/ethernet.h"

/* ------------------------------------------------------------------ */
/* Test helpers                                                        */
/* ------------------------------------------------------------------ */

static const uint8_t SRC_MAC[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t DST_MAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static const uint8_t PAYLOAD[]  = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_ethernet(void)
{
    eth_frame_t  frame;
    eth_header_t parsed_hdr;
    const uint8_t *parsed_payload;
    uint16_t      parsed_payload_len;
    uint16_t      total_len;
    uint8_t       raw[ETH_MAX_FRAME];
    bool          ok;
    int           i;

    printf("\n--- Ethernet layer tests ---\n");

    /* --- Test 1: Build frame returns correct total length --- */
    memset(&frame, 0, sizeof(frame));
    total_len = eth_build_frame(&frame, DST_MAC, SRC_MAC,
                                ETHERTYPE_IP,
                                PAYLOAD, (uint16_t)sizeof(PAYLOAD));
    ASSERT("eth_build: total length = ETH_HLEN + payload",
           total_len == (uint16_t)(ETH_HLEN + sizeof(PAYLOAD)));

    /* --- Test 2: Destination MAC is set correctly --- */
    ASSERT("eth_build: dst_mac[0]", frame.header.dst_mac[0] == 0xAA);
    ASSERT("eth_build: dst_mac[5]", frame.header.dst_mac[5] == 0xFF);

    /* --- Test 3: Source MAC is set correctly --- */
    ASSERT("eth_build: src_mac[0]", frame.header.src_mac[0] == 0x11);
    ASSERT("eth_build: src_mac[5]", frame.header.src_mac[5] == 0x66);

    /* --- Test 4: EtherType stored in network (big-endian) byte order --- */
    /*
     * ETHERTYPE_IP = 0x0800 in host order.
     * In big-endian wire format the high byte (0x08) comes first.
     */
    ASSERT("eth_build: ethertype high byte = 0x08",
           ((uint8_t *)&frame.header.ethertype)[0] == 0x08);
    ASSERT("eth_build: ethertype low byte = 0x00",
           ((uint8_t *)&frame.header.ethertype)[1] == 0x00);

    /* --- Test 5: Payload bytes copied correctly --- */
    ok = true;
    for (i = 0; i < (int)sizeof(PAYLOAD); i++) {
        if (frame.payload[i] != PAYLOAD[i]) { ok = false; break; }
    }
    ASSERT("eth_build: payload bytes match", ok);

    /* --- Test 6: Parse frame — round-trip --- */
    /* Copy the frame into a raw byte buffer as if received from the NIC */
    memcpy(raw, &frame, total_len);

    ok = eth_parse_frame(raw, total_len, &parsed_hdr,
                         &parsed_payload, &parsed_payload_len);
    ASSERT("eth_parse: returns true on valid frame", ok);
    ASSERT("eth_parse: payload length correct",
           parsed_payload_len == (uint16_t)sizeof(PAYLOAD));

    /* After parsing, ethertype is returned in host byte order */
    ASSERT("eth_parse: ethertype = ETHERTYPE_IP",
           parsed_hdr.ethertype == ETHERTYPE_IP);

    /* --- Test 7: Parse rejects buffer shorter than ETH_HLEN --- */
    ok = eth_parse_frame(raw, ETH_HLEN - 1, &parsed_hdr,
                         &parsed_payload, &parsed_payload_len);
    ASSERT("eth_parse: rejects too-short buffer", ok == false);

    /* --- Test 8: mac_equal --- */
    ASSERT("mac_equal: same MAC",     mac_equal(SRC_MAC, SRC_MAC) == true);
    ASSERT("mac_equal: diff MAC",     mac_equal(SRC_MAC, DST_MAC) == false);

    /* --- Test 9: mac_copy --- */
    {
        uint8_t tmp[6] = {0};
        mac_copy(tmp, SRC_MAC);
        ASSERT("mac_copy: bytes match", memcmp(tmp, SRC_MAC, 6) == 0);
    }

    /* --- Test 10: NULL frame returns 0 --- */
    total_len = eth_build_frame(NULL, DST_MAC, SRC_MAC,
                                ETHERTYPE_IP, PAYLOAD,
                                (uint16_t)sizeof(PAYLOAD));
    ASSERT("eth_build: NULL frame returns 0", total_len == 0);
}
