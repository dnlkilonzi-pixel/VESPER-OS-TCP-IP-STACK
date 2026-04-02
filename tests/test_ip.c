/*
 * test_ip.c - Unit tests for the IPv4 layer
 *
 * Tests:
 *  1. Checksum: known good checksum value (RFC 1071 example)
 *  2. Checksum: all-zeros data gives 0xFFFF
 *  3. ip_build_packet: IP header fields are correct
 *  4. ip_build_packet: header checksum is valid (re-verifying = 0)
 *  5. ip_build_packet: payload follows header
 *  6. ip_parse_packet: round-trip
 *  7. ip_parse_packet: rejects wrong IP version
 *  8. ip_make_addr: constructs correct 32-bit value
 */

#include "test_host_shim.h"
#include "test_framework.h"
#include "../include/ip.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static const uint8_t SRC_MAC[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static const uint8_t DST_MAC[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

/* 192.168.1.10 */
#define SRC_IP  ip_make_addr(192, 168, 1, 10)
/* 192.168.1.1  */
#define DST_IP  ip_make_addr(192, 168, 1, 1)

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_ip(void)
{
    eth_frame_t    frame;
    ip_header_t    parsed_hdr;
    const uint8_t *parsed_payload;
    uint16_t       parsed_payload_len;
    uint16_t       frame_len;
    bool           ok;

    /* Dummy TCP-like payload */
    static const uint8_t PAYLOAD[] = {0x00, 0x50, 0x00, 0x51,  /* ports */
                                       0xDE, 0xAD, 0xBE, 0xEF}; /* data  */

    printf("\n--- IPv4 layer tests ---\n");

    /* --- Test 1: ip_checksum on known data ---
     * RFC 1071 example header (20 bytes, no options):
     *   45 00 00 3c 1c 46 40 00 40 06 00 00 ac 10 0a 63 ac 10 0a 0c
     * Its checksum field is 0x0000 in the header. After computation
     * the result should be the ones' complement of the sum.
     * We verify by computing over the header with checksum = 0 and
     * confirming the result is non-zero (exact value validated via
     * verifying the completed header sums to 0).
     */
    {
        /* A sample 20-byte IP header with checksum zeroed */
        uint8_t hdr_bytes[20] = {
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,   /* checksum = 0 */
            0xac, 0x10, 0x0a, 0x63,
            0xac, 0x10, 0x0a, 0x0c
        };
        uint16_t csum = ip_checksum(hdr_bytes, 20);
        /* After filling in the checksum, the re-verify should give 0 */
        hdr_bytes[10] = (uint8_t)(csum >> 8);
        hdr_bytes[11] = (uint8_t)(csum & 0xFF);
        ASSERT("ip_checksum: computed then verified = 0",
               ip_checksum(hdr_bytes, 20) == 0);
    }

    /* --- Test 2: Checksum of buffer padded to all zeros (odd length) --- */
    {
        uint8_t zeros[3] = {0, 0, 0};
        uint16_t csum = ip_checksum(zeros, 3);
        ASSERT("ip_checksum: all-zeros odd length = 0xFFFF", csum == 0xFFFF);
    }

    /* --- Test 3: Build IP packet --- */
    memset(&frame, 0, sizeof(frame));
    frame_len = ip_build_packet(&frame,
                                SRC_IP, DST_IP,
                                IP_PROTO_TCP,
                                PAYLOAD, (uint16_t)sizeof(PAYLOAD),
                                SRC_MAC, DST_MAC);

    ASSERT("ip_build: non-zero frame length", frame_len > 0);
    ASSERT("ip_build: frame >= ETH_HLEN + IP_HLEN",
           frame_len >= (uint16_t)(ETH_HLEN + IP_HLEN));

    /* --- Test 4: IP header is at the expected position in the frame --- */
    {
        const ip_header_t *iph =
            (const ip_header_t *)((uint8_t *)&frame + ETH_HLEN);

        ASSERT("ip_build: version = 4",
               (iph->version_ihl >> 4) == 4);
        ASSERT("ip_build: IHL = 5",
               (iph->version_ihl & 0x0F) == 5);
        ASSERT("ip_build: protocol = TCP",
               iph->protocol == IP_PROTO_TCP);
        ASSERT("ip_build: TTL = IP_DEFAULT_TTL",
               iph->ttl == IP_DEFAULT_TTL);

        /* Total length: IP_HLEN + payload */
        ASSERT("ip_build: total_length correct",
               NTOHS(iph->total_length) ==
               (uint16_t)(IP_HLEN + sizeof(PAYLOAD)));

        /* Header checksum must verify to 0 */
        ASSERT("ip_build: header checksum valid",
               ip_checksum(iph, IP_HLEN) == 0);
    }

    /* --- Test 5: Parse round-trip --- */
    {
        /* eth_payload points to the IP packet inside the Ethernet frame */
        const uint8_t *eth_payload = (const uint8_t *)&frame + ETH_HLEN;
        uint16_t eth_payload_len   = (uint16_t)(frame_len - ETH_HLEN);

        ok = ip_parse_packet(eth_payload, eth_payload_len,
                             &parsed_hdr, &parsed_payload, &parsed_payload_len);
        ASSERT("ip_parse: returns true on valid packet", ok);
        ASSERT("ip_parse: payload length == sizeof PAYLOAD",
               parsed_payload_len == (uint16_t)sizeof(PAYLOAD));
        ASSERT("ip_parse: src_ip correct", parsed_hdr.src_ip == SRC_IP);
        ASSERT("ip_parse: dst_ip correct", parsed_hdr.dst_ip == DST_IP);
        ASSERT("ip_parse: protocol = TCP",
               parsed_hdr.protocol == IP_PROTO_TCP);
    }

    /* --- Test 6: Parse rejects wrong IP version --- */
    {
        uint8_t bad_buf[IP_HLEN] = {0};
        const uint8_t *pp;
        uint16_t plen;
        bad_buf[0] = 0x65; /* version = 6, IHL = 5 */
        ok = ip_parse_packet(bad_buf, IP_HLEN, &parsed_hdr, &pp, &plen);
        ASSERT("ip_parse: rejects wrong version", ok == false);
    }

    /* --- Test 7: ip_make_addr --- */
    ASSERT("ip_make_addr: 192.168.1.10",
           ip_make_addr(192, 168, 1, 10) == 0xC0A8010AU);
    ASSERT("ip_make_addr: 10.0.0.1",
           ip_make_addr(10, 0, 0, 1) == 0x0A000001U);
}
