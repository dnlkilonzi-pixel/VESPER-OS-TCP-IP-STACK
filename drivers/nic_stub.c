/*
 * nic_stub.c - Stub / loopback NIC driver for VESPER OS
 *
 * This driver provides a software-only NIC that stores transmitted frames
 * in a ring buffer and optionally echoes them to a registered RX handler.
 *
 * When running under QEMU with the e1000 or RTL8139 emulation, swap this
 * stub for the real hardware driver.  The net layer will continue to work
 * unchanged because it only calls through the nic_driver_t interface.
 *
 * Ring buffer design:
 *   - NIC_TX_RING_SIZE slots, each holding up to NIC_MAX_PKT_SIZE bytes.
 *   - tx_head  = index of the next slot to write into.
 *   - tx_count = number of frames currently stored.
 *   - Oldest frame is at index (tx_head - tx_count) % NIC_TX_RING_SIZE.
 */

#include "../include/nic.h"
#include "../include/klog.h"

/* ------------------------------------------------------------------ */
/* Internal ring buffer state                                          */
/* ------------------------------------------------------------------ */

static uint8_t  tx_ring[NIC_TX_RING_SIZE][NIC_MAX_PKT_SIZE];
static uint16_t tx_lengths[NIC_TX_RING_SIZE];
static uint8_t  tx_head  = 0;   /* Next write position */
static uint8_t  tx_count = 0;   /* Frames currently in the ring */

/* Registered receive handler (may be NULL) */
static nic_rx_handler_t stub_rx_handler = NULL;

/* Stub MAC address */
static const uint8_t STUB_MAC[ETH_ALEN] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

/* ------------------------------------------------------------------ */
/* mem_copy helper                                                     */
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
/* Stub driver implementation                                          */
/* ------------------------------------------------------------------ */

static bool stub_init(void)
{
    uint8_t i;
    tx_head  = 0;
    tx_count = 0;
    for (i = 0; i < NIC_TX_RING_SIZE; i++)
        tx_lengths[i] = 0;

    klog_puts("[NIC] Stub NIC initialised (loopback mode)\r\n");
    return true;
}

static bool stub_send(const uint8_t *frame, uint16_t length)
{
    uint8_t slot;

    if (!frame || length == 0 || length > NIC_MAX_PKT_SIZE)
        return false;

    /* Drop oldest frame if the ring is full */
    if (tx_count == NIC_TX_RING_SIZE) {
        klog_puts("[NIC] TX ring full — dropping oldest frame\r\n");
        tx_count--;
    }

    /* Write into the current head slot */
    slot = tx_head;
    mem_copy(tx_ring[slot], frame, length);
    tx_lengths[slot] = length;

    tx_head  = (uint8_t)((tx_head + 1) % NIC_TX_RING_SIZE);
    tx_count++;

    klog_puts("[NIC] TX frame stored: ");
    klog_udec(length);
    klog_puts(" bytes (ring count=");
    klog_udec(tx_count);
    klog_puts(")\r\n");

    /*
     * Loopback: echo the transmitted frame to the RX handler so that
     * upper layers can observe their own transmissions (useful for
     * unit testing without a real network).
     */
    if (stub_rx_handler)
        stub_rx_handler(frame, length);

    return true;
}

static void stub_poll(void)
{
    /*
     * The stub driver delivers frames synchronously in stub_send().
     * Nothing to do on poll in loopback mode.
     */
}

static void stub_register_rx_handler(nic_rx_handler_t handler)
{
    stub_rx_handler = handler;
}

/* ------------------------------------------------------------------ */
/* Public stub driver instance                                         */
/* ------------------------------------------------------------------ */

nic_driver_t nic_stub_driver = {
    .name                = "stub-loopback",
    .ready               = false,
    .init                = stub_init,
    .send                = stub_send,
    .poll                = stub_poll,
    .register_rx_handler = stub_register_rx_handler,
};

/* ------------------------------------------------------------------ */
/* Global NIC handle and convenience API                               */
/* ------------------------------------------------------------------ */

nic_driver_t *g_nic = NULL;

bool nic_init(void)
{
    /*
     * In a real OS we would probe PCI here and load the appropriate
     * hardware driver.  For now, always use the stub.
     */
    g_nic = &nic_stub_driver;

    /* Copy our MAC into the driver struct */
    {
        int i;
        for (i = 0; i < ETH_ALEN; i++)
            g_nic->mac[i] = STUB_MAC[i];
    }

    if (!g_nic->init())
        return false;

    g_nic->ready = true;
    return false; /* stub used — no real hardware detected */
}

bool nic_send_frame(const uint8_t *frame, uint16_t length)
{
    if (!g_nic || !g_nic->ready) return false;
    return g_nic->send(frame, length);
}

void nic_poll(void)
{
    if (g_nic && g_nic->ready)
        g_nic->poll();
}

void nic_register_rx_handler(nic_rx_handler_t handler)
{
    if (g_nic)
        g_nic->register_rx_handler(handler);
}

void nic_get_mac(uint8_t *mac_out)
{
    int i;
    if (!mac_out) return;
    for (i = 0; i < ETH_ALEN; i++)
        mac_out[i] = g_nic ? g_nic->mac[i] : 0;
}

/* ------------------------------------------------------------------ */
/* Test/debug helpers for inspecting the TX ring                       */
/* ------------------------------------------------------------------ */

/*
 * nic_stub_tx_count - Return the number of frames in the TX ring
 */
uint8_t nic_stub_tx_count(void) { return tx_count; }

/*
 * nic_stub_get_tx_frame - Copy a stored TX frame out of the ring
 *
 * @index  : 0 = oldest, tx_count-1 = newest
 * @buf    : output buffer (at least NIC_MAX_PKT_SIZE bytes)
 * @len_out: set to the frame length
 *
 * Returns true on success, false if index is out of range.
 */
bool nic_stub_get_tx_frame(uint8_t index, uint8_t *buf, uint16_t *len_out)
{
    uint8_t slot;

    if (!buf || !len_out || index >= tx_count)
        return false;

    /* Calculate the ring slot for the requested index */
    slot = (uint8_t)((tx_head - tx_count + index + NIC_TX_RING_SIZE)
                      % NIC_TX_RING_SIZE);

    mem_copy(buf, tx_ring[slot], tx_lengths[slot]);
    *len_out = tx_lengths[slot];
    return true;
}
